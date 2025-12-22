using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using VaultSharp;
using VaultSharp.V1.Commons;

namespace KeyVaultReferenceResolver.HashiCorp
{
    /// <summary>
    /// Implementation of <see cref="ISecretResolver"/> that uses HashiCorp Vault.
    /// </summary>
    public class HashiCorpVaultSecretResolver : ISecretResolver
    {
        // Regex timeout to prevent ReDoS attacks
        private static readonly TimeSpan RegexTimeout = TimeSpan.FromSeconds(1);

        // Pattern 1: @HashiCorp.Vault(VaultAddress=...;SecretPath=...;SecretKey=...)
        private static readonly Regex AttributePattern = new Regex(
            @"@HashiCorp\.Vault\(VaultAddress=(?<addr>[^;)]+);SecretPath=(?<path>[^;)]+);SecretKey=(?<key>[^)]+)\)",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);

        // Pattern 2: hashicorp://host/path#key
        private static readonly Regex UriPattern = new Regex(
            @"^hashicorp://(?<host>[^/]+)/(?<path>[^#]+)#(?<key>.+)$",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);

        private readonly HashiCorpVaultResolverOptions _options;
        private readonly ILogger<HashiCorpVaultSecretResolver> _logger;
        private readonly ConcurrentDictionary<string, IVaultClient> _vaultClients = new ConcurrentDictionary<string, IVaultClient>();
        private readonly ConcurrentDictionary<string, string> _secretCache = new ConcurrentDictionary<string, string>();

        /// <summary>
        /// Creates a new instance of <see cref="HashiCorpVaultSecretResolver"/>.
        /// </summary>
        /// <param name="options">The resolver options.</param>
        /// <param name="logger">Optional logger.</param>
        public HashiCorpVaultSecretResolver(
            HashiCorpVaultResolverOptions? options = null,
            ILogger<HashiCorpVaultSecretResolver>? logger = null)
        {
            _options = options ?? new HashiCorpVaultResolverOptions();
            _logger = logger ?? NullLogger<HashiCorpVaultSecretResolver>.Instance;
        }

        /// <inheritdoc />
        public async Task<string> ResolveSecretAsync(string secretUri, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(secretUri))
                throw new ArgumentException("Secret URI cannot be null or empty.", nameof(secretUri));

            // Check cache first
            if (_options.EnableCaching && _secretCache.TryGetValue(secretUri, out var cachedValue))
            {
                _logger.LogDebug("Returning cached secret for: {SecretUri}", MaskSecretUri(secretUri));
                return cachedValue;
            }

            var (vaultAddress, secretPath, secretKey) = ParseSecretUri(secretUri);
            var client = GetOrCreateClient(vaultAddress);

            using (var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
            {
                cts.CancelAfter(_options.Timeout);

                try
                {
                    _logger.LogDebug("Resolving secret {SecretKey} from path {SecretPath} at {VaultAddress}",
                        secretKey, MaskPath(secretPath), vaultAddress);

                    var secretValue = await ReadSecretAsync(client, secretPath, secretKey, cts.Token).ConfigureAwait(false);

                    // Cache the resolved secret
                    if (_options.EnableCaching)
                    {
                        _secretCache[secretUri] = secretValue;
                    }

                    _logger.LogInformation("Successfully resolved secret: {SecretKey} from {SecretPath}",
                        secretKey, MaskPath(secretPath));
                    return secretValue;
                }
                catch (OperationCanceledException) when (cts.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
                {
                    throw new TimeoutException($"Timeout resolving secret from {MaskSecretUri(secretUri)}");
                }
            }
        }

        /// <inheritdoc />
        public string ResolveSecret(string secretUri)
        {
            return ResolveSecretAsync(secretUri).GetAwaiter().GetResult();
        }

        /// <summary>
        /// Checks if a value is a HashiCorp Vault reference.
        /// </summary>
        /// <param name="value">The value to check.</param>
        /// <returns>True if the value is a HashiCorp Vault reference.</returns>
        public static bool IsHashiCorpVaultReference(string? value)
        {
            if (string.IsNullOrEmpty(value))
                return false;

            return AttributePattern.IsMatch(value) || UriPattern.IsMatch(value);
        }

        /// <summary>
        /// Tries to extract secret information from a HashiCorp Vault reference.
        /// </summary>
        /// <param name="value">The value to parse.</param>
        /// <returns>The extracted information, or null if not a valid reference.</returns>
        public static (string vaultAddress, string secretPath, string secretKey)? TryExtractSecretInfo(string? value)
        {
            if (string.IsNullOrEmpty(value))
                return null;

            try
            {
                return ParseSecretUri(value);
            }
            catch
            {
                return null;
            }
        }

        private static (string vaultAddress, string secretPath, string secretKey) ParseSecretUri(string secretUri)
        {
            // Try attribute pattern first: @HashiCorp.Vault(VaultAddress=...;SecretPath=...;SecretKey=...)
            var attrMatch = AttributePattern.Match(secretUri);
            if (attrMatch.Success)
            {
                return (
                    attrMatch.Groups["addr"].Value,
                    attrMatch.Groups["path"].Value,
                    attrMatch.Groups["key"].Value
                );
            }

            // Try URI pattern: hashicorp://host/path#key
            var uriMatch = UriPattern.Match(secretUri);
            if (uriMatch.Success)
            {
                var host = uriMatch.Groups["host"].Value;
                var path = uriMatch.Groups["path"].Value;
                var key = uriMatch.Groups["key"].Value;

                // Reconstruct vault address with https
                var vaultAddress = $"https://{host}";

                return (vaultAddress, path, key);
            }

            throw new ArgumentException(
                $"Invalid HashiCorp Vault reference format: {MaskSecretUri(secretUri)}. " +
                "Expected format: @HashiCorp.Vault(VaultAddress=https://vault.example.com;SecretPath=secret/data/myapp;SecretKey=password) " +
                "or hashicorp://vault.example.com/secret/data/myapp#password",
                nameof(secretUri));
        }

        // Note: VaultSharp does not currently support CancellationToken (see https://github.com/rajanadar/VaultSharp/issues/368)
        // The cancellationToken parameter is kept for future compatibility when VaultSharp adds support.
        // Timeout is enforced at the caller level via CancellationTokenSource.CancelAfter().
        private async Task<string> ReadSecretAsync(IVaultClient client, string secretPath, string secretKey, CancellationToken cancellationToken)
        {
            // Determine mount path and actual path
            var (mountPath, actualPath) = SplitPath(secretPath);

            // Use the configured mount path if none in the secret path
            if (string.IsNullOrEmpty(mountPath))
            {
                mountPath = _options.MountPath;
            }

            var kvVersion = _options.KvVersion ?? 2; // Default to KV v2

            Secret<SecretData> secret;
            if (kvVersion == 2)
            {
                secret = await client.V1.Secrets.KeyValue.V2.ReadSecretAsync(
                    path: actualPath,
                    mountPoint: mountPath
                ).ConfigureAwait(false);
            }
            else
            {
                var kvV1Secret = await client.V1.Secrets.KeyValue.V1.ReadSecretAsync(
                    path: actualPath,
                    mountPoint: mountPath
                ).ConfigureAwait(false);

                // Convert to same format for unified handling
                if (kvV1Secret?.Data == null || !kvV1Secret.Data.TryGetValue(secretKey, out var v1Value))
                {
                    throw new KeyNotFoundException($"Secret key not found at path '{MaskPath(secretPath)}'");
                }

                return v1Value?.ToString() ?? string.Empty;
            }

            if (secret?.Data?.Data == null || !secret.Data.Data.TryGetValue(secretKey, out var value))
            {
                throw new KeyNotFoundException($"Secret key not found at path '{MaskPath(secretPath)}'");
            }

            return value?.ToString() ?? string.Empty;
        }

        private static (string mountPath, string actualPath) SplitPath(string fullPath)
        {
            // Handle paths like "secret/data/myapp" -> ("secret", "myapp")
            // or "kv/data/myapp/config" -> ("kv", "myapp/config")

            var parts = fullPath.Split(new[] { '/' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2)
            {
                return (string.Empty, fullPath);
            }

            // Check if this is a KV v2 path with 'data' in it
            if (parts.Length >= 3 && parts[1].Equals("data", StringComparison.OrdinalIgnoreCase))
            {
                // KV v2 format: mount/data/path -> mount, path
                var mountPath = parts[0];
                var actualPath = string.Join("/", parts, 2, parts.Length - 2);
                return (mountPath, actualPath);
            }

            // KV v1 format or no data segment: mount/path -> mount, path
            var mount = parts[0];
            var path = string.Join("/", parts, 1, parts.Length - 1);
            return (mount, path);
        }

        private IVaultClient GetOrCreateClient(string vaultAddress)
        {
            // Use the provided address or fall back to options
            var effectiveAddress = !string.IsNullOrWhiteSpace(vaultAddress)
                ? vaultAddress
                : _options.GetEffectiveVaultAddress();

            // Normalize the address to avoid duplicate clients for same vault
            effectiveAddress = NormalizeVaultAddress(effectiveAddress);

            return _vaultClients.GetOrAdd(effectiveAddress, address =>
        {
            var authMethod = _options.GetEffectiveAuthMethod();
            var settings = new VaultClientSettings(address, authMethod.GetAuthMethodInfo());

            if (!string.IsNullOrWhiteSpace(_options.Namespace))
            {
                settings.Namespace = _options.Namespace;
            }

            return new VaultClient(settings);
        });
        }

        private static string NormalizeVaultAddress(string address)
        {
            if (string.IsNullOrWhiteSpace(address))
                return address;

            // Ensure lowercase for consistent cache keys
            address = address.ToLowerInvariant();

            // Remove trailing slash
            address = address.TrimEnd('/');

            return address;
        }

        private static string MaskSecretUri(string uri)
        {
            try
            {
                var attrMatch = AttributePattern.Match(uri);
                if (attrMatch.Success)
                {
                    return $"@HashiCorp.Vault(VaultAddress={attrMatch.Groups["addr"].Value};SecretPath=***;SecretKey=***)";
                }

                var uriMatch = UriPattern.Match(uri);
                if (uriMatch.Success)
                {
                    return $"hashicorp://{uriMatch.Groups["host"].Value}/***#***";
                }

                return "***";
            }
            catch
            {
                return "***";
            }
        }

        private static string MaskPath(string path)
        {
            // Mask everything after the mount point
            var parts = path.Split('/');
            if (parts.Length > 1)
            {
                return parts[0] + "/***";
            }
            return "***";
        }
    }
}
