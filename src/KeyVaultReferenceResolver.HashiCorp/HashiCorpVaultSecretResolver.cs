using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using VaultSharp;
using VaultSharp.Core;
using VaultSharp.V1.Commons;

namespace KeyVaultReferenceResolver.HashiCorp
{
    /// <summary>
    /// Implementation of <see cref="ISecretResolver"/> that uses HashiCorp Vault.
    /// </summary>
    public class HashiCorpVaultSecretResolver : ISecretResolver, IDisposable
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
        private readonly ILogger _logger;
        private readonly ConcurrentDictionary<string, IVaultClient> _vaultClients = new ConcurrentDictionary<string, IVaultClient>();
        private readonly ConcurrentDictionary<string, CacheEntry> _secretCache = new ConcurrentDictionary<string, CacheEntry>();
        private bool _disposed;

        /// <summary>
        /// Creates a new instance of <see cref="HashiCorpVaultSecretResolver"/>.
        /// </summary>
        /// <param name="options">The resolver options.</param>
        /// <param name="logger">Optional logger. Accepts any <see cref="ILogger"/>, including <see cref="ILogger{TCategoryName}"/>.</param>
        public HashiCorpVaultSecretResolver(
            HashiCorpVaultResolverOptions? options = null,
            ILogger? logger = null)
        {
            _options = options ?? new HashiCorpVaultResolverOptions();
            _options.Validate();
            _logger = logger ?? NullLogger.Instance;
        }

        /// <inheritdoc />
        public Task<string> ResolveSecretAsync(string secretUri, CancellationToken cancellationToken = default)
        {
            return ResolveSecretAsync(secretUri, forceRefresh: false, cancellationToken);
        }

        /// <summary>
        /// Resolves a secret, optionally bypassing the cache and fetching a fresh value from Vault.
        /// </summary>
        /// <param name="secretUri">The vault reference.</param>
        /// <param name="forceRefresh">
        /// When true, ignores any cached value, fetches from Vault and replaces the cache entry.
        /// Use this when the application has evidence that the cached secret is stale, such as a
        /// downstream login failing with an authentication error.
        /// </param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>The secret value.</returns>
        public async Task<string> ResolveSecretAsync(string secretUri, bool forceRefresh, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(secretUri))
                throw new ArgumentException("Secret URI cannot be null or empty.", nameof(secretUri));

            // Check cache first
            if (!forceRefresh &&
                _options.EnableCaching &&
                _secretCache.TryGetValue(secretUri, out var cached) &&
                !cached.IsExpired)
            {
                _logger.LogDebug(HashiCorpLogEvents.CacheHit, "Returning cached secret for: {SecretUri}", MaskSecretUri(secretUri));
                return cached.Value;
            }

            var (vaultAddress, secretPath, secretKey) = ParseSecretUri(secretUri);
            var client = GetOrCreateClient(vaultAddress);

            using (var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
            {
                if (_options.Timeout != System.Threading.Timeout.InfiniteTimeSpan)
                    cts.CancelAfter(_options.Timeout);

                try
                {
                    _logger.LogDebug(HashiCorpLogEvents.SecretResolved,
                        "Resolving secret {SecretKey} from path {SecretPath} at {VaultAddress}",
                        secretKey, MaskPath(secretPath), vaultAddress);

                    string secretValue;
                    try
                    {
                        secretValue = await ReadSecretAsync(client, secretPath, secretKey, cts.Token).ConfigureAwait(false);
                    }
                    catch (VaultApiException ex) when (IsAuthFailure(ex))
                    {
                        // VaultSharp logs in once and caches the result on the auth method info,
                        // so once the login token's TTL elapses every subsequent read fails with
                        // 403 for the life of the process. Evict the client and log in again.
                        _logger.LogInformation(
                            HashiCorpLogEvents.Reauthenticated,
                            "Vault returned {Status} for {SecretPath}; re-authenticating and retrying once.",
                            ex.HttpStatusCode,
                            MaskPath(secretPath));

                        var freshClient = ReauthenticateClient(vaultAddress);
                        secretValue = await ReadSecretAsync(freshClient, secretPath, secretKey, cts.Token)
                            .ConfigureAwait(false);
                    }

                    // Cache the resolved secret
                    if (_options.EnableCaching)
                    {
                        _secretCache[secretUri] = new CacheEntry(secretValue, _options.CacheTtl);
                    }

                    // Information level carries no secret key: these records are shipped to
                    // aggregated log stores, where key names such as "prod-db-root-password"
                    // would amount to an inventory of the vault's contents. The key is
                    // available at Debug.
                    _logger.LogInformation(HashiCorpLogEvents.SecretRead, "Successfully resolved secret from {SecretPath}",
                        MaskPath(secretPath));
                    return secretValue;
                }
                catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested)
                {
                    // Either the per-secret budget elapsed, or the Vault HTTP client hit
                    // VaultServiceTimeout (which surfaces as a TaskCanceledException).
                    throw new TimeoutException($"Timeout resolving secret from {MaskSecretUri(secretUri)}", ex);
                }
            }
        }

        /// <inheritdoc />
        public string ResolveSecret(string secretUri)
        {
            return ResolveSecretAsync(secretUri, forceRefresh: false).GetAwaiter().GetResult();
        }

        /// <summary>
        /// Resolves a secret synchronously, optionally bypassing the cache.
        /// </summary>
        /// <param name="secretUri">The vault reference.</param>
        /// <param name="forceRefresh">When true, ignores any cached value and fetches from Vault.</param>
        /// <returns>The secret value.</returns>
        public string ResolveSecret(string secretUri, bool forceRefresh)
        {
            return ResolveSecretAsync(secretUri, forceRefresh).GetAwaiter().GetResult();
        }

        /// <summary>
        /// Removes cached secrets so that the next resolution goes back to Vault.
        /// </summary>
        /// <param name="secretUri">The reference to evict, or null to clear the whole cache.</param>
        /// <remarks>
        /// This affects secrets resolved through this instance. Values already written into
        /// <see cref="Microsoft.Extensions.Configuration.IConfiguration"/> during startup are not
        /// re-read and keep their original values until the application restarts.
        /// </remarks>
        public void InvalidateCache(string? secretUri = null)
        {
            if (secretUri == null)
            {
                _secretCache.Clear();
                return;
            }

            _secretCache.TryRemove(secretUri, out _);
        }

        /// <summary>
        /// Clears the cached secret values and Vault clients held by this resolver.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Releases the resources held by this resolver.
        /// </summary>
        /// <param name="disposing">True when called from <see cref="Dispose()"/>.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                _secretCache.Clear();
                _vaultClients.Clear();
            }

            _disposed = true;
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
                return ParseSecretUri(value!);
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
                    ValidateSecretPath(attrMatch.Groups["path"].Value),
                    ValidateSecretKey(attrMatch.Groups["key"].Value)
                );
            }

            // Try URI pattern: hashicorp://host/path#key
            var uriMatch = UriPattern.Match(secretUri);
            if (uriMatch.Success)
            {
                var host = uriMatch.Groups["host"].Value;
                var path = ValidateSecretPath(uriMatch.Groups["path"].Value);
                var key = ValidateSecretKey(uriMatch.Groups["key"].Value);

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

        /// <summary>
        /// Rejects a secret path that could address a different Vault API endpoint.
        /// </summary>
        /// <remarks>
        /// The path comes from a configuration value and is passed to VaultSharp, which puts it
        /// into the request URL. A dot segment is normalised away by <see cref="Uri"/>, so
        /// <c>secret/data/../../sys/mounts</c> would reach a different endpoint entirely, and a
        /// <c>?</c> or <c>#</c> would splice a query string or fragment onto the request.
        /// </remarks>
        /// <param name="path">The secret path from the reference.</param>
        /// <returns>The validated path.</returns>
        /// <exception cref="ArgumentException">Thrown when the path is not a plain relative path.</exception>
        private static string ValidateSecretPath(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
                throw new ArgumentException("Vault secret path cannot be empty.", nameof(path));

            foreach (var c in path)
            {
                if (c == '?' || c == '#' || c == '\\' || char.IsControl(c))
                {
                    throw new ArgumentException(
                        $"Vault secret path contains an illegal character '{Describe(c)}'.",
                        nameof(path));
                }
            }

            var segments = path.Split('/');
            foreach (var segment in segments)
            {
                if (segment == "." || segment == "..")
                {
                    throw new ArgumentException(
                        "Vault secret path must not contain '.' or '..' segments.",
                        nameof(path));
                }
            }

            return path;
        }

        /// <summary>
        /// Rejects a secret key containing characters that do not belong in a KV field name.
        /// </summary>
        /// <param name="key">The secret key from the reference.</param>
        /// <returns>The validated key.</returns>
        /// <exception cref="ArgumentException">Thrown when the key contains a control character.</exception>
        private static string ValidateSecretKey(string key)
        {
            if (string.IsNullOrWhiteSpace(key))
                throw new ArgumentException("Vault secret key cannot be empty.", nameof(key));

            foreach (var c in key)
            {
                if (char.IsControl(c))
                {
                    throw new ArgumentException(
                        "Vault secret key contains a control character.",
                        nameof(key));
                }
            }

            return key;
        }

        private static string Describe(char c)
        {
            return char.IsControl(c) ? $"\\u{(int)c:x4}" : c.ToString();
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

            // KvVersion unset means "try v2, fall back to v1". Detecting the engine version
            // properly would mean reading sys/mounts, which a least-privileged application token
            // has no access to - so probing with the permissions we already hold is the only
            // detection that works in practice.
            if (_options.KvVersion == 1)
                return await ReadKvV1Async(client, mountPath, actualPath, secretPath, secretKey).ConfigureAwait(false);

            if (_options.KvVersion == 2)
                return await ReadKvV2Async(client, mountPath, actualPath, secretPath, secretKey).ConfigureAwait(false);

            try
            {
                return await ReadKvV2Async(client, mountPath, actualPath, secretPath, secretKey).ConfigureAwait(false);
            }
            catch (VaultApiException ex) when (IsMountVersionMismatch(ex))
            {
                _logger.LogDebug(
                    HashiCorpLogEvents.KvVersionProbe,
                    "Mount {MountPath} did not answer as KV v2 (HTTP {Status}); retrying as KV v1. " +
                    "Set KvVersion to skip this probe.",
                    mountPath,
                    ex.HttpStatusCode);

                return await ReadKvV1Async(client, mountPath, actualPath, secretPath, secretKey).ConfigureAwait(false);
            }
        }

        private async Task<string> ReadKvV2Async(
            IVaultClient client, string mountPath, string actualPath, string secretPath, string secretKey)
        {
            Secret<SecretData> secret = await client.V1.Secrets.KeyValue.V2.ReadSecretAsync(
                path: actualPath,
                mountPoint: mountPath
            ).ConfigureAwait(false);

            if (secret?.Data?.Data == null || !secret.Data.Data.TryGetValue(secretKey, out var value))
            {
                throw new KeyNotFoundException($"Secret key not found at path '{MaskPath(secretPath)}'");
            }

            return value?.ToString() ?? string.Empty;
        }

        private async Task<string> ReadKvV1Async(
            IVaultClient client, string mountPath, string actualPath, string secretPath, string secretKey)
        {
            var kvV1Secret = await client.V1.Secrets.KeyValue.V1.ReadSecretAsync(
                path: actualPath,
                mountPoint: mountPath
            ).ConfigureAwait(false);

            if (kvV1Secret?.Data == null || !kvV1Secret.Data.TryGetValue(secretKey, out var v1Value))
            {
                throw new KeyNotFoundException($"Secret key not found at path '{MaskPath(secretPath)}'");
            }

            return v1Value?.ToString() ?? string.Empty;
        }

        /// <summary>
        /// Recognises a Vault response that means the login token is no longer accepted.
        /// </summary>
        private static bool IsAuthFailure(VaultApiException ex)
        {
            return ex.HttpStatusCode == HttpStatusCode.Forbidden
                || ex.HttpStatusCode == HttpStatusCode.Unauthorized;
        }

        /// <summary>
        /// Drops the cached client for an address so the next call performs a fresh login.
        /// </summary>
        private IVaultClient ReauthenticateClient(string vaultAddress)
        {
            var effectiveAddress = NormalizeVaultAddress(ResolveTrustedAddress(vaultAddress));
            _vaultClients.TryRemove(effectiveAddress, out _);
            return GetOrCreateClient(vaultAddress);
        }

        /// <summary>
        /// Recognises the response a KV v1 mount gives to a v2-shaped request.
        /// </summary>
        private static bool IsMountVersionMismatch(VaultApiException ex)
        {
            // A v1 mount has no /data/ sub-path, so the v2 request shape 404s. 400 covers
            // "Invalid path for a versioned K/V secrets engine", which some versions return.
            return ex.HttpStatusCode == HttpStatusCode.NotFound
                || ex.HttpStatusCode == HttpStatusCode.BadRequest;
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
            var effectiveAddress = NormalizeVaultAddress(ResolveTrustedAddress(vaultAddress));

            return _vaultClients.GetOrAdd(effectiveAddress, address =>
            {
                var authMethod = _options.GetEffectiveAuthMethod();

                // Record which method won the auto-detection race. Without this, a leftover
                // VAULT_TOKEN in a production container silently overrides the intended
                // workload identity - VAULT_TOKEN is tried before AppRole, which is tried
                // before the Kubernetes service account - and nothing says so.
                _logger.LogInformation(
                    HashiCorpLogEvents.AuthMethodSelected,
                    "Authenticating to Vault at {VaultAddress} using {AuthMethod}",
                    address,
                    authMethod.GetType().Name);

                var settings = new VaultClientSettings(address, authMethod.GetAuthMethodInfo());

                // VaultSharp does not observe a CancellationToken, so this is the only timeout
                // that actually bounds a Vault call.
                if (_options.Timeout != System.Threading.Timeout.InfiniteTimeSpan)
                {
                    settings.VaultServiceTimeout = _options.Timeout;
                }

                if (!string.IsNullOrWhiteSpace(_options.Namespace))
                {
                    settings.Namespace = _options.Namespace;
                }

                return new VaultClient(settings);
            });
        }

        /// <summary>
        /// Decides which Vault address to contact, refusing an address supplied by a configuration
        /// reference unless it is explicitly trusted.
        /// </summary>
        /// <remarks>
        /// The address in a reference comes from the configuration value itself. Any source that can
        /// influence configuration could otherwise point it at an attacker-controlled host and have
        /// the resolver's ambient Vault credential sent there.
        /// </remarks>
        private string ResolveTrustedAddress(string vaultAddress)
        {
            // No address in the reference: use the configured one.
            if (string.IsNullOrWhiteSpace(vaultAddress))
                return _options.GetEffectiveVaultAddress();

            _options.EnsureTransportAllowed(vaultAddress);

            // A configured address pins the resolver: a reference may only name that same vault.
            if (!string.IsNullOrWhiteSpace(_options.VaultAddress))
            {
                if (AddressesMatch(vaultAddress, _options.VaultAddress!))
                    return vaultAddress;

                throw new InvalidOperationException(
                    $"Vault address '{vaultAddress}' in a configuration reference does not match the configured " +
                    $"{nameof(HashiCorpVaultResolverOptions.VaultAddress)}. Refusing to authenticate against an unexpected vault.");
            }

            var allowed = _options.AllowedVaultAddresses;
            if (allowed == null || allowed.Count == 0)
                return vaultAddress;

            foreach (var candidate in allowed)
            {
                if (!string.IsNullOrWhiteSpace(candidate) && AddressesMatch(vaultAddress, candidate))
                    return vaultAddress;
            }

            throw new InvalidOperationException(
                $"Vault address '{vaultAddress}' in a configuration reference is not listed in " +
                $"{nameof(HashiCorpVaultResolverOptions.AllowedVaultAddresses)}.");
        }

        private static bool AddressesMatch(string left, string right)
        {
            return string.Equals(
                NormalizeVaultAddress(left),
                NormalizeVaultAddress(right),
                StringComparison.Ordinal);
        }

        private static string NormalizeVaultAddress(string address)
        {
            if (string.IsNullOrWhiteSpace(address))
                return address;

            // Remove trailing slash
            address = address.TrimEnd('/');

            // Lowercase only the scheme and host; a path prefix on a Vault behind a gateway
            // (for example https://gw.example.com/Vault) is case-sensitive.
            if (Uri.TryCreate(address, UriKind.Absolute, out var uri))
            {
                var builder = new UriBuilder(uri)
                {
                    Scheme = uri.Scheme.ToLowerInvariant(),
                    Host = uri.Host.ToLowerInvariant()
                };

                return builder.Uri.GetComponents(
                    UriComponents.SchemeAndServer | UriComponents.Path,
                    UriFormat.UriEscaped).TrimEnd('/');
            }

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

        private readonly struct CacheEntry
        {
            private readonly DateTimeOffset _expiresAt;

            public CacheEntry(string value, TimeSpan ttl)
            {
                Value = value;
                _expiresAt = ttl == System.Threading.Timeout.InfiniteTimeSpan
                    ? DateTimeOffset.MaxValue
                    : DateTimeOffset.UtcNow.Add(ttl);
            }

            public string Value { get; }

            public bool IsExpired => DateTimeOffset.UtcNow >= _expiresAt;
        }
    }
}
