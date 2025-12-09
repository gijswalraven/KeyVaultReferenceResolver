using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace KeyVaultReferenceResolver
{
    /// <summary>
    /// Default implementation of <see cref="ISecretResolver"/> that uses Azure Key Vault.
    /// </summary>
    public class KeyVaultSecretResolver : ISecretResolver
    {
        private readonly TokenCredential _credential;
        private readonly KeyVaultReferenceResolverOptions _options;
        private readonly ILogger<KeyVaultSecretResolver> _logger;
        private readonly ConcurrentDictionary<string, SecretClient> _secretClients = new ConcurrentDictionary<string, SecretClient>();
        private readonly ConcurrentDictionary<string, string> _secretCache = new ConcurrentDictionary<string, string>();

        /// <summary>
        /// Creates a new instance of <see cref="KeyVaultSecretResolver"/>.
        /// </summary>
        /// <param name="options">The resolver options.</param>
        /// <param name="logger">Optional logger.</param>
        public KeyVaultSecretResolver(
            KeyVaultReferenceResolverOptions? options = null,
            ILogger<KeyVaultSecretResolver>? logger = null)
        {
            _options = options ?? new KeyVaultReferenceResolverOptions();
            _credential = _options.Credential ?? new DefaultAzureCredential();
            _logger = logger ?? NullLogger<KeyVaultSecretResolver>.Instance;
        }

        /// <inheritdoc />
        public async Task<string> ResolveSecretAsync(string secretUri, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(secretUri))
                throw new ArgumentException("Secret URI cannot be null or empty.", nameof(secretUri));

            // Check cache first
            if (_options.EnableCaching && _secretCache.TryGetValue(secretUri, out var cachedValue))
            {
                _logger.LogDebug("Returning cached secret for URI: {SecretUri}", MaskUri(secretUri));
                return cachedValue;
            }

            var (vaultUri, secretName, version) = ParseSecretUri(secretUri);
            var client = GetOrCreateClient(vaultUri);

            using (var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
            {
                cts.CancelAfter(_options.Timeout);

                try
                {
                    _logger.LogDebug("Resolving secret {SecretName} from vault {VaultUri}", secretName, vaultUri);

                    var response = string.IsNullOrEmpty(version)
                        ? await client.GetSecretAsync(secretName, cancellationToken: cts.Token).ConfigureAwait(false)
                        : await client.GetSecretAsync(secretName, version, cts.Token).ConfigureAwait(false);

                    var secretValue = response.Value.Value;

                    // Cache the resolved secret
                    if (_options.EnableCaching)
                    {
                        _secretCache[secretUri] = secretValue;
                    }

                    _logger.LogInformation("Successfully resolved secret: {SecretName}", secretName);
                    return secretValue;
                }
                catch (OperationCanceledException) when (cts.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
                {
                    throw new TimeoutException($"Timeout resolving secret from {MaskUri(secretUri)}");
                }
            }
        }

        /// <inheritdoc />
        public string ResolveSecret(string secretUri)
        {
            return ResolveSecretAsync(secretUri).GetAwaiter().GetResult();
        }

        private static (Uri vaultUri, string secretName, string? version) ParseSecretUri(string secretUri)
        {
            var uri = new Uri(secretUri);
            var vaultUri = new Uri($"{uri.Scheme}://{uri.Host}");

            var pathParts = uri.AbsolutePath.Split(new[] { '/' }, StringSplitOptions.RemoveEmptyEntries);

            if (pathParts.Length < 2 || !pathParts[0].Equals("secrets", StringComparison.OrdinalIgnoreCase))
            {
                throw new ArgumentException(
                    $"Invalid Key Vault secret URI format: {secretUri}. Expected format: https://{{vault}}.vault.azure.net/secrets/{{secret-name}}[/{{version}}]",
                    nameof(secretUri));
            }

            var secretName = pathParts[1];
            var version = pathParts.Length > 2 ? pathParts[2] : null;

            return (vaultUri, secretName, version);
        }

        private SecretClient GetOrCreateClient(Uri vaultUri)
        {
            return _secretClients.GetOrAdd(
                vaultUri.ToString(),
                _ => new SecretClient(vaultUri, _credential));
        }

        private static string MaskUri(string uri)
        {
            // Mask the secret name in logs for security
            try
            {
                var parsed = new Uri(uri);
                return $"{parsed.Scheme}://{parsed.Host}/secrets/***";
            }
            catch
            {
                return "***";
            }
        }
    }
}
