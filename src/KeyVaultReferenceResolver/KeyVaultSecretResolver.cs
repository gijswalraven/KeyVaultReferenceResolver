using System;
using System.Collections.Concurrent;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;
using Azure;
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
    public class KeyVaultSecretResolver : ISecretResolver, IDisposable
    {
        private readonly TokenCredential _credential;
        private readonly KeyVaultReferenceResolverOptions _options;
        private readonly ILogger _logger;
        private readonly ConcurrentDictionary<string, SecretClient> _secretClients = new ConcurrentDictionary<string, SecretClient>();
        private readonly ConcurrentDictionary<string, CacheEntry> _secretCache = new ConcurrentDictionary<string, CacheEntry>();
        private bool _disposed;

        /// <summary>Separator for splitting a secret URI path; static to avoid reallocating per call.</summary>
        private static readonly char[] PathSeparators = { '/' };

        /// <summary>
        /// Creates a new instance of <see cref="KeyVaultSecretResolver"/>.
        /// </summary>
        /// <param name="options">The resolver options.</param>
        /// <param name="logger">Optional logger. Accepts any <see cref="ILogger"/>, including <see cref="ILogger{TCategoryName}"/>.</param>
        public KeyVaultSecretResolver(
            KeyVaultReferenceResolverOptions? options = null,
            ILogger? logger = null)
        {
            _options = options ?? new KeyVaultReferenceResolverOptions();
            _options.Validate();
            _credential = _options.Credential ?? CreateDefaultCredential(_options);
            _logger = logger ?? NullLogger.Instance;
        }

        /// <inheritdoc />
        public Task<string> ResolveSecretAsync(string secretUri, CancellationToken cancellationToken = default)
        {
            return ResolveSecretAsync(secretUri, forceRefresh: false, cancellationToken);
        }

        /// <summary>
        /// Resolves a secret, optionally bypassing the cache and fetching a fresh value from Key Vault.
        /// </summary>
        /// <param name="secretUri">The full URI to the secret.</param>
        /// <param name="forceRefresh">
        /// When true, ignores any cached value, fetches from Key Vault and replaces the cache entry.
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
                // Guarded: masking allocates, and this path runs per secret on every
                // resolution even when Debug is switched off.
                if (_logger.IsEnabled(LogLevel.Debug))
                {
                    var maskedUri = MaskUri(secretUri);
                    Log.CacheHit(_logger, maskedUri);
                }

                return cached.Value;
            }

            var (vaultUri, secretName, version) = ParseSecretUri(secretUri);

            using (var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
            {
                if (_options.Timeout != System.Threading.Timeout.InfiniteTimeSpan)
                    cts.CancelAfter(_options.Timeout);

                try
                {
                    Log.ResolvingSecret(_logger, secretName, vaultUri);

                    var secret = await FetchSecretAsync(vaultUri, secretName, version, cts.Token)
                        .ConfigureAwait(false);

                    CheckValidityPeriod(secret, secretUri);

                    var secretValue = secret.Value;

                    // Cache the resolved secret
                    if (_options.EnableCaching)
                    {
                        _secretCache[secretUri] = new CacheEntry(secretValue, _options.CacheTtl);
                    }

                    // Information level carries no secret name: these records are shipped to
                    // aggregated log stores, where the set of names would amount to an inventory
                    // of the vault's contents. The name is available at Debug.
                    Log.SecretRead(_logger, vaultUri);
                    return secretValue;
                }
                catch (OperationCanceledException ex) when (cts.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
                {
                    throw new TimeoutException($"Timeout resolving secret from {MaskUri(secretUri)}", ex);
                }
                catch (RequestFailedException ex)
                {
                    // Map the status onto something an operator can act on. "403" on its own
                    // does not distinguish a missing role assignment from a firewall rule, and
                    // a throttling response reads as a generic failure.
                    throw new KeyVaultReferenceResolutionException(
                        DescribeRequestFailure(ex, vaultUri, secretUri),
                        ex);
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
        /// <param name="secretUri">The full URI to the secret.</param>
        /// <param name="forceRefresh">When true, ignores any cached value and fetches from Key Vault.</param>
        /// <returns>The secret value.</returns>
        public string ResolveSecret(string secretUri, bool forceRefresh)
        {
            return ResolveSecretAsync(secretUri, forceRefresh).GetAwaiter().GetResult();
        }

        /// <summary>
        /// Removes cached secrets so that the next resolution goes back to Key Vault.
        /// </summary>
        /// <param name="secretUri">The secret URI to evict, or null to clear the whole cache.</param>
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
        /// Clears the cached secret values and Key Vault clients held by this resolver.
        /// </summary>
        /// <remarks>
        /// Resolved secrets are plain managed strings and cannot be zeroed, but dropping the
        /// references lets the garbage collector reclaim them rather than keeping them reachable
        /// (and therefore present in any crash dump) for the lifetime of the process.
        /// </remarks>
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
                _secretClients.Clear();
            }

            _disposed = true;
        }

        /// <summary>
        /// Warns when a secret is outside its validity period, and rejects it when configured to.
        /// </summary>
        /// <remarks>
        /// Key Vault does not block a GET on a secret whose ExpiresOn has passed - for secrets,
        /// expiry is advisory metadata. Without this check the library hands the application an
        /// expired credential and the failure surfaces later, at the downstream service, as an
        /// authentication error with no hint as to why.
        /// </remarks>
        private void CheckValidityPeriod(KeyVaultSecret secret, string secretUri)
        {
            var properties = secret.Properties;
            if (properties == null)
                return;

            var now = DateTimeOffset.UtcNow;
            var masked = MaskUri(secretUri);

            if (properties.NotBefore.HasValue && now < properties.NotBefore.Value)
            {
                if (_options.RejectSecretsOutsideValidityPeriod)
                {
                    throw new KeyVaultReferenceResolutionException(
                        $"Secret {masked} is not valid until {properties.NotBefore.Value:u}.");
                }

                Log.SecretNotYetValid(
                    _logger,
                    properties.VaultUri,
                    Format(properties.NotBefore.Value));
            }

            if (!properties.ExpiresOn.HasValue)
                return;

            var expiresOn = properties.ExpiresOn.Value;

            if (now >= expiresOn)
            {
                if (_options.RejectSecretsOutsideValidityPeriod)
                {
                    throw new KeyVaultReferenceResolutionException(
                        $"Secret {masked} expired at {expiresOn:u}.");
                }

                Log.SecretExpired(_logger, properties.VaultUri, Format(expiresOn));
            }
            else if (_options.ExpiryWarningThreshold > TimeSpan.Zero &&
                     expiresOn - now <= _options.ExpiryWarningThreshold)
            {
                Log.SecretExpiringSoon(
                    _logger,
                    properties.VaultUri,
                    Format(expiresOn),
                    _options.ExpiryWarningThreshold);
            }
        }

        /// <summary>
        /// Fetches a secret from Key Vault. This is the only member that talks to the network.
        /// </summary>
        /// <param name="vaultUri">The validated vault URI.</param>
        /// <param name="secretName">The secret name.</param>
        /// <param name="version">The secret version, or null for the current version.</param>
        /// <param name="cancellationToken">Cancellation token, already carrying the per-secret timeout.</param>
        /// <returns>The retrieved secret, including its properties.</returns>
        /// <remarks>
        /// Overridable so that the surrounding behaviour - caching, TTL expiry, forced refresh,
        /// validity-period handling - can be exercised by tests without a live vault. Everything
        /// reachable only through a network call would otherwise be untested, which for a
        /// credential cache is the part most worth testing. Callers should not need to override it.
        /// </remarks>
        protected virtual async Task<KeyVaultSecret> FetchSecretAsync(
            Uri vaultUri,
            string secretName,
            string? version,
            CancellationToken cancellationToken)
        {
            var client = GetOrCreateClient(vaultUri);

            var response = string.IsNullOrEmpty(version)
                ? await client.GetSecretAsync(secretName, cancellationToken: cancellationToken).ConfigureAwait(false)
                : await client.GetSecretAsync(secretName, version, cancellationToken).ConfigureAwait(false);

            return response.Value;
        }

        /// <summary>
        /// Formats a timestamp for a log message, invariant so records are comparable across hosts.
        /// </summary>
        private static string Format(DateTimeOffset value)
        {
            return value.ToString("u", CultureInfo.InvariantCulture);
        }

        /// <summary>
        /// Turns a Key Vault request failure into a message that names the likely cause.
        /// </summary>
        private static string DescribeRequestFailure(RequestFailedException ex, Uri vaultUri, string secretUri)
        {
            var masked = MaskUri(secretUri);

            switch (ex.Status)
            {
                case 401:
                case 403:
                    return $"Access denied reading {masked} (HTTP {ex.Status}). " +
                           "Check that the application identity holds the 'Key Vault Secrets User' role " +
                           $"on {vaultUri} (or 'Get' in a legacy access policy), and that the vault firewall " +
                           "allows this caller.";
                case 404:
                    return $"Secret not found at {masked} (HTTP 404). Check the secret name, and whether the " +
                           "secret has been deleted - a soft-deleted secret must be recovered before it can be read.";
                case 429:
                    return $"Key Vault throttled the request for {masked} (HTTP 429). Reduce MaxConcurrency, " +
                           "raise Timeout so the SDK's backoff can complete, or stagger application startup.";
                default:
                    return $"Failed to read {masked} from Key Vault (HTTP {ex.Status}).";
            }
        }

        private static DefaultAzureCredential CreateDefaultCredential(KeyVaultReferenceResolverOptions options)
        {
            var credentialOptions = new DefaultAzureCredentialOptions
            {
                ExcludeAzureCliCredential = !options.AllowDeveloperCredentials,
                ExcludeAzureDeveloperCliCredential = !options.AllowDeveloperCredentials,
                ExcludeVisualStudioCredential = !options.AllowDeveloperCredentials,
                ExcludeAzurePowerShellCredential = !options.AllowDeveloperCredentials,
                ExcludeInteractiveBrowserCredential = true,
                ExcludeEnvironmentCredential = options.ExcludeEnvironmentCredential
            };

            if (!string.IsNullOrWhiteSpace(options.ManagedIdentityClientId))
                credentialOptions.ManagedIdentityClientId = options.ManagedIdentityClientId;

            if (!string.IsNullOrWhiteSpace(options.TenantId))
                credentialOptions.TenantId = options.TenantId;

            if (options.AuthorityHost != null)
                credentialOptions.AuthorityHost = options.AuthorityHost;

            return new DefaultAzureCredential(credentialOptions);
        }

        private (Uri vaultUri, string secretName, string? version) ParseSecretUri(string secretUri)
        {
            if (!Uri.TryCreate(secretUri, UriKind.Absolute, out var uri))
            {
                throw new ArgumentException(
                    $"Invalid Key Vault secret URI: {MaskUri(secretUri)}.",
                    nameof(secretUri));
            }

            if (uri.Scheme != Uri.UriSchemeHttps)
            {
                throw new ArgumentException(
                    $"Key Vault secret URIs must use https. Got scheme '{uri.Scheme}'.",
                    nameof(secretUri));
            }

            EnsureAllowedVaultHost(uri);

            var vaultUri = new Uri($"{uri.Scheme}://{uri.Host}");

            var pathParts = uri.AbsolutePath.Split(PathSeparators, StringSplitOptions.RemoveEmptyEntries);

            if (pathParts.Length < 2 || !pathParts[0].Equals("secrets", StringComparison.OrdinalIgnoreCase))
            {
                throw new ArgumentException(
                    $"Invalid Key Vault secret URI format: {MaskUri(secretUri)}. Expected format: https://{{vault}}.vault.azure.net/secrets/{{secret-name}}[/{{version}}]",
                    nameof(secretUri));
            }

            var secretName = Uri.UnescapeDataString(pathParts[1]);
            var version = pathParts.Length > 2 ? Uri.UnescapeDataString(pathParts[2]) : null;

            return (vaultUri, secretName, version);
        }

        private void EnsureAllowedVaultHost(Uri uri)
        {
            var allowed = _options.AllowedVaultHostSuffixes;
            if (allowed == null || allowed.Count == 0)
                return;

            foreach (var suffix in allowed)
            {
                if (string.IsNullOrWhiteSpace(suffix))
                    continue;

                if (uri.Host.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
                    return;
            }

            throw new ArgumentException(
                $"Vault host '{uri.Host}' is not an allowed Key Vault host. " +
                $"Add its suffix to {nameof(KeyVaultReferenceResolverOptions)}.{nameof(KeyVaultReferenceResolverOptions.AllowedVaultHostSuffixes)} if this is intentional.",
                nameof(uri));
        }

        private SecretClient GetOrCreateClient(Uri vaultUri)
        {
            return _secretClients.GetOrAdd(
                vaultUri.ToString(),
                _ => new SecretClient(vaultUri, _credential, BuildClientOptions()));
        }

        private SecretClientOptions BuildClientOptions()
        {
            var clientOptions = _options.ClientOptions ?? new SecretClientOptions();

            // Never let Azure SDK content logging write secret payloads to the log,
            // regardless of AZURE_LOG_LEVEL or any listener the consumer has attached.
            clientOptions.Diagnostics.IsLoggingContentEnabled = false;

            return clientOptions;
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
