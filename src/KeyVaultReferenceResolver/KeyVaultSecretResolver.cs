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
        private int _cacheFullReported;

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

            // Parsed before the cache is consulted, so the cache key is the canonical form of the
            // reference rather than however it happened to be spelled. Two references differing
            // only in host casing or an escaped character are one secret, and must be one entry -
            // otherwise InvalidateCache leaves a stale copy behind under the other spelling.
            var (vaultUri, secretName, version) = ParseSecretUri(secretUri);
            var cacheKey = BuildCacheKey(vaultUri, secretName, version);

            if (!forceRefresh &&
                _options.EnableCaching &&
                _secretCache.TryGetValue(cacheKey, out var cached) &&
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
                        StoreInCache(cacheKey, secretValue);

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

            // Normalised the same way as on insertion, so eviction is not defeated by the caller
            // spelling the reference differently from whoever resolved it. A reference that cannot
            // be parsed cannot be in the cache, so there is nothing to remove.
            try
            {
                var (vaultUri, secretName, version) = ParseSecretUri(secretUri);
                _secretCache.TryRemove(BuildCacheKey(vaultUri, secretName, version), out _);
            }
            catch (ArgumentException)
            {
            }
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
            return new DefaultAzureCredential(BuildCredentialOptions(options));
        }

        /// <summary>
        /// Builds the credential options for the default credential chain.
        /// </summary>
        /// <remarks>
        /// Separated from <see cref="CreateDefaultCredential"/>, and internal, because
        /// <see cref="DefaultAzureCredential"/> exposes none of this once constructed: without a
        /// seam here, which identities the chain will accept is untestable.
        /// </remarks>
        internal static DefaultAzureCredentialOptions BuildCredentialOptions(KeyVaultReferenceResolverOptions options)
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

            // Left alone when null so the Azure Identity default, including
            // AZURE_ADDITIONALLY_ALLOWED_TENANTS, still applies. An empty list is meaningful: it
            // pins the credential to one tenant and overrides that variable.
            if (options.AdditionallyAllowedTenants != null)
            {
                credentialOptions.AdditionallyAllowedTenants.Clear();
                foreach (var tenant in options.AdditionallyAllowedTenants)
                    credentialOptions.AdditionallyAllowedTenants.Add(tenant);
            }

            return credentialOptions;
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

            var secretName = ValidateSegment(pathParts[1], "secret name", secretUri);
            var version = pathParts.Length > 2
                ? ValidateSegment(pathParts[2], "secret version", secretUri)
                : null;

            return (vaultUri, secretName, version);
        }

        /// <summary>
        /// Checks that a path segment is a legal Key Vault name and returns it unchanged.
        /// </summary>
        /// <remarks>
        /// This used to call <see cref="Uri.UnescapeDataString"/>, on a path that
        /// <see cref="Uri"/> has already partially decoded - so <c>%252e%252e%252f</c> arrived at
        /// the SDK as <c>../</c>. Nothing was exploitable, because Azure.Core re-escapes the
        /// segment when it builds the request path, but the safety of a value handed to a
        /// credential store should not rest on what a dependency does with it afterwards.
        /// Key Vault names are alphanumerics and hyphens, so anything else cannot name a real
        /// secret and is rejected here instead.
        /// </remarks>
        private static string ValidateSegment(string segment, string description, string secretUri)
        {
            foreach (var c in segment)
            {
                var allowed = (c >= '0' && c <= '9')
                    || (c >= 'a' && c <= 'z')
                    || (c >= 'A' && c <= 'Z')
                    || c == '-';

                if (!allowed)
                {
                    throw new ArgumentException(
                        $"Invalid {description} in {MaskUri(secretUri)}. Key Vault names may contain only " +
                        "alphanumerics and hyphens.",
                        nameof(secretUri));
                }
            }

            return segment;
        }

        private void EnsureAllowedVaultHost(Uri uri)
        {
            // An exact-host list is authoritative: it is the only setting that restricts resolution
            // to this application's own vaults, so a suffix entry must not be able to widen it.
            var hosts = _options.AllowedVaultHosts;
            if (hosts != null && hosts.Count > 0)
            {
                foreach (var host in hosts)
                {
                    if (!string.IsNullOrWhiteSpace(host) &&
                        uri.Host.Equals(host.Trim(), StringComparison.OrdinalIgnoreCase))
                    {
                        return;
                    }
                }

                throw new ArgumentException(
                    $"Vault host '{uri.Host}' is not listed in {nameof(KeyVaultReferenceResolverOptions)}.{nameof(KeyVaultReferenceResolverOptions.AllowedVaultHosts)}.",
                    nameof(uri));
            }

            var allowed = _options.AllowedVaultHostSuffixes;
            if (allowed == null || allowed.Count == 0)
                return;

            foreach (var suffix in allowed)
            {
                if (string.IsNullOrWhiteSpace(suffix))
                    continue;

                if (MatchesHostSuffix(uri.Host, suffix))
                    return;
            }

            throw new ArgumentException(
                $"Vault host '{uri.Host}' is not an allowed Key Vault host. " +
                $"Add its suffix to {nameof(KeyVaultReferenceResolverOptions)}.{nameof(KeyVaultReferenceResolverOptions.AllowedVaultHostSuffixes)} if this is intentional.",
                nameof(uri));
        }

        /// <summary>
        /// Matches a host against an allowed suffix at a label boundary.
        /// </summary>
        /// <remarks>
        /// A plain <see cref="string.EndsWith(string, StringComparison)"/> matches inside a label,
        /// so an operator narrowing the list to their own vault by writing
        /// <c>contoso.vault.azure.net</c> would also admit <c>evilcontoso.vault.azure.net</c> -
        /// which anyone can create. Requiring the character before the match to be a dot, or the
        /// whole host to be equal, removes that. A leading dot on the entry is optional so the
        /// shipped defaults and a hand-written entry behave the same way.
        /// </remarks>
        internal static bool MatchesHostSuffix(string host, string suffix)
        {
            var trimmed = suffix.Trim().TrimStart('.');

            if (trimmed.Length == 0)
                return false;

            if (host.Equals(trimmed, StringComparison.OrdinalIgnoreCase))
                return true;

            var boundary = host.Length - trimmed.Length - 1;

            return boundary > 0
                && host[boundary] == '.'
                && host.EndsWith(trimmed, StringComparison.OrdinalIgnoreCase);
        }

        private SecretClient GetOrCreateClient(Uri vaultUri)
        {
            return _secretClients.GetOrAdd(
                vaultUri.ToString(),
                _ => new SecretClient(vaultUri, _credential, BuildClientOptions()));
        }

        internal SecretClientOptions BuildClientOptions()
        {
            var clientOptions = _options.ClientOptions ?? new SecretClientOptions();

            // Never let Azure SDK content logging write secret payloads to the log,
            // regardless of AZURE_LOG_LEVEL or any listener the consumer has attached.
            clientOptions.Diagnostics.IsLoggingContentEnabled = false;

            // Challenge resource verification is what stops a vault from naming a different
            // resource in its authentication challenge and having the SDK fetch a token for it.
            // The SDK already defaults this off; forcing it means a caller-supplied
            // SecretClientOptions cannot turn the check off for a library that exists to move
            // credentials around.
            clientOptions.DisableChallengeResourceVerification = false;

            return clientOptions;
        }

        /// <summary>
        /// Builds the canonical cache key for a parsed reference.
        /// </summary>
        private static string BuildCacheKey(Uri vaultUri, string secretName, string? version)
        {
            // Uri already lower-cases the host. The secret name is case-sensitive in Key Vault,
            // so it is not folded here.
            return string.IsNullOrEmpty(version)
                ? $"{vaultUri}secrets/{secretName}"
                : $"{vaultUri}secrets/{secretName}/{version}";
        }

        /// <summary>
        /// Adds a resolved secret to the cache, up to <see cref="KeyVaultReferenceResolverOptions.MaxCacheEntries"/>.
        /// </summary>
        /// <remarks>
        /// The cache is keyed by reference and nothing ever removes an entry on its own, so a
        /// caller resolving references chosen at runtime could grow it without limit. Once the
        /// limit is reached further secrets are simply not cached, rather than evicting one that
        /// is probably still in use: for the intended workload - a fixed set of secrets read at
        /// startup - reaching the limit at all means something is wrong, and the warning matters
        /// more than the eviction policy.
        /// </remarks>
        private void StoreInCache(string cacheKey, string secretValue)
        {
            var limit = _options.MaxCacheEntries;

            if (limit > 0 && _secretCache.Count >= limit && !_secretCache.ContainsKey(cacheKey))
            {
                if (Interlocked.Exchange(ref _cacheFullReported, 1) == 0)
                    Log.CacheFull(_logger, limit);

                return;
            }

            _secretCache[cacheKey] = new CacheEntry(secretValue, _options.CacheTtl);
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
