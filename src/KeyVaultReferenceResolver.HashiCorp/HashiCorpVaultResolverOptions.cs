using System;
using System.Collections.Generic;
using KeyVaultReferenceResolver.HashiCorp.Authentication;

namespace KeyVaultReferenceResolver.HashiCorp
{
    /// <summary>
    /// Configuration options for HashiCorp Vault secret resolution.
    /// </summary>
    public class HashiCorpVaultResolverOptions
    {
        /// <summary>
        /// Gets or sets the HashiCorp Vault server address.
        /// If null, reads from VAULT_ADDR environment variable.
        /// </summary>
        /// <remarks>
        /// When this is set, a vault address carried inside a configuration reference must match it.
        /// Setting it is the strongest available protection against a tampered configuration value
        /// redirecting the resolver's Vault token to a host of the attacker's choosing.
        /// </remarks>
        public string? VaultAddress { get; set; }

        /// <summary>
        /// Gets or sets the authentication method to use.
        /// If null, auto-detects from environment variables in order:
        /// 1. VAULT_TOKEN (Token auth)
        /// 2. VAULT_ROLE_ID + VAULT_SECRET_ID (AppRole auth)
        /// 3. Kubernetes service account token (if running in K8s)
        /// </summary>
        public IVaultAuthMethod? AuthMethod { get; set; }

        /// <summary>
        /// Gets or sets the Kubernetes role name for auto-detected Kubernetes auth.
        /// Only used when AuthMethod is null and running in Kubernetes.
        /// </summary>
        public string? KubernetesRoleName { get; set; }

        /// <summary>
        /// Gets or sets the default secrets engine mount path.
        /// Defaults to "secret".
        /// </summary>
        public string MountPath { get; set; } = "secret";

        /// <summary>
        /// Gets or sets the KV secrets engine version. Valid values: 1 or 2.
        /// When null, a read is attempted as KV v2 and retried as KV v1 if the mount answers
        /// that the v2 path shape does not exist.
        /// </summary>
        /// <remarks>
        /// Detecting the engine version properly would mean reading <c>sys/mounts</c>, which a
        /// least-privileged application token has no access to - so the version is probed with
        /// the permissions the application already holds. Set this explicitly to skip the extra
        /// round trip on a v1 mount.
        /// </remarks>
        public int? KvVersion { get; set; }

        /// <summary>
        /// Gets or sets whether to throw an exception when a secret cannot be resolved.
        /// Default is true (fail fast).
        /// </summary>
        /// <remarks>
        /// When set to <c>false</c>, a configuration key whose secret cannot be resolved is set to
        /// <c>null</c> rather than being left holding the literal <c>@HashiCorp.Vault(...)</c>
        /// reference. The application therefore sees a missing value instead of receiving the
        /// reference string itself as if it were the secret.
        /// </remarks>
        public bool ThrowOnResolveFailure { get; set; } = true;

        /// <summary>
        /// Gets or sets the timeout for a single secret retrieval operation.
        /// Default is 30 seconds.
        /// </summary>
        /// <remarks>
        /// This is applied as the Vault HTTP client's service timeout, because VaultSharp does not
        /// observe a <see cref="System.Threading.CancellationToken"/>.
        /// </remarks>
        public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);

        /// <summary>
        /// Gets or sets the total time budget for resolving every reference in the configuration.
        /// Default is 2 minutes. Use <see cref="System.Threading.Timeout.InfiniteTimeSpan"/> for no overall limit.
        /// </summary>
        public TimeSpan OverallTimeout { get; set; } = TimeSpan.FromMinutes(2);

        /// <summary>
        /// Gets or sets how many secrets are resolved concurrently. Default is 8.
        /// </summary>
        public int MaxConcurrency { get; set; } = 8;

        /// <summary>
        /// Gets or sets whether to cache resolved secrets in memory.
        /// Default is true.
        /// </summary>
        public bool EnableCaching { get; set; } = true;

        /// <summary>
        /// Gets or sets how long a resolved secret stays cached.
        /// Defaults to <see cref="System.Threading.Timeout.InfiniteTimeSpan"/>: cached for the
        /// lifetime of the resolver, with no periodic re-fetch from Vault.
        /// </summary>
        /// <remarks>
        /// Refresh on demand instead of on a timer: call
        /// <see cref="HashiCorpVaultSecretResolver.InvalidateCache"/> or resolve with
        /// <c>forceRefresh: true</c> when the application observes that a secret has gone stale.
        /// Values already materialised into
        /// <see cref="Microsoft.Extensions.Configuration.IConfiguration"/> are resolved once while
        /// the configuration is built and do not change until the application restarts.
        /// </remarks>
        public TimeSpan CacheTtl { get; set; } = System.Threading.Timeout.InfiniteTimeSpan;

        /// <summary>
        /// Gets or sets the largest number of secrets held in the in-memory cache.
        /// Default is 1024. Set to 0 for no limit.
        /// </summary>
        /// <remarks>
        /// Nothing removes a cache entry on its own, so a caller that resolves references chosen at
        /// runtime would otherwise hold every secret it has ever seen for the life of the process.
        /// Past the limit, further secrets are not cached and a warning is logged once.
        /// </remarks>
        public int MaxCacheEntries { get; set; } = 1024;

        /// <summary>
        /// Gets or sets whether a plaintext <c>http://</c> Vault address is permitted.
        /// Default is <c>false</c>.
        /// </summary>
        /// <remarks>
        /// Over plaintext HTTP the Vault token and the returned secret are both sent in the clear,
        /// including between pods inside a cluster. Only enable this against a local development
        /// Vault in dev mode.
        /// </remarks>
        public bool AllowInsecureTransport { get; set; }

        /// <summary>
        /// Gets or sets the Vault addresses that may be contacted. When populated, this list is
        /// authoritative for an address carried inside a configuration reference.
        /// </summary>
        /// <remarks>
        /// When this is empty and <see cref="VaultAddress"/> is not set, an address in a reference
        /// is validated against <c>VAULT_ADDR</c>. A mismatch, or the absence of anything to
        /// validate against, is reported according to <see cref="StrictVaultAddressValidation"/>.
        /// </remarks>
        public IList<string> AllowedVaultAddresses { get; set; } = new List<string>();

        /// <summary>
        /// Gets or sets whether an address in a configuration reference that cannot be matched
        /// against a trusted address is rejected rather than used. Default is <c>false</c>, which
        /// logs a warning and contacts the address anyway.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The address in a reference comes from the configuration value itself, so any source that
        /// can influence configuration can name a host and have this process's Vault credential -
        /// <c>VAULT_TOKEN</c>, an AppRole secret ID, or a Kubernetes service account token -
        /// presented to it. Setting <see cref="VaultAddress"/> or
        /// <see cref="AllowedVaultAddresses"/> already closes that off; this option additionally
        /// treats <c>VAULT_ADDR</c> as a pin, and refuses to proceed when there is nothing at all
        /// to validate against.
        /// </para>
        /// <para>
        /// It defaults to <c>false</c> so that enabling it is a deliberate step rather than a
        /// behaviour change on upgrade. The warning logged in the permissive case
        /// (<see cref="HashiCorpLogEvents.VaultAddressUnverified"/>) is there to find affected
        /// configurations before the default flips to <c>true</c> in the next major version.
        /// </para>
        /// </remarks>
        public bool StrictVaultAddressValidation { get; set; }

        /// <summary>
        /// Gets or sets the Vault namespace (Enterprise feature).
        /// Leave null for open source Vault.
        /// </summary>
        public string? Namespace { get; set; }

        /// <summary>
        /// Validates the option values, throwing when they cannot produce a working resolver.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when a timeout or concurrency value is invalid.</exception>
        public void Validate()
        {
            if (Timeout <= TimeSpan.Zero && Timeout != System.Threading.Timeout.InfiniteTimeSpan)
                throw new ArgumentOutOfRangeException(nameof(Timeout), Timeout, "Timeout must be positive or Timeout.InfiniteTimeSpan.");

            if (OverallTimeout <= TimeSpan.Zero && OverallTimeout != System.Threading.Timeout.InfiniteTimeSpan)
                throw new ArgumentOutOfRangeException(nameof(OverallTimeout), OverallTimeout, "OverallTimeout must be positive or Timeout.InfiniteTimeSpan.");

            if (CacheTtl <= TimeSpan.Zero && CacheTtl != System.Threading.Timeout.InfiniteTimeSpan)
                throw new ArgumentOutOfRangeException(nameof(CacheTtl), CacheTtl, "CacheTtl must be positive or Timeout.InfiniteTimeSpan.");

            if (MaxConcurrency < 1)
                throw new ArgumentOutOfRangeException(nameof(MaxConcurrency), MaxConcurrency, "MaxConcurrency must be at least 1.");

            if (MaxCacheEntries < 0)
                throw new ArgumentOutOfRangeException(nameof(MaxCacheEntries), MaxCacheEntries, "MaxCacheEntries must be zero (unlimited) or positive.");
        }

        /// <summary>
        /// Gets the effective vault address, falling back to VAULT_ADDR environment variable.
        /// </summary>
        /// <returns>The vault address.</returns>
        /// <exception cref="InvalidOperationException">Thrown when vault address cannot be determined or is not permitted.</exception>
        public string GetEffectiveVaultAddress()
        {
            var address = VaultAddress ?? GetVaultAddressFromEnvironment();
            if (string.IsNullOrWhiteSpace(address))
                throw new InvalidOperationException(
                    "Vault address not configured. Set VaultAddress option or VAULT_ADDR environment variable.");

            return EnsureTransportAllowed(address!);
        }

        /// <summary>
        /// Reads the vault address from the environment. Declared here so the variable name is
        /// written once and the resolver's trust check cannot drift from the address it resolves.
        /// </summary>
        internal static string? GetVaultAddressFromEnvironment()
        {
            return Environment.GetEnvironmentVariable("VAULT_ADDR");
        }

        /// <summary>
        /// Validates that an address uses a permitted transport and returns it unchanged.
        /// </summary>
        /// <param name="address">The vault address to check.</param>
        /// <returns>The validated address.</returns>
        /// <exception cref="InvalidOperationException">Thrown when the address is malformed or uses plaintext HTTP without opt-in.</exception>
        public string EnsureTransportAllowed(string address)
        {
            if (!Uri.TryCreate(address, UriKind.Absolute, out var uri))
                throw new InvalidOperationException($"Vault address '{address}' is not a valid absolute URI.");

            if (uri.Scheme == Uri.UriSchemeHttps)
                return address;

            if (uri.Scheme == Uri.UriSchemeHttp && AllowInsecureTransport)
                return address;

            throw new InvalidOperationException(
                $"Vault address '{address}' must use https. Plaintext HTTP sends the Vault token and the " +
                $"secret in the clear; set {nameof(AllowInsecureTransport)} to true only for a local development Vault.");
        }

        /// <summary>
        /// Gets the effective authentication method, auto-detecting from environment if not set.
        /// </summary>
        /// <returns>The authentication method.</returns>
        /// <exception cref="InvalidOperationException">Thrown when no authentication method can be determined.</exception>
        public IVaultAuthMethod GetEffectiveAuthMethod()
        {
            if (AuthMethod != null)
                return AuthMethod;

            // Try Token auth from environment
            if (TokenAuthMethod.TryFromEnvironment(out var tokenAuth))
                return tokenAuth;

            // Try AppRole auth from environment
            if (AppRoleAuthMethod.TryFromEnvironment(out var appRoleAuth))
                return appRoleAuth;

            // Try Kubernetes auth if running in K8s
            if (!string.IsNullOrWhiteSpace(KubernetesRoleName) &&
                KubernetesAuthMethod.TryFromFile(KubernetesRoleName!, out var k8sAuth))
                return k8sAuth;

            throw new InvalidOperationException(
                "No authentication method configured. Set AuthMethod option, VAULT_TOKEN, " +
                "VAULT_ROLE_ID + VAULT_SECRET_ID, or configure KubernetesRoleName when running in Kubernetes.");
        }
    }
}
