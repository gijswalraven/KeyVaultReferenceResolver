using System;
using System.Collections.Generic;
using Azure.Core;
using Azure.Security.KeyVault.Secrets;

namespace KeyVaultReferenceResolver
{
    /// <summary>
    /// Options for configuring Key Vault reference resolution.
    /// </summary>
    public class KeyVaultReferenceResolverOptions
    {
        /// <summary>
        /// Host suffixes that are trusted to serve Key Vault secrets, covering the
        /// Azure public, US Government, China and Germany clouds plus Managed HSM.
        /// </summary>
        public static readonly IReadOnlyList<string> DefaultAllowedVaultHostSuffixes = new[]
        {
            ".vault.azure.net",
            ".vaultcore.azure.net",
            ".vault.usgovcloudapi.net",
            ".vault.azure.cn",
            ".vault.microsoftazure.de",
            ".managedhsm.azure.net",
            ".managedhsm.usgovcloudapi.net",
            ".managedhsm.azure.cn"
        };

        /// <summary>
        /// Gets or sets the Azure credential to use for authentication.
        /// If null, a <see cref="Azure.Identity.DefaultAzureCredential"/> is built from
        /// <see cref="ManagedIdentityClientId"/>, <see cref="TenantId"/>, <see cref="AuthorityHost"/>,
        /// <see cref="AllowDeveloperCredentials"/> and <see cref="ExcludeEnvironmentCredential"/>.
        /// </summary>
        public TokenCredential? Credential { get; set; }

        /// <summary>
        /// Gets or sets the client ID of the user-assigned managed identity to authenticate with.
        /// Required on hosts that have more than one managed identity assigned, where the
        /// default credential cannot pick an identity on its own.
        /// Ignored when <see cref="Credential"/> is set.
        /// </summary>
        public string? ManagedIdentityClientId { get; set; }

        /// <summary>
        /// Gets or sets the tenant ID to authenticate against.
        /// Ignored when <see cref="Credential"/> is set.
        /// </summary>
        public string? TenantId { get; set; }

        /// <summary>
        /// Gets or sets the Entra ID authority host, for sovereign clouds
        /// (for example <c>https://login.microsoftonline.us/</c>).
        /// Ignored when <see cref="Credential"/> is set.
        /// </summary>
        public Uri? AuthorityHost { get; set; }

        /// <summary>
        /// Gets or sets whether locally cached developer credentials (Azure CLI, Azure Developer CLI,
        /// Visual Studio, Azure PowerShell) may be used. Default is <c>false</c>, so a process running
        /// in Azure cannot silently fall back to a developer's personal identity.
        /// Set to <c>true</c> for local development. Ignored when <see cref="Credential"/> is set.
        /// </summary>
        public bool AllowDeveloperCredentials { get; set; }

        /// <summary>
        /// Gets or sets whether the environment-variable credential
        /// (<c>AZURE_CLIENT_ID</c> / <c>AZURE_TENANT_ID</c> / <c>AZURE_CLIENT_SECRET</c>) is excluded
        /// from the credential chain. Default is <c>false</c> for backwards compatibility.
        /// </summary>
        /// <remarks>
        /// The environment credential sits ahead of managed identity in the default chain, so anything
        /// able to set those variables in the process environment can redirect vault access to an
        /// identity of its choosing. Set this to <c>true</c> when the workload authenticates with a
        /// managed or workload identity. Ignored when <see cref="Credential"/> is set.
        /// </remarks>
        public bool ExcludeEnvironmentCredential { get; set; }

        /// <summary>
        /// Gets or sets the options used to construct each <see cref="SecretClient"/>, for retry
        /// tuning, proxy/transport configuration, diagnostics and service version pinning.
        /// </summary>
        /// <remarks>
        /// <see cref="Azure.Core.DiagnosticsOptions.IsLoggingContentEnabled"/> is always forced to
        /// <c>false</c> on the instance supplied here, so that enabling Azure SDK logging can never
        /// write secret payloads to the log.
        /// </remarks>
        public SecretClientOptions? ClientOptions { get; set; }

        /// <summary>
        /// Gets or sets whether to throw an exception when a secret cannot be resolved.
        /// Default is true (fail fast).
        /// </summary>
        /// <remarks>
        /// When set to <c>false</c>, a configuration key whose secret cannot be resolved is set to
        /// <c>null</c> rather than being left holding the literal
        /// <c>@Microsoft.KeyVault(SecretUri=...)</c> reference. The application therefore sees a
        /// missing value instead of receiving the reference string itself as if it were the secret.
        /// </remarks>
        public bool ThrowOnResolveFailure { get; set; } = true;

        /// <summary>
        /// Gets or sets the timeout for a single secret retrieval operation.
        /// Default is 30 seconds.
        /// </summary>
        public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);

        /// <summary>
        /// Gets or sets the total time budget for resolving every reference in the configuration.
        /// Default is 2 minutes. Use <see cref="System.Threading.Timeout.InfiniteTimeSpan"/> for no overall limit.
        /// </summary>
        /// <remarks>
        /// Without an overall budget, N unreachable references stall application startup for up to
        /// N * <see cref="Timeout"/>, which outlives most container liveness probes.
        /// </remarks>
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
        /// lifetime of the resolver, with no periodic re-fetch from Key Vault.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Secrets rotate rarely, so polling Key Vault on a timer mostly buys traffic and throttling
        /// risk. Instead of a TTL, refresh on demand when the application observes that a secret has
        /// gone stale (for example a downstream login failing with an authentication error): call
        /// <see cref="KeyVaultSecretResolver.InvalidateCache"/>, or resolve with
        /// <c>forceRefresh: true</c>.
        /// </para>
        /// <para>
        /// Set a finite TTL only if you want time-based expiry as well. Either way this affects
        /// callers that use <see cref="ISecretResolver"/> directly; values already materialised into
        /// <see cref="Microsoft.Extensions.Configuration.IConfiguration"/> are resolved once while
        /// the configuration is built and do not change until the application restarts.
        /// </para>
        /// </remarks>
        public TimeSpan CacheTtl { get; set; } = System.Threading.Timeout.InfiniteTimeSpan;

        /// <summary>
        /// Gets or sets the Key Vault DNS suffix used to build a URI from the
        /// <c>VaultName=</c> reference format. Defaults to <c>vault.azure.net</c>.
        /// </summary>
        /// <remarks>
        /// Set this for sovereign clouds - <c>vault.usgovcloudapi.net</c> for Azure Government,
        /// <c>vault.azure.cn</c> for Azure China - alongside <see cref="AuthorityHost"/>. The
        /// <c>SecretUri=</c> format carries its own host and is unaffected.
        /// </remarks>
        public string VaultDnsSuffix { get; set; } = "vault.azure.net";

        /// <summary>
        /// Gets or sets whether a secret outside its validity period is rejected rather than used.
        /// Default is <c>false</c>, which logs a warning and uses the secret anyway.
        /// </summary>
        /// <remarks>
        /// Key Vault does not block reads of a secret whose <c>ExpiresOn</c> has passed - for
        /// secrets, expiry is advisory metadata, which is why the CIS "set an expiration date on
        /// all secrets" control has no effect on its own. Enabling this makes the control
        /// enforceable at the consumer. It defaults to off because turning it on can stop an
        /// application that is currently working with a secret whose expiry date was never
        /// maintained.
        /// </remarks>
        public bool RejectSecretsOutsideValidityPeriod { get; set; }

        /// <summary>
        /// Gets or sets how long before expiry a warning is logged for a resolved secret.
        /// Default is 7 days. Set to <see cref="TimeSpan.Zero"/> to disable.
        /// </summary>
        public TimeSpan ExpiryWarningThreshold { get; set; } = TimeSpan.FromDays(7);

        /// <summary>
        /// Gets or sets the host suffixes a secret URI must end with to be resolved.
        /// Defaults to <see cref="DefaultAllowedVaultHostSuffixes"/>.
        /// </summary>
        /// <remarks>
        /// Any configuration source that an attacker can influence would otherwise be able to point a
        /// reference at a host of their choosing, making the process issue an authenticated request to
        /// it during startup. Set to an empty list to disable the check.
        /// </remarks>
        public IList<string> AllowedVaultHostSuffixes { get; set; } = new List<string>(DefaultAllowedVaultHostSuffixes);

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
        }
    }
}
