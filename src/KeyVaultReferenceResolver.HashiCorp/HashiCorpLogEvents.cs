using Microsoft.Extensions.Logging;

namespace KeyVaultReferenceResolver.HashiCorp
{
    /// <summary>
    /// Event IDs for the records the HashiCorp Vault package emits, so they can be filtered,
    /// alerted on and correlated rather than matched by message text.
    /// </summary>
    /// <remarks>
    /// Numbered from 2000 to stay clear of <see cref="LogEvents"/> in the core package, so a
    /// consumer using both sees no collisions. IDs are grouped: 2000s for resolution, 2100s for
    /// authentication, 2200s for caching.
    /// </remarks>
    public static class HashiCorpLogEvents
    {
        // The const int values are what the source-generated log methods bind to; the EventId
        // fields below are the consumer-facing form. They are declared together so the two can
        // never drift apart.

        /// <summary>Numeric ID of <see cref="SecretResolved"/>.</summary>
        public const int SecretResolvedId = 2001;

        /// <summary>Numeric ID of <see cref="SecretRead"/>.</summary>
        public const int SecretReadId = 2002;

        /// <summary>Numeric ID of <see cref="ResolutionFailed"/>.</summary>
        public const int ResolutionFailedId = 2003;

        /// <summary>Numeric ID of <see cref="ResolutionSummary"/>.</summary>
        public const int ResolutionSummaryId = 2004;

        /// <summary>Numeric ID of <see cref="KvVersionProbe"/>.</summary>
        public const int KvVersionProbeId = 2005;

        /// <summary>Numeric ID of <see cref="ResolverNotLastSource"/>.</summary>
        public const int ResolverNotLastSourceId = 2006;

        /// <summary>Numeric ID of <see cref="UnresolvedReference"/>.</summary>
        public const int UnresolvedReferenceId = 2007;

        /// <summary>Numeric ID of <see cref="AuthMethodSelected"/>.</summary>
        public const int AuthMethodSelectedId = 2101;

        /// <summary>Numeric ID of <see cref="Reauthenticated"/>.</summary>
        public const int ReauthenticatedId = 2102;

        /// <summary>Numeric ID of <see cref="VaultAddressUnverified"/>.</summary>
        public const int VaultAddressUnverifiedId = 2103;

        /// <summary>Numeric ID of <see cref="CacheHit"/>.</summary>
        public const int CacheHitId = 2201;

        /// <summary>A single secret was read from Vault. Debug.</summary>
        public static readonly EventId SecretResolved = new EventId(SecretResolvedId, nameof(SecretResolved));

        /// <summary>A secret was read successfully, without naming the key. Information.</summary>
        public static readonly EventId SecretRead = new EventId(SecretReadId, nameof(SecretRead));

        /// <summary>A reference could not be resolved and its value was set to null. Error.</summary>
        public static readonly EventId ResolutionFailed = new EventId(ResolutionFailedId, nameof(ResolutionFailed));

        /// <summary>Summary of how many references were resolved. Information.</summary>
        public static readonly EventId ResolutionSummary = new EventId(ResolutionSummaryId, nameof(ResolutionSummary));

        /// <summary>The mount answered as KV v1 after a v2 attempt. Debug.</summary>
        public static readonly EventId KvVersionProbe = new EventId(KvVersionProbeId, nameof(KvVersionProbe));

        /// <summary>Which authentication method was selected for a vault. Information.</summary>
        public static readonly EventId AuthMethodSelected = new EventId(AuthMethodSelectedId, nameof(AuthMethodSelected));

        /// <summary>Vault rejected the login token, so the client re-authenticated. Information.</summary>
        public static readonly EventId Reauthenticated = new EventId(ReauthenticatedId, nameof(Reauthenticated));

        /// <summary>
        /// A vault address taken from a configuration reference could not be matched against a
        /// trusted address and was contacted anyway. Warning.
        /// </summary>
        /// <remarks>
        /// Worth alerting on: it means the host this process sent its Vault credential to was
        /// decided by a configuration value rather than by deployment configuration. Set
        /// <see cref="HashiCorpVaultResolverOptions.StrictVaultAddressValidation"/> to turn it
        /// into a failure.
        /// </remarks>
        public static readonly EventId VaultAddressUnverified = new EventId(VaultAddressUnverifiedId, nameof(VaultAddressUnverified));

        /// <summary>
        /// A configuration source was registered after the resolver, so it overrides the resolved
        /// secrets and is itself never resolved. Error.
        /// </summary>
        public static readonly EventId ResolverNotLastSource = new EventId(ResolverNotLastSourceId, nameof(ResolverNotLastSource));

        /// <summary>A configuration value still holds an unresolved Vault reference. Error.</summary>
        public static readonly EventId UnresolvedReference = new EventId(UnresolvedReferenceId, nameof(UnresolvedReference));

        /// <summary>A secret was served from the in-memory cache. Debug.</summary>
        public static readonly EventId CacheHit = new EventId(CacheHitId, nameof(CacheHit));
    }
}
