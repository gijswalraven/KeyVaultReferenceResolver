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
        /// <summary>A single secret was read from Vault. Debug.</summary>
        public static readonly EventId SecretResolved = new EventId(2001, nameof(SecretResolved));

        /// <summary>A secret was read successfully, without naming the key. Information.</summary>
        public static readonly EventId SecretRead = new EventId(2002, nameof(SecretRead));

        /// <summary>A reference could not be resolved and its value was set to null. Error.</summary>
        public static readonly EventId ResolutionFailed = new EventId(2003, nameof(ResolutionFailed));

        /// <summary>Summary of how many references were resolved. Information.</summary>
        public static readonly EventId ResolutionSummary = new EventId(2004, nameof(ResolutionSummary));

        /// <summary>The mount answered as KV v1 after a v2 attempt. Debug.</summary>
        public static readonly EventId KvVersionProbe = new EventId(2005, nameof(KvVersionProbe));

        /// <summary>Which authentication method was selected for a vault. Information.</summary>
        public static readonly EventId AuthMethodSelected = new EventId(2101, nameof(AuthMethodSelected));

        /// <summary>Vault rejected the login token, so the client re-authenticated. Information.</summary>
        public static readonly EventId Reauthenticated = new EventId(2102, nameof(Reauthenticated));

        /// <summary>A secret was served from the in-memory cache. Debug.</summary>
        public static readonly EventId CacheHit = new EventId(2201, nameof(CacheHit));
    }
}
