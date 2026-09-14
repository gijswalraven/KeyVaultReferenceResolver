using Microsoft.Extensions.Logging;

namespace KeyVaultReferenceResolver
{
    /// <summary>
    /// Event IDs for the records this library emits, so they can be filtered, alerted on and
    /// correlated rather than matched by message text.
    /// </summary>
    /// <remarks>
    /// These are part of the public surface deliberately. Secret access is the kind of activity
    /// an ISO 27001 or SOC 2 audit asks for evidence of, and a stable identifier is what makes a
    /// log-based control testable. IDs are grouped: 1000s for resolution, 1100s for secret
    /// validity, 1200s for caching.
    /// </remarks>
    public static class LogEvents
    {
        // The const int values are what the source-generated log methods bind to; the EventId
        // fields below are the consumer-facing form. They are declared together so the two can
        // never drift apart.

        /// <summary>Numeric ID of <see cref="SecretResolved"/>.</summary>
        public const int SecretResolvedId = 1001;

        /// <summary>Numeric ID of <see cref="SecretRead"/>.</summary>
        public const int SecretReadId = 1002;

        /// <summary>Numeric ID of <see cref="ResolutionFailed"/>.</summary>
        public const int ResolutionFailedId = 1003;

        /// <summary>Numeric ID of <see cref="ResolutionSummary"/>.</summary>
        public const int ResolutionSummaryId = 1004;

        /// <summary>Numeric ID of <see cref="SecretExpired"/>.</summary>
        public const int SecretExpiredId = 1101;

        /// <summary>Numeric ID of <see cref="SecretExpiringSoon"/>.</summary>
        public const int SecretExpiringSoonId = 1102;

        /// <summary>Numeric ID of <see cref="SecretNotYetValid"/>.</summary>
        public const int SecretNotYetValidId = 1103;

        /// <summary>Numeric ID of <see cref="CacheHit"/>.</summary>
        public const int CacheHitId = 1201;

        /// <summary>A single secret was read from Key Vault. Debug.</summary>
        public static readonly EventId SecretResolved = new EventId(SecretResolvedId, nameof(SecretResolved));

        /// <summary>A secret was read successfully, without naming it. Information.</summary>
        public static readonly EventId SecretRead = new EventId(SecretReadId, nameof(SecretRead));

        /// <summary>A reference could not be resolved and its value was set to null. Error.</summary>
        public static readonly EventId ResolutionFailed = new EventId(ResolutionFailedId, nameof(ResolutionFailed));

        /// <summary>Summary of how many configuration values were resolved. Information.</summary>
        public static readonly EventId ResolutionSummary = new EventId(ResolutionSummaryId, nameof(ResolutionSummary));

        /// <summary>A secret past its ExpiresOn was used anyway. Warning.</summary>
        public static readonly EventId SecretExpired = new EventId(SecretExpiredId, nameof(SecretExpired));

        /// <summary>A secret expires within the configured warning threshold. Warning.</summary>
        public static readonly EventId SecretExpiringSoon = new EventId(SecretExpiringSoonId, nameof(SecretExpiringSoon));

        /// <summary>A secret before its NotBefore was used anyway. Warning.</summary>
        public static readonly EventId SecretNotYetValid = new EventId(SecretNotYetValidId, nameof(SecretNotYetValid));

        /// <summary>A secret was served from the in-memory cache. Debug.</summary>
        public static readonly EventId CacheHit = new EventId(CacheHitId, nameof(CacheHit));
    }
}
