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
        /// <summary>A single secret was read from Key Vault. Debug.</summary>
        public static readonly EventId SecretResolved = new EventId(1001, nameof(SecretResolved));

        /// <summary>A secret was read successfully, without naming it. Information.</summary>
        public static readonly EventId SecretRead = new EventId(1002, nameof(SecretRead));

        /// <summary>A reference could not be resolved and its value was set to null. Error.</summary>
        public static readonly EventId ResolutionFailed = new EventId(1003, nameof(ResolutionFailed));

        /// <summary>Summary of how many configuration values were resolved. Information.</summary>
        public static readonly EventId ResolutionSummary = new EventId(1004, nameof(ResolutionSummary));

        /// <summary>A secret past its ExpiresOn was used anyway. Warning.</summary>
        public static readonly EventId SecretExpired = new EventId(1101, nameof(SecretExpired));

        /// <summary>A secret expires within the configured warning threshold. Warning.</summary>
        public static readonly EventId SecretExpiringSoon = new EventId(1102, nameof(SecretExpiringSoon));

        /// <summary>A secret before its NotBefore was used anyway. Warning.</summary>
        public static readonly EventId SecretNotYetValid = new EventId(1103, nameof(SecretNotYetValid));

        /// <summary>A secret was served from the in-memory cache. Debug.</summary>
        public static readonly EventId CacheHit = new EventId(1201, nameof(CacheHit));
    }
}
