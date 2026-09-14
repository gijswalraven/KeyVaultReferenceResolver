using System;
using Microsoft.Extensions.Logging;

namespace KeyVaultReferenceResolver
{
    /// <summary>
    /// Source-generated log methods for this package.
    /// </summary>
    /// <remarks>
    /// Generated rather than hand-written <see cref="LoggerExtensions"/> calls so that the
    /// message template is compiled once, the arguments are not boxed into a <c>params</c> array,
    /// and nothing is evaluated when the level is disabled. The EventId values are the same ones
    /// documented on <see cref="LogEvents"/>, which stays as the public reference for consumers
    /// writing alerts.
    /// </remarks>
    internal static partial class Log
    {
        [LoggerMessage(
            EventId = LogEvents.CacheHitId,
            Level = LogLevel.Debug,
            Message = "Returning cached secret for URI: {SecretUri}")]
        public static partial void CacheHit(ILogger logger, string secretUri);

        [LoggerMessage(
            EventId = LogEvents.SecretResolvedId,
            Level = LogLevel.Debug,
            Message = "Resolving secret {SecretName} from vault {VaultUri}")]
        public static partial void ResolvingSecret(ILogger logger, string secretName, Uri vaultUri);

        [LoggerMessage(
            EventId = LogEvents.SecretReadId,
            Level = LogLevel.Information,
            Message = "Successfully resolved secret from {VaultUri}")]
        public static partial void SecretRead(ILogger logger, Uri vaultUri);

        [LoggerMessage(
            EventId = LogEvents.SecretNotYetValidId,
            Level = LogLevel.Warning,
            Message = "Secret from {VaultUri} is not valid until {NotBefore} but is being used now")]
        public static partial void SecretNotYetValid(ILogger logger, Uri? vaultUri, string notBefore);

        [LoggerMessage(
            EventId = LogEvents.SecretExpiredId,
            Level = LogLevel.Warning,
            Message = "Secret from {VaultUri} expired at {ExpiresOn} and is being used anyway")]
        public static partial void SecretExpired(ILogger logger, Uri? vaultUri, string expiresOn);

        [LoggerMessage(
            EventId = LogEvents.SecretExpiringSoonId,
            Level = LogLevel.Warning,
            Message = "Secret from {VaultUri} expires at {ExpiresOn}, within the {Threshold} warning threshold")]
        public static partial void SecretExpiringSoon(ILogger logger, Uri? vaultUri, string expiresOn, TimeSpan threshold);

        [LoggerMessage(
            EventId = LogEvents.SecretResolvedId,
            Level = LogLevel.Debug,
            Message = "Resolved Key Vault reference: {SecretUri}")]
        public static partial void ReferenceResolved(ILogger logger, string secretUri);

        [LoggerMessage(
            EventId = LogEvents.ResolutionFailedId,
            Level = LogLevel.Error,
            Message = "Failed to resolve Key Vault reference for '{ConfigKey}'; the value has been set to null")]
        public static partial void ResolutionFailed(ILogger logger, Exception exception, string configKey);

        [LoggerMessage(
            EventId = LogEvents.ResolutionSummaryId,
            Level = LogLevel.Information,
            Message = "Resolved {Count} of {Total} configuration value(s) containing Key Vault reference(s)")]
        public static partial void ResolutionSummary(ILogger logger, int count, int total);
    }
}
