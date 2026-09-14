using System;
using System.Net;
using Microsoft.Extensions.Logging;

namespace KeyVaultReferenceResolver.HashiCorp
{
    /// <summary>
    /// Source-generated log methods for the HashiCorp Vault package.
    /// </summary>
    /// <remarks>
    /// See <see cref="HashiCorpLogEvents"/> for the consumer-facing event ID reference.
    /// </remarks>
    internal static partial class HashiCorpLog
    {
        [LoggerMessage(
            EventId = HashiCorpLogEvents.VaultAddressUnverifiedId,
            Level = LogLevel.Warning,
            Message = "Vault address {VaultAddress} came from a configuration reference and could not be matched " +
                      "against VaultAddress, AllowedVaultAddresses or VAULT_ADDR; contacting it anyway. Set " +
                      "StrictVaultAddressValidation to reject it instead.")]
        public static partial void VaultAddressUnverified(ILogger logger, string vaultAddress);

        [LoggerMessage(
            EventId = HashiCorpLogEvents.CacheHitId,
            Level = LogLevel.Debug,
            Message = "Returning cached secret for: {SecretUri}")]
        public static partial void CacheHit(ILogger logger, string secretUri);

        [LoggerMessage(
            EventId = HashiCorpLogEvents.SecretResolvedId,
            Level = LogLevel.Debug,
            Message = "Resolving secret {SecretKey} from path {SecretPath} at {VaultAddress}")]
        public static partial void ResolvingSecret(ILogger logger, string secretKey, string secretPath, string vaultAddress);

        [LoggerMessage(
            EventId = HashiCorpLogEvents.SecretReadId,
            Level = LogLevel.Information,
            Message = "Successfully resolved secret from {SecretPath}")]
        public static partial void SecretRead(ILogger logger, string secretPath);

        [LoggerMessage(
            EventId = HashiCorpLogEvents.SecretResolvedId,
            Level = LogLevel.Debug,
            Message = "Resolved HashiCorp Vault reference: {ConfigKey}")]
        public static partial void ReferenceResolved(ILogger logger, string configKey);

        [LoggerMessage(
            EventId = HashiCorpLogEvents.ResolutionFailedId,
            Level = LogLevel.Error,
            Message = "Failed to resolve HashiCorp Vault reference for '{ConfigKey}'; the value has been set to null")]
        public static partial void ResolutionFailed(ILogger logger, Exception exception, string configKey);

        [LoggerMessage(
            EventId = HashiCorpLogEvents.ResolutionSummaryId,
            Level = LogLevel.Information,
            Message = "Resolved {Count} of {Total} HashiCorp Vault reference(s)")]
        public static partial void ResolutionSummary(ILogger logger, int count, int total);

        [LoggerMessage(
            EventId = HashiCorpLogEvents.KvVersionProbeId,
            Level = LogLevel.Debug,
            Message = "Mount {MountPath} did not answer as KV v2 (HTTP {Status}); retrying as KV v1. Set KvVersion to skip this probe.")]
        public static partial void KvVersionProbe(ILogger logger, string mountPath, HttpStatusCode status);

        [LoggerMessage(
            EventId = HashiCorpLogEvents.AuthMethodSelectedId,
            Level = LogLevel.Information,
            Message = "Authenticating to Vault at {VaultAddress} using {AuthMethod}")]
        public static partial void AuthMethodSelected(ILogger logger, string vaultAddress, string authMethod);

        [LoggerMessage(
            EventId = HashiCorpLogEvents.ReauthenticatedId,
            Level = LogLevel.Information,
            Message = "Vault returned {Status} for {SecretPath}; re-authenticating and retrying once.")]
        public static partial void Reauthenticated(ILogger logger, HttpStatusCode status, string secretPath);
    }
}
