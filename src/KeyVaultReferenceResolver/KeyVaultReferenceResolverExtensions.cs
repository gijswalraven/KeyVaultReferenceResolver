using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Azure.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace KeyVaultReferenceResolver
{
    /// <summary>
    /// Extension methods for adding Key Vault reference resolution to <see cref="IConfigurationBuilder"/>.
    /// </summary>
    public static class KeyVaultReferenceResolverExtensions
    {
        // Regex timeout to prevent ReDoS attacks on attacker-influenced configuration values.
        private static readonly TimeSpan RegexTimeout = TimeSpan.FromSeconds(1);

        /// <summary>
        /// Key Vault DNS suffix for the Azure public cloud, used when none is configured.
        /// </summary>
        private const string DefaultVaultDnsSuffix = "vault.azure.net";

        /// <summary>
        /// Pattern to match Key Vault references using SecretUri format.
        /// Supports format: @Microsoft.KeyVault(SecretUri=https://vault.vault.azure.net/secrets/secret-name)
        /// </summary>
        private static readonly Regex SecretUriPattern = new Regex(
            @"@Microsoft\.KeyVault\(SecretUri=(?<uri>https://[^)\s\\]+)\)",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Pattern to match Key Vault references using VaultName format.
        /// Supports format: @Microsoft.KeyVault(VaultName=myvault;SecretName=mysecret) or
        /// @Microsoft.KeyVault(VaultName=myvault;SecretName=mysecret;SecretVersion=version123)
        /// </summary>
        /// <remarks>
        /// The vault, secret and version groups are constrained to Azure's own naming rules
        /// (alphanumerics and hyphens). A looser pattern would let a tampered configuration value
        /// inject path or authority characters into the URI built in <see cref="TryExtractSecretUri"/>
        /// and redirect the lookup to a host outside Key Vault.
        /// </remarks>
        private static readonly Regex VaultNamePattern = new Regex(
            @"@Microsoft\.KeyVault\(VaultName=(?<vault>[A-Za-z0-9-]{3,24});SecretName=(?<secret>[A-Za-z0-9-]{1,127})(?:;SecretVersion=(?<version>[A-Za-z0-9]{1,64}))?\)",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Adds Key Vault reference resolution to the configuration builder using default options.
        /// </summary>
        /// <param name="builder">The configuration builder.</param>
        /// <returns>The configuration builder for chaining.</returns>
        public static IConfigurationBuilder AddKeyVaultReferenceResolver(this IConfigurationBuilder builder)
        {
            return builder.AddKeyVaultReferenceResolver(options: null, logger: null);
        }

        /// <summary>
        /// Adds Key Vault reference resolution to the configuration builder.
        /// </summary>
        /// <param name="builder">The configuration builder.</param>
        /// <param name="credential">The Azure credential to use.</param>
        /// <returns>The configuration builder for chaining.</returns>
        public static IConfigurationBuilder AddKeyVaultReferenceResolver(
            this IConfigurationBuilder builder,
            TokenCredential credential)
        {
            if (credential == null)
                throw new ArgumentNullException(nameof(credential));

            return builder.AddKeyVaultReferenceResolver(
                new KeyVaultReferenceResolverOptions { Credential = credential },
                logger: null);
        }

        /// <summary>
        /// Adds Key Vault reference resolution to the configuration builder.
        /// </summary>
        /// <param name="builder">The configuration builder.</param>
        /// <param name="configureOptions">Action to configure the resolver options.</param>
        /// <returns>The configuration builder for chaining.</returns>
        public static IConfigurationBuilder AddKeyVaultReferenceResolver(
            this IConfigurationBuilder builder,
            Action<KeyVaultReferenceResolverOptions> configureOptions)
        {
            if (configureOptions == null)
                throw new ArgumentNullException(nameof(configureOptions));

            var options = new KeyVaultReferenceResolverOptions();
            configureOptions(options);
            return builder.AddKeyVaultReferenceResolver(options, logger: null);
        }

        /// <summary>
        /// Adds Key Vault reference resolution to the configuration builder.
        /// </summary>
        /// <param name="builder">The configuration builder.</param>
        /// <param name="options">The resolver options.</param>
        /// <param name="logger">Optional logger for diagnostics.</param>
        /// <returns>The configuration builder for chaining.</returns>
        public static IConfigurationBuilder AddKeyVaultReferenceResolver(
            this IConfigurationBuilder builder,
            KeyVaultReferenceResolverOptions? options,
            ILogger? logger)
        {
            options = options ?? new KeyVaultReferenceResolverOptions();
            logger = logger ?? NullLogger.Instance;

            var resolver = new KeyVaultSecretResolver(options, logger);

            return builder.AddKeyVaultReferenceResolver(resolver, options, logger);
        }

        /// <summary>
        /// Adds Key Vault reference resolution to the configuration builder using a custom secret resolver.
        /// </summary>
        /// <param name="builder">The configuration builder.</param>
        /// <param name="secretResolver">The secret resolver to use.</param>
        /// <param name="options">The resolver options.</param>
        /// <param name="logger">Optional logger for diagnostics.</param>
        /// <returns>The configuration builder for chaining.</returns>
        /// <remarks>
        /// References are resolved with bounded concurrency under a single
        /// <see cref="KeyVaultReferenceResolverOptions.OverallTimeout"/> budget. A reference that
        /// cannot be resolved sets its configuration key to <c>null</c>, so the literal
        /// <c>@Microsoft.KeyVault(...)</c> string is never handed to the application as if it were
        /// the secret, regardless of
        /// <see cref="KeyVaultReferenceResolverOptions.ThrowOnResolveFailure"/>.
        /// </remarks>
        public static IConfigurationBuilder AddKeyVaultReferenceResolver(
            this IConfigurationBuilder builder,
            ISecretResolver secretResolver,
            KeyVaultReferenceResolverOptions? options = null,
            ILogger? logger = null)
        {
            if (builder == null)
                throw new ArgumentNullException(nameof(builder));
            if (secretResolver == null)
                throw new ArgumentNullException(nameof(secretResolver));

            options = options ?? new KeyVaultReferenceResolverOptions();
            options.Validate();
            logger = logger ?? NullLogger.Instance;

            // Key -> the distinct secret URIs referenced by that key's value. A value may embed
            // more than one reference, and may embed a reference alongside literal text.
            var referencingKeys = new Dictionary<string, string>();
            var distinctUris = new HashSet<string>(StringComparer.Ordinal);

            // builder.Build() instantiates a fresh set of providers, separate from the ones the
            // caller's own Build() will create. Each AddJsonFile(reloadOnChange: true) among them
            // holds a FileSystemWatcher, so leaving this undisposed leaks one per source for the
            // lifetime of the process.
            var tempConfig = builder.Build();
            try
            {
                foreach (var kvp in tempConfig.AsEnumerable())
                {
                    if (string.IsNullOrEmpty(kvp.Value))
                        continue;

                    var found = false;
                    foreach (var uri in EnumerateSecretUris(kvp.Value!, options.VaultDnsSuffix))
                    {
                        distinctUris.Add(uri);
                        found = true;
                    }

                    if (found)
                        referencingKeys[kvp.Key] = kvp.Value!;
                }
            }
            finally
            {
                (tempConfig as IDisposable)?.Dispose();
            }

            if (distinctUris.Count == 0)
                return builder;

            var secrets = ResolveSecrets(distinctUris, secretResolver, options, logger, referencingKeys);
            var resolvedValues = new Dictionary<string, string?>(referencingKeys.Count);

            foreach (var entry in referencingKeys)
            {
                resolvedValues[entry.Key] = SubstituteReferences(entry.Value, secrets, options.VaultDnsSuffix);
            }

            builder.AddInMemoryCollection(resolvedValues);

            var succeeded = resolvedValues.Count(pair => pair.Value != null);
            Log.ResolutionSummary(logger, succeeded, resolvedValues.Count);

            return builder;
        }

        /// <summary>
        /// Replaces every reference in a configuration value with its resolved secret, leaving
        /// any surrounding literal text intact. Returns null if any reference in the value could
        /// not be resolved, so a partially substituted credential is never handed to the caller.
        /// </summary>
        private static string? SubstituteReferences(
            string originalValue,
            Dictionary<string, string?> secrets,
            string vaultDnsSuffix)
        {
            var failed = false;

            string Substitute(Match match)
            {
                var uri = UriFromMatch(match, vaultDnsSuffix);
                if (uri != null && secrets.TryGetValue(uri, out var secret) && secret != null)
                    return secret;

                failed = true;
                return string.Empty;
            }

            var result = SecretUriPattern.Replace(originalValue, m => Substitute(m));
            result = VaultNamePattern.Replace(result, m => Substitute(m));

            return failed ? null : result;
        }

        /// <summary>
        /// Resolves every distinct secret URI with bounded concurrency under one overall budget.
        /// </summary>
        private static Dictionary<string, string?> ResolveSecrets(
            HashSet<string> distinctUris,
            ISecretResolver secretResolver,
            KeyVaultReferenceResolverOptions options,
            ILogger logger,
            Dictionary<string, string> referencingKeys)
        {
            var resolved = new ConcurrentDictionary<string, string?>(StringComparer.Ordinal);
            var failures = new ConcurrentQueue<KeyVaultReferenceResolutionException>();

            using (var overallCts = new CancellationTokenSource())
            using (var gate = new SemaphoreSlim(options.MaxConcurrency))
            {
                if (options.OverallTimeout != System.Threading.Timeout.InfiniteTimeSpan)
                    overallCts.CancelAfter(options.OverallTimeout);

                var tasks = distinctUris
                    .Select(uri => ResolveOneAsync(
                        uri, secretResolver, logger, resolved, failures, gate,
                        referencingKeys, options.VaultDnsSuffix, overallCts.Token))
                    .ToArray();

                Task.WhenAll(tasks).GetAwaiter().GetResult();
            }

            if (options.ThrowOnResolveFailure && failures.TryDequeue(out var firstFailure))
                throw firstFailure;

            return new Dictionary<string, string?>(resolved, StringComparer.Ordinal);
        }

        private static async Task ResolveOneAsync(
            string secretUri,
            ISecretResolver secretResolver,
            ILogger logger,
            ConcurrentDictionary<string, string?> resolved,
            ConcurrentQueue<KeyVaultReferenceResolutionException> failures,
            SemaphoreSlim gate,
            Dictionary<string, string> referencingKeys,
            string vaultDnsSuffix,
            CancellationToken cancellationToken)
        {
            await gate.WaitAsync(CancellationToken.None).ConfigureAwait(false);
            try
            {
                var secretValue = await secretResolver
                    .ResolveSecretAsync(secretUri, cancellationToken)
                    .ConfigureAwait(false);

                resolved[secretUri] = secretValue;
                // Debug rather than Information: one record per key produces a map of exactly
                // which configuration keys hold credentials, and key names routinely embed
                // tenant or customer identifiers (Clients:AcmeCorp:ApiKey). The aggregate count
                // is logged at Information instead.
                if (logger.IsEnabled(LogLevel.Debug))
                {
                    var maskedUri = MaskUri(secretUri);
                    Log.ReferenceResolved(logger, maskedUri);
                }
            }
            catch (Exception ex)
            {
                // Fail closed. Leaving a key unset would let the application read the literal
                // "@Microsoft.KeyVault(SecretUri=...)" string and use it as a credential.
                resolved[secretUri] = null;

                var configKey = FirstKeyReferencing(secretUri, referencingKeys, vaultDnsSuffix);

                failures.Enqueue(new KeyVaultReferenceResolutionException(
                    $"Failed to resolve Key Vault reference for configuration key '{configKey}'",
                    configKey,
                    secretUri,
                    ex));

                Log.ResolutionFailed(logger, ex, configKey);
            }
            finally
            {
                gate.Release();
            }
        }

        /// <summary>
        /// Finds a configuration key whose value references the given URI, for error reporting.
        /// </summary>
        private static string FirstKeyReferencing(
            string secretUri,
            Dictionary<string, string> referencingKeys,
            string vaultDnsSuffix)
        {
            foreach (var entry in referencingKeys)
            {
                foreach (var uri in EnumerateSecretUris(entry.Value, vaultDnsSuffix))
                {
                    if (string.Equals(uri, secretUri, StringComparison.Ordinal))
                        return entry.Key;
                }
            }

            return string.Empty;
        }

        /// <summary>
        /// Enumerates the secret URIs referenced by a configuration value, in both formats.
        /// </summary>
        private static IEnumerable<string> EnumerateSecretUris(string value, string vaultDnsSuffix)
        {
            foreach (Match match in SecretUriPattern.Matches(value))
            {
                var uri = UriFromMatch(match, vaultDnsSuffix);
                if (uri != null)
                    yield return uri;
            }

            foreach (Match match in VaultNamePattern.Matches(value))
            {
                var uri = UriFromMatch(match, vaultDnsSuffix);
                if (uri != null)
                    yield return uri;
            }
        }

        /// <summary>
        /// Builds the secret URI a single matched reference points at.
        /// </summary>
        private static string? UriFromMatch(Match match, string vaultDnsSuffix)
        {
            if (!match.Success)
                return null;

            var uriGroup = match.Groups["uri"];
            if (uriGroup.Success)
                return uriGroup.Value;

            var vaultName = match.Groups["vault"].Value;
            var secretName = match.Groups["secret"].Value;
            var version = match.Groups["version"].Value;

            var suffix = string.IsNullOrWhiteSpace(vaultDnsSuffix)
                ? DefaultVaultDnsSuffix
                : vaultDnsSuffix.TrimStart('.');

            // The patterns restrict every group to alphanumerics and hyphens, so nothing here
            // can alter the authority of the resulting URI.
            var uri = $"https://{vaultName}.{suffix}/secrets/{secretName}";
            if (!string.IsNullOrEmpty(version))
                uri += $"/{version}";

            return uri;
        }

        private static string MaskUri(string uri)
        {
            return KeyVaultReferenceResolutionException.MaskSecretUri(uri);
        }

        /// <summary>
        /// Checks if a configuration value contains a Key Vault reference.
        /// Supports both SecretUri and VaultName formats.
        /// </summary>
        /// <param name="value">The configuration value to check.</param>
        /// <returns>True if the value contains a Key Vault reference.</returns>
        public static bool IsKeyVaultReference(string? value)
        {
            if (string.IsNullOrEmpty(value))
                return false;

            return SecretUriPattern.IsMatch(value) || VaultNamePattern.IsMatch(value);
        }

        /// <summary>
        /// Extracts the secret URI from a Key Vault reference string.
        /// Supports both SecretUri and VaultName formats.
        /// For VaultName format, constructs the full URI.
        /// </summary>
        /// <param name="value">The configuration value containing the Key Vault reference.</param>
        /// <returns>The secret URI, or null if no valid reference is found.</returns>
        public static string? ExtractSecretUri(string? value)
        {
            return TryExtractSecretUri(value);
        }

        /// <summary>
        /// Tries to extract a secret URI from either format.
        /// </summary>
        private static string? TryExtractSecretUri(string? value)
        {
            if (string.IsNullOrEmpty(value))
                return null;

            // SecretUri format takes precedence, matching the previous behaviour. This public
            // entry point has no options, so the public-cloud suffix is used for VaultName.
            var uri = UriFromMatch(SecretUriPattern.Match(value!), DefaultVaultDnsSuffix);
            return uri ?? UriFromMatch(VaultNamePattern.Match(value!), DefaultVaultDnsSuffix);
        }
    }
}
