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

            var tempConfig = builder.Build();
            var references = new List<KeyValuePair<string, string>>();

            foreach (var kvp in tempConfig.AsEnumerable())
            {
                if (string.IsNullOrEmpty(kvp.Value))
                    continue;

                var secretUri = TryExtractSecretUri(kvp.Value);
                if (secretUri == null)
                    continue;

                references.Add(new KeyValuePair<string, string>(kvp.Key, secretUri));
            }

            if (references.Count == 0)
                return builder;

            var resolvedValues = ResolveReferences(references, secretResolver, options, logger);

            if (resolvedValues.Count > 0)
            {
                builder.AddInMemoryCollection(resolvedValues);

                var succeeded = resolvedValues.Count(pair => pair.Value != null);
                logger.LogInformation(
                    "Resolved {Count} of {Total} Key Vault reference(s)",
                    succeeded,
                    resolvedValues.Count);
            }

            return builder;
        }

        /// <summary>
        /// Resolves every reference with bounded concurrency under one overall time budget.
        /// </summary>
        private static Dictionary<string, string?> ResolveReferences(
            List<KeyValuePair<string, string>> references,
            ISecretResolver secretResolver,
            KeyVaultReferenceResolverOptions options,
            ILogger logger)
        {
            var resolved = new ConcurrentDictionary<string, string?>();
            var failures = new ConcurrentQueue<KeyVaultReferenceResolutionException>();

            using (var overallCts = new CancellationTokenSource())
            using (var gate = new SemaphoreSlim(options.MaxConcurrency))
            {
                if (options.OverallTimeout != System.Threading.Timeout.InfiniteTimeSpan)
                    overallCts.CancelAfter(options.OverallTimeout);

                var tasks = references
                    .Select(reference => ResolveOneAsync(
                        reference, secretResolver, logger, resolved, failures, gate, overallCts.Token))
                    .ToArray();

                Task.WhenAll(tasks).GetAwaiter().GetResult();
            }

            if (options.ThrowOnResolveFailure && failures.TryDequeue(out var firstFailure))
                throw firstFailure;

            return new Dictionary<string, string?>(resolved);
        }

        private static async Task ResolveOneAsync(
            KeyValuePair<string, string> reference,
            ISecretResolver secretResolver,
            ILogger logger,
            ConcurrentDictionary<string, string?> resolved,
            ConcurrentQueue<KeyVaultReferenceResolutionException> failures,
            SemaphoreSlim gate,
            CancellationToken cancellationToken)
        {
            await gate.WaitAsync(CancellationToken.None).ConfigureAwait(false);
            try
            {
                var secretValue = await secretResolver
                    .ResolveSecretAsync(reference.Value, cancellationToken)
                    .ConfigureAwait(false);

                resolved[reference.Key] = secretValue;
                // Debug rather than Information: one record per key produces a map of exactly
                // which configuration keys hold credentials, and key names routinely embed
                // tenant or customer identifiers (Clients:AcmeCorp:ApiKey). The aggregate count
                // is logged at Information instead.
                logger.LogDebug("Resolved Key Vault reference: {ConfigKey}", reference.Key);
            }
            catch (Exception ex)
            {
                // Fail closed. Leaving the key unset would let the application read the literal
                // "@Microsoft.KeyVault(SecretUri=...)" string and use it as a credential.
                resolved[reference.Key] = null;

                failures.Enqueue(new KeyVaultReferenceResolutionException(
                    $"Failed to resolve Key Vault reference for configuration key '{reference.Key}'",
                    reference.Key,
                    reference.Value,
                    ex));

                logger.LogError(
                    ex,
                    "Failed to resolve Key Vault reference for '{ConfigKey}'; the value has been set to null",
                    reference.Key);
            }
            finally
            {
                gate.Release();
            }
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

            // Try SecretUri format first
            var secretUriMatch = SecretUriPattern.Match(value);
            if (secretUriMatch.Success)
            {
                return secretUriMatch.Groups["uri"].Value;
            }

            // Try VaultName format
            var vaultNameMatch = VaultNamePattern.Match(value);
            if (vaultNameMatch.Success)
            {
                var vaultName = vaultNameMatch.Groups["vault"].Value;
                var secretName = vaultNameMatch.Groups["secret"].Value;
                var version = vaultNameMatch.Groups["version"].Value;

                // Construct the full URI. The pattern restricts every group to alphanumerics and
                // hyphens, so nothing here can alter the authority of the resulting URI.
                var uri = $"https://{vaultName}.vault.azure.net/secrets/{secretName}";
                if (!string.IsNullOrEmpty(version))
                {
                    uri += $"/{version}";
                }
                return uri;
            }

            return null;
        }
    }
}
