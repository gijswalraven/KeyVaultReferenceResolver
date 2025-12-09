using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
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
        /// <summary>
        /// Pattern to match Key Vault references using SecretUri format.
        /// Supports format: @Microsoft.KeyVault(SecretUri=https://vault.vault.azure.net/secrets/secret-name)
        /// </summary>
        private static readonly Regex SecretUriPattern = new Regex(
            @"@Microsoft\.KeyVault\(SecretUri=(?<uri>https://[^)]+)\)",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        /// <summary>
        /// Pattern to match Key Vault references using VaultName format.
        /// Supports format: @Microsoft.KeyVault(VaultName=myvault;SecretName=mysecret) or
        /// @Microsoft.KeyVault(VaultName=myvault;SecretName=mysecret;SecretVersion=version123)
        /// </summary>
        private static readonly Regex VaultNamePattern = new Regex(
            @"@Microsoft\.KeyVault\(VaultName=(?<vault>[^;)]+);SecretName=(?<secret>[^;)]+)(?:;SecretVersion=(?<version>[^)]+))?\)",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

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

            var resolver = new KeyVaultSecretResolver(
                options,
                logger as ILogger<KeyVaultSecretResolver>);

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
            logger = logger ?? NullLogger.Instance;

            var tempConfig = builder.Build();
            var resolvedValues = new Dictionary<string, string?>();

            foreach (var kvp in tempConfig.AsEnumerable())
            {
                if (string.IsNullOrEmpty(kvp.Value))
                    continue;

                var secretUri = TryExtractSecretUri(kvp.Value);
                if (secretUri == null)
                    continue;

                try
                {
                    var secretValue = secretResolver.ResolveSecret(secretUri);
                    resolvedValues[kvp.Key] = secretValue;
                    logger.LogInformation("Resolved Key Vault reference: {ConfigKey}", kvp.Key);
                }
                catch (Exception ex)
                {
                    logger.LogWarning(ex, "Failed to resolve Key Vault reference for '{ConfigKey}'", kvp.Key);

                    if (options.ThrowOnResolveFailure)
                    {
                        throw new KeyVaultReferenceResolutionException(
                            $"Failed to resolve Key Vault reference for configuration key '{kvp.Key}'",
                            kvp.Key,
                            secretUri,
                            ex);
                    }
                }
            }

            if (resolvedValues.Count > 0)
            {
                builder.AddInMemoryCollection(resolvedValues);
                logger.LogInformation("Resolved {Count} Key Vault reference(s)", resolvedValues.Count);
            }

            return builder;
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

                // Construct the full URI
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
