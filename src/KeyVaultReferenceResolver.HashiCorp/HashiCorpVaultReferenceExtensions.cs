using System;
using System.Collections.Generic;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace KeyVaultReferenceResolver.HashiCorp
{
    /// <summary>
    /// Extension methods for adding HashiCorp Vault reference resolution to <see cref="IConfigurationBuilder"/>.
    /// </summary>
    public static class HashiCorpVaultReferenceExtensions
    {
        /// <summary>
        /// Adds HashiCorp Vault reference resolution to the configuration builder using default options.
        /// Vault address and authentication are auto-detected from environment variables.
        /// </summary>
        /// <param name="builder">The configuration builder.</param>
        /// <returns>The configuration builder for chaining.</returns>
        public static IConfigurationBuilder AddHashiCorpVaultResolver(this IConfigurationBuilder builder)
        {
            return builder.AddHashiCorpVaultResolver(options: null, logger: null);
        }

        /// <summary>
        /// Adds HashiCorp Vault reference resolution to the configuration builder.
        /// </summary>
        /// <param name="builder">The configuration builder.</param>
        /// <param name="configureOptions">Action to configure the resolver options.</param>
        /// <returns>The configuration builder for chaining.</returns>
        public static IConfigurationBuilder AddHashiCorpVaultResolver(
            this IConfigurationBuilder builder,
            Action<HashiCorpVaultResolverOptions> configureOptions)
        {
            var options = new HashiCorpVaultResolverOptions();
            configureOptions(options);
            return builder.AddHashiCorpVaultResolver(options, logger: null);
        }

        /// <summary>
        /// Adds HashiCorp Vault reference resolution to the configuration builder.
        /// </summary>
        /// <param name="builder">The configuration builder.</param>
        /// <param name="options">The resolver options.</param>
        /// <param name="logger">Optional logger for diagnostics.</param>
        /// <returns>The configuration builder for chaining.</returns>
        public static IConfigurationBuilder AddHashiCorpVaultResolver(
            this IConfigurationBuilder builder,
            HashiCorpVaultResolverOptions? options,
            ILogger? logger = null)
        {
            options = options ?? new HashiCorpVaultResolverOptions();
            logger = logger ?? NullLogger.Instance;

            var resolver = new HashiCorpVaultSecretResolver(
                options,
                logger as ILogger<HashiCorpVaultSecretResolver>);

            return builder.AddHashiCorpVaultResolver(resolver, options, logger);
        }

        /// <summary>
        /// Adds HashiCorp Vault reference resolution to the configuration builder using a custom secret resolver.
        /// </summary>
        /// <param name="builder">The configuration builder.</param>
        /// <param name="secretResolver">The secret resolver to use.</param>
        /// <param name="options">The resolver options.</param>
        /// <param name="logger">Optional logger for diagnostics.</param>
        /// <returns>The configuration builder for chaining.</returns>
        public static IConfigurationBuilder AddHashiCorpVaultResolver(
            this IConfigurationBuilder builder,
            ISecretResolver secretResolver,
            HashiCorpVaultResolverOptions? options = null,
            ILogger? logger = null)
        {
            if (builder == null)
                throw new ArgumentNullException(nameof(builder));
            if (secretResolver == null)
                throw new ArgumentNullException(nameof(secretResolver));

            options = options ?? new HashiCorpVaultResolverOptions();
            logger = logger ?? NullLogger.Instance;

            var tempConfig = builder.Build();
            var resolvedValues = new Dictionary<string, string?>();

            foreach (var kvp in tempConfig.AsEnumerable())
            {
                if (string.IsNullOrEmpty(kvp.Value))
                    continue;

                if (!HashiCorpVaultSecretResolver.IsHashiCorpVaultReference(kvp.Value))
                    continue;

                try
                {
                    var secretValue = secretResolver.ResolveSecret(kvp.Value);
                    resolvedValues[kvp.Key] = secretValue;
                    logger.LogInformation("Resolved HashiCorp Vault reference: {ConfigKey}", kvp.Key);
                }
                catch (Exception ex)
                {
                    logger.LogWarning(ex, "Failed to resolve HashiCorp Vault reference for '{ConfigKey}'", kvp.Key);

                    if (options.ThrowOnResolveFailure)
                    {
                        throw new HashiCorpVaultReferenceResolutionException(
                            $"Failed to resolve HashiCorp Vault reference for configuration key '{kvp.Key}'",
                            kvp.Key,
                            kvp.Value,
                            ex);
                    }
                }
            }

            if (resolvedValues.Count > 0)
            {
                builder.AddInMemoryCollection(resolvedValues);
                logger.LogInformation("Resolved {Count} HashiCorp Vault reference(s)", resolvedValues.Count);
            }

            return builder;
        }

        /// <summary>
        /// Checks if a configuration value contains a HashiCorp Vault reference.
        /// Supports both @HashiCorp.Vault(...) and hashicorp:// URI formats.
        /// </summary>
        /// <param name="value">The configuration value to check.</param>
        /// <returns>True if the value contains a HashiCorp Vault reference.</returns>
        public static bool IsHashiCorpVaultReference(string? value)
        {
            return HashiCorpVaultSecretResolver.IsHashiCorpVaultReference(value);
        }

        /// <summary>
        /// Extracts secret information from a HashiCorp Vault reference string.
        /// </summary>
        /// <param name="value">The configuration value containing the HashiCorp Vault reference.</param>
        /// <returns>The vault address, secret path, and secret key, or null if no valid reference is found.</returns>
        public static (string vaultAddress, string secretPath, string secretKey)? ExtractSecretInfo(string? value)
        {
            return HashiCorpVaultSecretResolver.TryExtractSecretInfo(value);
        }
    }
}
