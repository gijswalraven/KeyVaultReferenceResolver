using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
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

            var resolver = new HashiCorpVaultSecretResolver(options, logger);

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
            options.Validate();
            logger = logger ?? NullLogger.Instance;

            var references = new List<KeyValuePair<string, string>>();

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

                    if (!HashiCorpVaultSecretResolver.IsHashiCorpVaultReference(kvp.Value))
                        continue;

                    references.Add(new KeyValuePair<string, string>(kvp.Key, kvp.Value!));
                }
            }
            finally
            {
                (tempConfig as IDisposable)?.Dispose();
            }

            if (references.Count == 0)
                return builder;

            var resolvedValues = ResolveReferences(references, secretResolver, options, logger);

            if (resolvedValues.Count > 0)
            {
                // Not AddInMemoryCollection: this source detects, at Build time, that something
                // was registered after it and would override the secrets it just resolved.
                builder.Add(new ResolvedVaultSecretsSource(resolvedValues, logger));

                var succeeded = resolvedValues.Count(pair => pair.Value != null);
                HashiCorpLog.ResolutionSummary(logger, succeeded, resolvedValues.Count);
            }

            return builder;
        }

        /// <summary>
        /// Resolves every reference with bounded concurrency under one overall time budget.
        /// </summary>
        private static Dictionary<string, string?> ResolveReferences(
            List<KeyValuePair<string, string>> references,
            ISecretResolver secretResolver,
            HashiCorpVaultResolverOptions options,
            ILogger logger)
        {
            var resolved = new ConcurrentDictionary<string, string?>();
            var failures = new ConcurrentQueue<HashiCorpVaultReferenceResolutionException>();

            using (var overallCts = new CancellationTokenSource())
            using (var gate = new SemaphoreSlim(options.MaxConcurrency))
            {
                if (options.OverallTimeout != Timeout.InfiniteTimeSpan)
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
            ConcurrentQueue<HashiCorpVaultReferenceResolutionException> failures,
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
                // Debug rather than Information - see the Azure-side extension for rationale.
                HashiCorpLog.ReferenceResolved(logger, reference.Key);
            }
            catch (Exception ex)
            {
                // Fail closed. Leaving the key unset would let the application read the literal
                // "@HashiCorp.Vault(...)" string and use it as a credential.
                resolved[reference.Key] = null;

                failures.Enqueue(new HashiCorpVaultReferenceResolutionException(
                    $"Failed to resolve HashiCorp Vault reference for configuration key '{reference.Key}'",
                    reference.Key,
                    reference.Value,
                    ex));

                HashiCorpLog.ResolutionFailed(logger, ex, reference.Key);
            }
            finally
            {
                gate.Release();
            }
        }

        /// <summary>
        /// Returns the configuration keys whose value still contains an unresolved Vault reference.
        /// </summary>
        /// <param name="configuration">The built configuration to inspect.</param>
        /// <returns>The offending keys, in configuration order. Empty when everything resolved.</returns>
        public static IReadOnlyList<string> FindUnresolvedVaultReferences(this IConfiguration configuration)
        {
            if (configuration == null)
                throw new ArgumentNullException(nameof(configuration));

            var unresolved = new List<string>();

            foreach (var kvp in configuration.AsEnumerable())
            {
                if (!string.IsNullOrEmpty(kvp.Value) && IsHashiCorpVaultReference(kvp.Value))
                    unresolved.Add(kvp.Key);
            }

            return unresolved;
        }

        /// <summary>
        /// Throws if any configuration value still contains an unresolved Vault reference.
        /// </summary>
        /// <param name="configuration">The built configuration to inspect.</param>
        /// <param name="logger">Optional logger; each offending key is logged before throwing.</param>
        /// <exception cref="HashiCorpVaultReferenceResolutionException">
        /// Thrown when at least one value still holds a reference.
        /// </exception>
        /// <remarks>
        /// Call this immediately after <c>Build()</c>. References are resolved once while the
        /// configuration is built, so a source registered after the resolver - or a reloading
        /// source that gains a reference later - is never resolved, and the literal
        /// <c>@HashiCorp.Vault(...)</c> string would be used as a credential.
        /// </remarks>
        public static void AssertNoUnresolvedVaultReferences(this IConfiguration configuration, ILogger? logger = null)
        {
            var unresolved = configuration.FindUnresolvedVaultReferences();
            if (unresolved.Count == 0)
                return;

            if (logger != null)
            {
                foreach (var key in unresolved)
                    HashiCorpLog.UnresolvedReference(logger, key);
            }

            throw new HashiCorpVaultReferenceResolutionException(
                "Configuration still contains unresolved HashiCorp Vault reference(s) for: " +
                string.Join(", ", unresolved) +
                ". Register AddHashiCorpVaultResolver after every other configuration source.");
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
