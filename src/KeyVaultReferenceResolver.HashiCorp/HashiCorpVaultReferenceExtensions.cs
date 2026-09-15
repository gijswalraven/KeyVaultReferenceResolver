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

            // Key -> its original value. A value may embed a reference alongside literal text, and
            // may embed more than one.
            var referencingKeys = new Dictionary<string, string>();
            var distinctReferences = new HashSet<string>(StringComparer.Ordinal);

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
                    foreach (var reference in EnumerateReferences(kvp.Value!))
                    {
                        distinctReferences.Add(reference);
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

            if (distinctReferences.Count == 0)
            {
                // Registered even with nothing in it - see the Azure-side extension for why.
                builder.Add(new ResolvedVaultSecretsSource(new Dictionary<string, string?>(), logger));
                return builder;
            }

            var secrets = RunWithoutSynchronizationContext(
                () => ResolveReferences(distinctReferences, secretResolver, options, logger, referencingKeys));

            var resolvedValues = new Dictionary<string, string?>(referencingKeys.Count);
            foreach (var entry in referencingKeys)
                resolvedValues[entry.Key] = SubstituteReferences(entry.Value, secrets);

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
        /// <summary>
        /// Enumerates the Vault references embedded in a configuration value.
        /// </summary>
        /// <remarks>
        /// The attribute form can appear anywhere in a value, so a connection string may carry one
        /// alongside literal text. The <c>hashicorp://</c> form is anchored and can only be a whole
        /// value, so it is matched as such.
        /// </remarks>
        private static IEnumerable<string> EnumerateReferences(string value)
        {
            foreach (var reference in HashiCorpVaultSecretResolver.EnumerateAttributeReferences(value))
                yield return reference;

            if (HashiCorpVaultSecretResolver.IsWholeValueUriReference(value))
                yield return value;
        }

        /// <summary>
        /// Replaces every reference in a value with its resolved secret, leaving surrounding
        /// literal text intact. Returns null if any reference in the value could not be resolved,
        /// so a partially substituted credential is never handed to the caller.
        /// </summary>
        private static string? SubstituteReferences(string originalValue, Dictionary<string, string?> secrets)
        {
            // A whole-value hashicorp:// reference has nothing around it to preserve.
            if (HashiCorpVaultSecretResolver.IsWholeValueUriReference(originalValue))
                return secrets.TryGetValue(originalValue, out var whole) ? whole : null;

            var failed = false;

            var result = HashiCorpVaultSecretResolver.ReplaceAttributeReferences(originalValue, reference =>
            {
                if (secrets.TryGetValue(reference, out var secret) && secret != null)
                    return secret;

                failed = true;
                return string.Empty;
            });

            return failed ? null : result;
        }

        private static Dictionary<string, string?> ResolveReferences(
            HashSet<string> references,
            ISecretResolver secretResolver,
            HashiCorpVaultResolverOptions options,
            ILogger logger,
            Dictionary<string, string> referencingKeys)
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
                        reference, secretResolver, logger, resolved, failures, gate,
                        referencingKeys, overallCts.Token))
                    .ToArray();

                Task.WhenAll(tasks).GetAwaiter().GetResult();
            }

            if (options.ThrowOnResolveFailure && failures.TryDequeue(out var firstFailure))
                throw firstFailure;

            return new Dictionary<string, string?>(resolved);
        }

        private static async Task ResolveOneAsync(
            string reference,
            ISecretResolver secretResolver,
            ILogger logger,
            ConcurrentDictionary<string, string?> resolved,
            ConcurrentQueue<HashiCorpVaultReferenceResolutionException> failures,
            SemaphoreSlim gate,
            Dictionary<string, string> referencingKeys,
            CancellationToken cancellationToken)
        {
            await gate.WaitAsync(CancellationToken.None).ConfigureAwait(false);
            try
            {
                var secretValue = await secretResolver
                    .ResolveSecretAsync(reference, cancellationToken)
                    .ConfigureAwait(false);

                resolved[reference] = secretValue;
            }
            catch (Exception ex)
            {
                // Fail closed. Leaving the key unset would let the application read the literal
                // "@HashiCorp.Vault(...)" string and use it as a credential.
                resolved[reference] = null;

                var configKey = FirstKeyReferencing(reference, referencingKeys);

                failures.Enqueue(new HashiCorpVaultReferenceResolutionException(
                    $"Failed to resolve HashiCorp Vault reference for configuration key '{configKey}'",
                    configKey,
                    reference,
                    ex));

                HashiCorpLog.ResolutionFailed(logger, ex, configKey);
            }
            finally
            {
                gate.Release();
            }
        }

        /// <summary>
        /// Finds a configuration key whose value carries the given reference, for error reporting.
        /// </summary>
        private static string FirstKeyReferencing(string reference, Dictionary<string, string> referencingKeys)
        {
            foreach (var entry in referencingKeys)
            {
                foreach (var candidate in EnumerateReferences(entry.Value))
                {
                    if (string.Equals(candidate, reference, StringComparison.Ordinal))
                        return entry.Key;
                }
            }

            return string.Empty;
        }

        /// <summary>
        /// Runs the resolution on a thread with no <see cref="SynchronizationContext"/>.
        /// </summary>
        /// <remarks>
        /// Configuration is built synchronously, so the asynchronous resolution has to be waited
        /// on. The library's own awaits all use ConfigureAwait(false), but the ISecretResolver it
        /// awaits belongs to the caller: a resolver that yields without ConfigureAwait(false)
        /// posts its continuation to whatever context was current when it was invoked, and that
        /// thread is the one blocked waiting for it. Startup then hangs with no error.
        ///
        /// Moving only the wait is not enough - the tasks are started here too, so the
        /// continuation would already have been posted to the captured context. The whole
        /// resolution runs on the thread pool, where there is no context to post back to.
        /// </remarks>
        private static T RunWithoutSynchronizationContext<T>(Func<T> resolve)
        {
            if (SynchronizationContext.Current == null)
                return resolve();

            return Task.Run(resolve).GetAwaiter().GetResult();
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
