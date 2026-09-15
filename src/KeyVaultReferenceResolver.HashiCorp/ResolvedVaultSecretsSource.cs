using System;
using System.Collections.Generic;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace KeyVaultReferenceResolver.HashiCorp
{
    /// <summary>
    /// Configuration source holding the values resolved from HashiCorp Vault.
    /// </summary>
    /// <remarks>
    /// This replaces a plain <c>AddInMemoryCollection</c> for one reason: <see cref="Build"/>
    /// receives the builder, which is the only point at which the library can see whether any
    /// source was registered after it. A later source wins, so if it still carries a literal
    /// <c>@HashiCorp.Vault(...)</c> value for a key resolved here, the application reads the
    /// reference string and uses it as a credential. Resolution happens once, when
    /// <c>AddHashiCorpVaultResolver</c> is called, so a source added afterwards is never
    /// resolved at all.
    /// </remarks>
    internal sealed class ResolvedVaultSecretsSource : IConfigurationSource
    {
        private readonly IDictionary<string, string?> _values;
        private readonly ILogger _logger;

        public ResolvedVaultSecretsSource(IDictionary<string, string?> values, ILogger logger)
        {
            _values = values;
            _logger = logger;
        }

        public IConfigurationProvider Build(IConfigurationBuilder builder)
        {
            InspectLaterSources(builder);
            return new ResolvedVaultSecretsProvider(_values);
        }

        /// <summary>
        /// Rejects a configuration source registered after the resolver that still carries an
        /// unresolved reference.
        /// </summary>
        /// <remarks>
        /// <para>
        /// A later source overrides the values resolved here and is itself never resolved, so a
        /// reference in one reaches the application as the literal <c>@HashiCorp.Vault(...)</c> string and is used as
        /// a credential. In 1.4.x this was logged at <c>Error</c>; it now throws, because a
        /// credential that is silently a placeholder fails somewhere far away from the cause.
        /// </para>
        /// <para>
        /// What throws is a later source <i>carrying a reference</i>, not the mere existence of
        /// one. Registering <c>AddCommandLine</c> or <c>AddEnvironmentVariables</c> last is both
        /// common and correct, and overriding a resolved secret with a literal value is a
        /// legitimate thing to do - for a test, or a local run. Only the unresolvable case is an
        /// error, and that case is still reported as HashiCorpLog.ResolverNotLastSource at
        /// <c>Error</c> when the later sources cannot be inspected.
        /// </para>
        /// </remarks>
        private void InspectLaterSources(IConfigurationBuilder builder)
        {
            var sources = builder.Sources;
            var position = sources.IndexOf(this);

            // Not found means someone has rebuilt the source list around us; nothing useful to say.
            if (position < 0)
                return;

            var later = new List<IConfigurationSource>();
            for (var i = position + 1; i < sources.Count; i++)
                later.Add(sources[i]);

            if (later.Count == 0)
                return;

            List<string> unresolved;
            try
            {
                unresolved = FindReferences(later, builder);
            }
            catch (Exception)
            {
                // A later source that cannot be built here will fail the caller's own Build()
                // moments from now with a better message. Fall back to reporting the shape of the
                // problem rather than masking that failure with one of our own.
                HashiCorpLog.ResolverNotLastSource(_logger, later.Count);
                return;
            }

            if (unresolved.Count == 0)
                return;

            foreach (var key in unresolved)
                HashiCorpLog.UnresolvedReference(_logger, key);

            throw new HashiCorpVaultReferenceResolutionException(
                "Configuration source(s) registered after AddHashiCorpVaultResolver carry unresolved reference(s) for: " +
                string.Join(", ", unresolved) +
                ". They override the resolved secrets and are never themselves resolved, so the " +
                "application would read the reference string and use it as a credential. Register " +
                "AddHashiCorpVaultResolver after every other configuration source.");
        }

        /// <summary>
        /// Builds the given sources in isolation and returns the keys still holding a reference.
        /// </summary>
        private static List<string> FindReferences(List<IConfigurationSource> sources, IConfigurationBuilder builder)
        {
            var providers = new List<IConfigurationProvider>(sources.Count);
            foreach (var source in sources)
                providers.Add(source.Build(builder));

            // ConfigurationRoot loads each provider on construction. These are separate instances
            // from the ones the caller's Build() will create, so disposing them here does not
            // disturb the configuration being built.
            var root = new ConfigurationRoot(providers);
            try
            {
                var found = new List<string>();

                foreach (var entry in root.AsEnumerable())
                {
                    if (!string.IsNullOrEmpty(entry.Value) && HashiCorpVaultSecretResolver.IsHashiCorpVaultReference(entry.Value))
                        found.Add(entry.Key);
                }

                return found;
            }
            finally
            {
                root.Dispose();
            }
        }

        /// <summary>
        /// Serves the resolved values. A key whose secret could not be resolved is present with a
        /// null value, so it shadows the literal reference in the source it came from rather than
        /// letting that reference fall through to the application.
        /// </summary>
        private sealed class ResolvedVaultSecretsProvider : ConfigurationProvider
        {
            private readonly IDictionary<string, string?> _values;

            public ResolvedVaultSecretsProvider(IDictionary<string, string?> values)
            {
                _values = values;
            }

            public override void Load()
            {
                Data = new Dictionary<string, string?>(_values, System.StringComparer.OrdinalIgnoreCase);
            }
        }
    }
}
