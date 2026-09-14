using System.Collections.Generic;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace KeyVaultReferenceResolver
{
    /// <summary>
    /// Configuration source holding the values resolved from Key Vault.
    /// </summary>
    /// <remarks>
    /// This replaces a plain <c>AddInMemoryCollection</c> for one reason: <see cref="Build"/>
    /// receives the builder, which is the only point at which the library can see whether any
    /// source was registered after it. A later source wins, so if it still carries a literal
    /// <c>@Microsoft.KeyVault(...)</c> value for a key resolved here, the application reads the
    /// reference string and uses it as a credential. Resolution happens once, when
    /// <c>AddKeyVaultReferenceResolver</c> is called, so a source added afterwards is never
    /// resolved at all.
    /// </remarks>
    internal sealed class ResolvedSecretsSource : IConfigurationSource
    {
        private readonly IDictionary<string, string?> _values;
        private readonly ILogger _logger;

        public ResolvedSecretsSource(IDictionary<string, string?> values, ILogger logger)
        {
            _values = values;
            _logger = logger;
        }

        public IConfigurationProvider Build(IConfigurationBuilder builder)
        {
            WarnIfNotLastSource(builder);
            return new ResolvedSecretsProvider(_values);
        }

        private void WarnIfNotLastSource(IConfigurationBuilder builder)
        {
            var sources = builder.Sources;
            var position = sources.IndexOf(this);

            // Not found means someone has rebuilt the source list around us; nothing useful to say.
            if (position < 0)
                return;

            var later = sources.Count - position - 1;
            if (later > 0)
                Log.ResolverNotLastSource(_logger, later);
        }

        /// <summary>
        /// Serves the resolved values. A key whose secret could not be resolved is present with a
        /// null value, so it shadows the literal reference in the source it came from rather than
        /// letting that reference fall through to the application.
        /// </summary>
        private sealed class ResolvedSecretsProvider : ConfigurationProvider
        {
            private readonly IDictionary<string, string?> _values;

            public ResolvedSecretsProvider(IDictionary<string, string?> values)
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
