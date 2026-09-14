using System.Collections.Concurrent;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Xunit;

namespace KeyVaultReferenceResolver.HashiCorp.Tests
{
    /// <summary>
    /// Covers what happens to a Vault reference the resolver never saw.
    /// </summary>
    /// <remarks>
    /// Resolution is a single sweep performed while the configuration is built, so a source
    /// registered after the resolver overrides the resolved secrets and is itself never resolved.
    /// The application would then read the literal <c>@HashiCorp.Vault(...)</c> string and use it
    /// as a credential.
    /// </remarks>
    public class UnresolvedVaultReferenceTests
    {
        private const string Reference =
            "@HashiCorp.Vault(VaultAddress=https://vault.example.com;SecretPath=secret/data/myapp;SecretKey=password)";

        [Fact]
        public void SourceRegisteredAfterTheResolver_IsReported()
        {
            var logger = new RecordingLogger();

            var builder = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?> { ["Db:Password"] = Reference });

            builder.AddHashiCorpVaultResolver(Resolver(), options: null, logger: logger);
            builder.AddInMemoryCollection(new Dictionary<string, string?> { ["Db:Password"] = Reference });
            builder.Build();

            var error = Assert.Single(logger.Entries, e => e.EventId == HashiCorpLogEvents.ResolverNotLastSource);
            Assert.Equal(LogLevel.Error, error.Level);
        }

        [Fact]
        public void ResolverRegisteredLast_IsNotReported()
        {
            var logger = new RecordingLogger();

            var builder = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?> { ["Db:Password"] = Reference });

            builder.AddHashiCorpVaultResolver(Resolver(), options: null, logger: logger);
            builder.Build();

            Assert.DoesNotContain(logger.Entries, e => e.EventId == HashiCorpLogEvents.ResolverNotLastSource);
        }

        [Fact]
        public void FindUnresolvedVaultReferences_ReportsAKeyALaterSourceReintroduced()
        {
            var builder = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?> { ["Db:Password"] = Reference });

            builder.AddHashiCorpVaultResolver(Resolver());
            builder.AddInMemoryCollection(new Dictionary<string, string?> { ["Db:Password"] = Reference });

            var configuration = builder.Build();

            Assert.Equal(Reference, configuration["Db:Password"]);
            Assert.Equal("Db:Password", Assert.Single(configuration.FindUnresolvedVaultReferences()));
        }

        [Fact]
        public void FindUnresolvedVaultReferences_IsEmptyWhenEverythingResolved()
        {
            var builder = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?> { ["Db:Password"] = Reference });

            builder.AddHashiCorpVaultResolver(Resolver());
            var configuration = builder.Build();

            Assert.Equal("p@ssw0rd", configuration["Db:Password"]);
            Assert.Empty(configuration.FindUnresolvedVaultReferences());
        }

        [Fact]
        public void AssertNoUnresolvedVaultReferences_ThrowsNamingTheKey()
        {
            var builder = new ConfigurationBuilder();
            builder.AddHashiCorpVaultResolver(Resolver());
            builder.AddInMemoryCollection(new Dictionary<string, string?> { ["Added:Later"] = Reference });

            var logger = new RecordingLogger();
            var configuration = builder.Build();

            var ex = Assert.Throws<HashiCorpVaultReferenceResolutionException>(
                () => configuration.AssertNoUnresolvedVaultReferences(logger));

            Assert.Contains("Added:Later", ex.Message, StringComparison.Ordinal);

            // The key is named; the path and key inside the reference are not.
            Assert.DoesNotContain("secret/data/myapp", ex.Message, StringComparison.Ordinal);
            Assert.Contains(logger.Entries, e => e.EventId == HashiCorpLogEvents.UnresolvedReference);
        }

        [Fact]
        public void AssertNoUnresolvedVaultReferences_PassesOnACleanConfiguration()
        {
            var builder = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?> { ["Db:Password"] = Reference });

            builder.AddHashiCorpVaultResolver(Resolver());

            builder.Build().AssertNoUnresolvedVaultReferences();
        }

        private static MockSecretResolver Resolver() =>
            new MockSecretResolver().AddSecret(Reference, "p@ssw0rd");

        private sealed class RecordingLogger : ILogger
        {
            private readonly ConcurrentQueue<Entry> _entries = new();

            public IEnumerable<Entry> Entries => _entries;

            public IDisposable BeginScope<TState>(TState state) where TState : notnull => NullScope.Instance;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(
                LogLevel logLevel,
                EventId eventId,
                TState state,
                Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
                _entries.Enqueue(new Entry(logLevel, eventId, formatter(state, exception)));
            }

            internal sealed record Entry(LogLevel Level, EventId EventId, string Text);

            private sealed class NullScope : IDisposable
            {
                public static readonly NullScope Instance = new();
                public void Dispose() { }
            }
        }
    }
}
