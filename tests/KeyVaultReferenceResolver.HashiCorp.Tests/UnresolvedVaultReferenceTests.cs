using System.Collections.Concurrent;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Xunit;
using KeyVaultReferenceResolver.Testing;

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
        public void LaterSourceCarryingAReference_FailsTheBuild()
        {
            var builder = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?> { ["Db:Password"] = Reference });

            builder.AddHashiCorpVaultResolver(Resolver());
            builder.AddInMemoryCollection(new Dictionary<string, string?> { ["Db:Password"] = Reference });

            var ex = Assert.Throws<HashiCorpVaultReferenceResolutionException>(() => builder.Build());

            Assert.Contains("Db:Password", ex.Message, StringComparison.Ordinal);
            Assert.DoesNotContain("secret/data/myapp", ex.Message, StringComparison.Ordinal);
        }

        /// <summary>
        /// The case that used to slip through entirely: with no references at registration the
        /// resolver returned early and registered nothing to notice what arrived later.
        /// </summary>
        [Fact]
        public void LaterSourceIsTheOnlySourceWithAReference_StillFailsTheBuild()
        {
            var builder = new ConfigurationBuilder();
            builder.AddHashiCorpVaultResolver(Resolver());
            builder.AddInMemoryCollection(new Dictionary<string, string?> { ["Added:Later"] = Reference });

            var ex = Assert.Throws<HashiCorpVaultReferenceResolutionException>(() => builder.Build());
            Assert.Contains("Added:Later", ex.Message, StringComparison.Ordinal);
        }

        /// <summary>
        /// Only a later reference is an error; a later source overriding a resolved secret with a
        /// literal value is legitimate.
        /// </summary>
        [Fact]
        public void LaterSourceWithoutAReference_IsAllowedAndStillOverrides()
        {
            var builder = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?> { ["Db:Password"] = Reference });

            builder.AddHashiCorpVaultResolver(Resolver());
            builder.AddInMemoryCollection(new Dictionary<string, string?> { ["Db:Password"] = "local-override" });

            Assert.Equal("local-override", builder.Build()["Db:Password"]);
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
            // Built without the resolver: this is the check for a configuration assembled
            // somewhere the resolver was never registered, so nothing failed the build.
            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?> { ["Added:Later"] = Reference })
                .Build();

            var logger = new RecordingLogger();

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

        private static FakeSecretResolver Resolver() =>
            new FakeSecretResolver().AddSecret(Reference, "p@ssw0rd");

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
