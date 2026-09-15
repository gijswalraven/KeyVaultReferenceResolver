using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using Xunit;

namespace KeyVaultReferenceResolver.HashiCorp.Tests
{
    /// <summary>
    /// Covers which Vault address the resolver is willing to contact when the address comes from
    /// a configuration reference rather than from deployment configuration.
    /// </summary>
    /// <remarks>
    /// The reference is a configuration value, so anything able to influence configuration can
    /// name a host; whatever it names receives this process's Vault credential. These tests assert
    /// on <see cref="HashiCorpVaultSecretResolver.ResolveTrustedAddress"/> directly, because the
    /// accepted cases would otherwise go on to attempt a real login.
    /// </remarks>
    [Collection("VaultEnvironment")]
    public class VaultAddressTrustTests
    {
        private const string Configured = "https://vault.example.com";
        private const string Attacker = "https://attacker.example.net";

        [Fact]
        public void ExplicitVaultAddress_MismatchedReference_Throws()
        {
            using var env = new VaultAddressEnvironment(null);
            var resolver = Create(new HashiCorpVaultResolverOptions { VaultAddress = Configured });

            var ex = Assert.Throws<InvalidOperationException>(() => resolver.ResolveTrustedAddress(Attacker));
            Assert.Contains("does not match the configured", ex.Message, StringComparison.Ordinal);
        }

        [Theory]
        [InlineData("https://vault.example.com")]
        [InlineData("https://vault.example.com/")]
        [InlineData("https://VAULT.example.com")]
        public void ExplicitVaultAddress_EquivalentReference_Allowed(string reference)
        {
            using var env = new VaultAddressEnvironment(null);
            var resolver = Create(new HashiCorpVaultResolverOptions { VaultAddress = Configured });

            Assert.Equal(reference, resolver.ResolveTrustedAddress(reference));
        }

        /// <summary>
        /// The fix: VAULT_ADDR is the most common way the address is supplied, and before this it
        /// pinned nothing at all - the reference-supplied address was used unchecked.
        /// </summary>
        [Fact]
        public void EnvironmentAddress_MismatchedReference_Strict_Throws()
        {
            using var env = new VaultAddressEnvironment(Configured);
            var resolver = Create(new HashiCorpVaultResolverOptions { StrictVaultAddressValidation = true });

            var ex = Assert.Throws<InvalidOperationException>(() => resolver.ResolveTrustedAddress(Attacker));
            Assert.Contains("does not match VAULT_ADDR", ex.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void EnvironmentAddress_MismatchedReference_NotStrict_WarnsAndAllows()
        {
            using var env = new VaultAddressEnvironment(Configured);
            var logger = new RecordingLogger();
            var resolver = Create(new HashiCorpVaultResolverOptions { StrictVaultAddressValidation = false }, logger);

            Assert.Equal(Attacker, resolver.ResolveTrustedAddress(Attacker));

            var warning = Assert.Single(logger.Entries, e => e.Level == LogLevel.Warning);
            Assert.Equal(HashiCorpLogEvents.VaultAddressUnverified, warning.EventId);
            Assert.Contains(Attacker, warning.Text, StringComparison.Ordinal);
        }

        [Fact]
        public void EnvironmentAddress_MatchingReference_Allowed()
        {
            using var env = new VaultAddressEnvironment(Configured);
            var logger = new RecordingLogger();
            var resolver = Create(new HashiCorpVaultResolverOptions { StrictVaultAddressValidation = true }, logger);

            Assert.Equal(Configured, resolver.ResolveTrustedAddress(Configured));
            Assert.DoesNotContain(logger.Entries, e => e.Level >= LogLevel.Warning);
        }

        [Fact]
        public void NothingConfigured_Strict_Throws()
        {
            using var env = new VaultAddressEnvironment(null);
            var resolver = Create(new HashiCorpVaultResolverOptions { StrictVaultAddressValidation = true });

            var ex = Assert.Throws<InvalidOperationException>(() => resolver.ResolveTrustedAddress(Attacker));
            Assert.Contains("nothing to validate it against", ex.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void NothingConfigured_NotStrict_WarnsAndAllows()
        {
            using var env = new VaultAddressEnvironment(null);
            var logger = new RecordingLogger();
            var resolver = Create(new HashiCorpVaultResolverOptions { StrictVaultAddressValidation = false }, logger);

            Assert.Equal(Attacker, resolver.ResolveTrustedAddress(Attacker));

            var warning = Assert.Single(logger.Entries, e => e.Level == LogLevel.Warning);
            Assert.Equal(HashiCorpLogEvents.VaultAddressUnverified, warning.EventId);
        }

        [Fact]
        public void AllowedVaultAddresses_ListedReference_Allowed()
        {
            using var env = new VaultAddressEnvironment(null);
            var options = new HashiCorpVaultResolverOptions
            {
                AllowedVaultAddresses = { Configured, "https://vault-dr.example.com" }
            };

            Assert.Equal(Configured, Create(options).ResolveTrustedAddress(Configured));
        }

        [Fact]
        public void AllowedVaultAddresses_UnlistedReference_Throws()
        {
            using var env = new VaultAddressEnvironment(null);
            var options = new HashiCorpVaultResolverOptions
            {
                AllowedVaultAddresses = { Configured }
            };

            var ex = Assert.Throws<InvalidOperationException>(() => Create(options).ResolveTrustedAddress(Attacker));
            Assert.Contains("is not listed in", ex.Message, StringComparison.Ordinal);
        }

        /// <summary>
        /// An allow-list that does not cover the address must lose to nothing: the permissive
        /// VAULT_ADDR path below it must not rescue an address the operator has excluded.
        /// </summary>
        [Fact]
        public void AllowedVaultAddresses_UnlistedReference_ThrowsEvenWhenEnvironmentMatches()
        {
            using var env = new VaultAddressEnvironment(Attacker);
            var options = new HashiCorpVaultResolverOptions
            {
                AllowedVaultAddresses = { Configured }
            };

            Assert.Throws<InvalidOperationException>(() => Create(options).ResolveTrustedAddress(Attacker));
        }

        /// <summary>
        /// Transport is checked before trust, so a plaintext address is refused whether or not it
        /// would have been trusted.
        /// </summary>
        [Fact]
        public void PlaintextReference_WithoutOptIn_Throws()
        {
            using var env = new VaultAddressEnvironment("http://vault.example.com");
            var resolver = Create(new HashiCorpVaultResolverOptions { AllowInsecureTransport = false });

            var ex = Assert.Throws<InvalidOperationException>(
                () => resolver.ResolveTrustedAddress("http://vault.example.com"));
            Assert.Contains("must use https", ex.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void EmptyReferenceAddress_FallsBackToEffectiveAddress()
        {
            using var env = new VaultAddressEnvironment(Configured);
            var resolver = Create(new HashiCorpVaultResolverOptions());

            Assert.Equal(Configured, resolver.ResolveTrustedAddress(string.Empty));
        }

        private static HashiCorpVaultSecretResolver Create(
            HashiCorpVaultResolverOptions options,
            ILogger? logger = null)
        {
            return new HashiCorpVaultSecretResolver(options, logger);
        }

        /// <summary>
        /// Sets VAULT_ADDR for the duration of a test and restores whatever was there before.
        /// </summary>
        private sealed class VaultAddressEnvironment : IDisposable
        {
            private readonly string? _original;

            public VaultAddressEnvironment(string? value)
            {
                _original = Environment.GetEnvironmentVariable("VAULT_ADDR");
                Environment.SetEnvironmentVariable("VAULT_ADDR", value);
            }

            public void Dispose()
            {
                Environment.SetEnvironmentVariable("VAULT_ADDR", _original);
            }
        }

        /// <summary>
        /// Minimal <see cref="ILogger"/> that keeps the level, event ID and rendered text of every
        /// entry, so a test can assert that a specific event was raised rather than matching on
        /// message text alone.
        /// </summary>
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
