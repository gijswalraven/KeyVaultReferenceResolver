using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using VaultSharp;
using Xunit;

namespace KeyVaultReferenceResolver.HashiCorp.Tests
{
    /// <summary>
    /// Covers the identity of a cache entry and the size of the cache.
    /// </summary>
    /// <remarks>
    /// The cache was keyed on the reference exactly as written, so the same secret spelled two ways
    /// occupied two entries and <c>InvalidateCache</c> could evict one while the other kept serving
    /// the old value - a rotated credential silently still in use.
    /// </remarks>
    [Collection("VaultEnvironment")]
    public class VaultCacheKeyTests
    {
        private const string Address = "https://vault.example.com";

        [Theory]
        [InlineData("https://vault.example.com")]
        [InlineData("https://vault.example.com/")]
        [InlineData("https://VAULT.EXAMPLE.COM")]
        public async Task EquivalentAddresses_ShareOneCacheEntry(string equivalent)
        {
            using var env = new VaultAddressEnvironment(null);
            var resolver = Create();

            await resolver.ResolveSecretAsync(Reference(Address), TestContext.Current.CancellationToken);
            await resolver.ResolveSecretAsync(Reference(equivalent), TestContext.Current.CancellationToken);

            Assert.Equal(1, resolver.Reads);
        }

        [Fact]
        public async Task InvalidateCache_EvictsRegardlessOfHowTheAddressIsSpelled()
        {
            using var env = new VaultAddressEnvironment(null);
            var resolver = Create();

            await resolver.ResolveSecretAsync(Reference(Address), TestContext.Current.CancellationToken);
            resolver.InvalidateCache(Reference("https://VAULT.EXAMPLE.COM/"));
            await resolver.ResolveSecretAsync(Reference(Address), TestContext.Current.CancellationToken);

            Assert.Equal(2, resolver.Reads);
        }

        [Fact]
        public async Task InvalidateCache_WithAnUnparseableReference_DoesNotThrow()
        {
            using var env = new VaultAddressEnvironment(null);
            var resolver = Create();

            await resolver.ResolveSecretAsync(Reference(Address), TestContext.Current.CancellationToken);
            resolver.InvalidateCache("not-a-vault-reference");
            await resolver.ResolveSecretAsync(Reference(Address), TestContext.Current.CancellationToken);

            Assert.Equal(1, resolver.Reads);
        }

        [Fact]
        public async Task DifferentSecretKeys_AreDistinctEntries()
        {
            using var env = new VaultAddressEnvironment(null);
            var resolver = Create();

            await resolver.ResolveSecretAsync(Reference(Address, key: "password"), TestContext.Current.CancellationToken);
            await resolver.ResolveSecretAsync(Reference(Address, key: "username"), TestContext.Current.CancellationToken);

            Assert.Equal(2, resolver.Reads);
        }

        [Fact]
        public async Task CacheStopsGrowingAtMaxCacheEntries()
        {
            using var env = new VaultAddressEnvironment(null);
            var logger = new RecordingLogger();
            var resolver = Create(maxCacheEntries: 2, logger: logger);

            for (var pass = 0; pass < 2; pass++)
            {
                for (var i = 0; i < 3; i++)
                    await resolver.ResolveSecretAsync(Reference(Address, key: $"key{i}"), TestContext.Current.CancellationToken);
            }

            // Two cached and served from cache on the second pass; the third fetched both times.
            Assert.Equal(4, resolver.Reads);
            Assert.Single(logger.Entries, e => e.EventId == HashiCorpLogEvents.CacheFull);
        }

        private static string Reference(string address, string key = "password") =>
            $"@HashiCorp.Vault(VaultAddress={address};SecretPath=secret/data/myapp;SecretKey={key})";

        private static CountingResolver Create(int? maxCacheEntries = null, ILogger? logger = null)
        {
            var options = new HashiCorpVaultResolverOptions
            {
                // Pinned explicitly: StrictVaultAddressValidation is on by default from 2.0, so a
                // resolver with nothing to validate the reference address against refuses to run.
                VaultAddress = Address,
                AuthMethod = new Authentication.TokenAuthMethod("test-token")
            };

            if (maxCacheEntries.HasValue)
                options.MaxCacheEntries = maxCacheEntries.Value;

            return new CountingResolver(options, logger);
        }

        /// <summary>
        /// Overrides the read so the cache behaviour around it can be driven without a live Vault.
        /// </summary>
        private sealed class CountingResolver : HashiCorpVaultSecretResolver
        {
            private int _reads;

            public CountingResolver(HashiCorpVaultResolverOptions options, ILogger? logger)
                : base(options, logger)
            {
            }

            public int Reads => _reads;

            protected override Task<string> ReadSecretAsync(
                IVaultClient client, string secretPath, string secretKey, CancellationToken cancellationToken)
            {
                Interlocked.Increment(ref _reads);
                return Task.FromResult("p@ssw0rd");
            }
        }

        private sealed class VaultAddressEnvironment : IDisposable
        {
            private readonly string? _original;

            public VaultAddressEnvironment(string? value)
            {
                _original = Environment.GetEnvironmentVariable("VAULT_ADDR");
                Environment.SetEnvironmentVariable("VAULT_ADDR", value);
            }

            public void Dispose() => Environment.SetEnvironmentVariable("VAULT_ADDR", _original);
        }

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
