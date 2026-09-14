using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Extensions.Logging;
using Xunit;

namespace KeyVaultReferenceResolver.Tests;

/// <summary>
/// Covers the identity of a cache entry and the size of the cache.
/// </summary>
/// <remarks>
/// The cache was keyed on the reference string exactly as written, so the same secret spelled two
/// ways occupied two entries and <c>InvalidateCache</c> could evict one while the other kept
/// serving the old value - a rotated credential silently still in use. Nothing evicted entries
/// either, so a caller resolving references chosen at runtime grew the cache without limit.
/// </remarks>
public class CacheKeyAndBoundsTests
{
    private const string Canonical = "https://myvault.vault.azure.net/secrets/db-password";

    [Theory]
    [InlineData("https://MYVAULT.vault.azure.net/secrets/db-password")]
    [InlineData("https://myvault.vault.azure.net/secrets/db-password/")]
    [InlineData("https://myvault.Vault.Azure.Net/secrets/db-password")]
    public async Task EquivalentSpellings_ShareOneCacheEntry(string equivalent)
    {
        var resolver = new CountingResolver();

        await resolver.ResolveSecretAsync(Canonical, TestContext.Current.CancellationToken);
        await resolver.ResolveSecretAsync(equivalent, TestContext.Current.CancellationToken);

        Assert.Equal(1, resolver.Fetches);
    }

    [Fact]
    public async Task InvalidateCache_EvictsRegardlessOfHowTheReferenceIsSpelled()
    {
        var resolver = new CountingResolver();

        await resolver.ResolveSecretAsync(Canonical, TestContext.Current.CancellationToken);
        resolver.InvalidateCache("https://MYVAULT.vault.azure.net/secrets/db-password");
        await resolver.ResolveSecretAsync(Canonical, TestContext.Current.CancellationToken);

        Assert.Equal(2, resolver.Fetches);
    }

    [Fact]
    public async Task InvalidateCache_WithAnUnparseableReference_DoesNotThrow()
    {
        var resolver = new CountingResolver();

        await resolver.ResolveSecretAsync(Canonical, TestContext.Current.CancellationToken);
        resolver.InvalidateCache("not-a-uri");

        // The valid entry is untouched.
        await resolver.ResolveSecretAsync(Canonical, TestContext.Current.CancellationToken);
        Assert.Equal(1, resolver.Fetches);
    }

    [Fact]
    public async Task DifferentVersions_AreDistinctEntries()
    {
        var resolver = new CountingResolver();

        await resolver.ResolveSecretAsync(Canonical, TestContext.Current.CancellationToken);
        await resolver.ResolveSecretAsync($"{Canonical}/abc123", TestContext.Current.CancellationToken);

        Assert.Equal(2, resolver.Fetches);
    }

    [Fact]
    public async Task CacheStopsGrowingAtMaxCacheEntries()
    {
        var logger = new RecordingLogger();
        var resolver = new CountingResolver(maxCacheEntries: 2, logger: logger);

        // Two secrets fill the cache; the third is resolved but not cached.
        for (var i = 0; i < 3; i++)
            await resolver.ResolveSecretAsync(Numbered(i), TestContext.Current.CancellationToken);

        // The first two are served from cache on a second pass, the third is fetched again.
        for (var i = 0; i < 3; i++)
            await resolver.ResolveSecretAsync(Numbered(i), TestContext.Current.CancellationToken);

        Assert.Equal(1, resolver.FetchesFor(Numbered(0)));
        Assert.Equal(1, resolver.FetchesFor(Numbered(1)));
        Assert.Equal(2, resolver.FetchesFor(Numbered(2)));

        var warning = Assert.Single(logger.Entries, e => e.EventId == LogEvents.CacheFull);
        Assert.Equal(LogLevel.Warning, warning.Level);
    }

    [Fact]
    public async Task CacheFull_IsReportedOncePerResolver()
    {
        var logger = new RecordingLogger();
        var resolver = new CountingResolver(maxCacheEntries: 1, logger: logger);

        for (var i = 0; i < 5; i++)
            await resolver.ResolveSecretAsync(Numbered(i), TestContext.Current.CancellationToken);

        Assert.Single(logger.Entries, e => e.EventId == LogEvents.CacheFull);
    }

    [Fact]
    public async Task MaxCacheEntriesZero_MeansNoLimit()
    {
        var logger = new RecordingLogger();
        var resolver = new CountingResolver(maxCacheEntries: 0, logger: logger);

        for (var i = 0; i < 50; i++)
            await resolver.ResolveSecretAsync(Numbered(i), TestContext.Current.CancellationToken);
        for (var i = 0; i < 50; i++)
            await resolver.ResolveSecretAsync(Numbered(i), TestContext.Current.CancellationToken);

        Assert.Equal(50, resolver.Fetches);
        Assert.DoesNotContain(logger.Entries, e => e.EventId == LogEvents.CacheFull);
    }

    [Fact]
    public void NegativeMaxCacheEntries_IsRejected()
    {
        var options = new KeyVaultReferenceResolverOptions { MaxCacheEntries = -1 };

        Assert.Throws<ArgumentOutOfRangeException>(() => options.Validate());
    }

    private static string Numbered(int index) =>
        string.Create(CultureInfo.InvariantCulture, $"https://myvault.vault.azure.net/secrets/secret-{index}");

    private sealed class CountingResolver : KeyVaultSecretResolver
    {
        private readonly ConcurrentDictionary<string, int> _fetches = new();

        public CountingResolver(int? maxCacheEntries = null, ILogger? logger = null)
            : base(Options(maxCacheEntries), logger)
        {
        }

        public int Fetches => _fetches.Values.Sum();

        public int FetchesFor(string uri)
        {
            var name = uri.Substring(uri.LastIndexOf('/') + 1);
            return _fetches.TryGetValue(name, out var count) ? count : 0;
        }

        protected override Task<KeyVaultSecret> FetchSecretAsync(
            Uri vaultUri,
            string secretName,
            string? version,
            CancellationToken cancellationToken)
        {
            _fetches.AddOrUpdate(secretName, 1, (_, existing) => existing + 1);
            return Task.FromResult(new KeyVaultSecret(secretName, "value"));
        }

        private static KeyVaultReferenceResolverOptions Options(int? maxCacheEntries)
        {
            var options = new KeyVaultReferenceResolverOptions
            {
                Credential = new Azure.Identity.DefaultAzureCredential()
            };

            if (maxCacheEntries.HasValue)
                options.MaxCacheEntries = maxCacheEntries.Value;

            return options;
        }
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
