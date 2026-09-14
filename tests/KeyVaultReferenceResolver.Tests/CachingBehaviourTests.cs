using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace KeyVaultReferenceResolver.Tests;

/// <summary>
/// Pins the caching contract by counting vault fetches rather than by inspecting state.
/// </summary>
/// <remarks>
/// These are the tests that back the rotation documentation. Without them, "a rotated secret
/// is not picked up until the application restarts" and "CacheTtl defaults to infinite" are
/// claims in a README rather than properties of the code. The resolver-level tests drive the
/// real <see cref="KeyVaultSecretResolver"/> through its FetchSecretAsync seam, so the cache,
/// TTL and refresh code under test is the code that ships.
/// </remarks>
public class CachingBehaviourTests
{
    private const string SecretUri = "https://myvault.vault.azure.net/secrets/db-password";
    private const string Reference = "@Microsoft.KeyVault(SecretUri=https://myvault.vault.azure.net/secrets/db-password)";
    private const string OtherUri = "https://myvault.vault.azure.net/secrets/db-user";
    private const string OtherReference = "@Microsoft.KeyVault(SecretUri=https://myvault.vault.azure.net/secrets/db-user)";

    #region Configuration-level

    [Fact]
    public void SameSecretReferencedTwice_IsFetchedOnce()
    {
        // Arrange
        var resolver = new CountingSecretResolver { [SecretUri] = "p@ssw0rd" };

        var builder = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["First"] = Reference,
                ["Second"] = Reference,
                ["Third"] = $"prefix-{Reference}"
            });

        // Act
        builder.AddKeyVaultReferenceResolver(resolver);
        var config = builder.Build();

        // Assert - deduplicated across keys, not fetched once per key
        Assert.Equal(1, resolver.CallCount(SecretUri));
        Assert.Equal("p@ssw0rd", config["First"]);
        Assert.Equal("p@ssw0rd", config["Second"]);
        Assert.Equal("prefix-p@ssw0rd", config["Third"]);
    }

    [Fact]
    public void DistinctSecrets_AreEachFetchedOnce()
    {
        // Arrange
        var resolver = new CountingSecretResolver
        {
            [SecretUri] = "p@ssw0rd",
            [OtherUri] = "sa"
        };

        var builder = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Db"] = $"User Id={OtherReference};Password={Reference}"
            });

        // Act
        builder.AddKeyVaultReferenceResolver(resolver);
        builder.Build();

        // Assert
        Assert.Equal(1, resolver.CallCount(SecretUri));
        Assert.Equal(1, resolver.CallCount(OtherUri));
        Assert.Equal(2, resolver.TotalCalls);
    }

    [Fact]
    public void ConfigurationValues_DoNotChangeWhenTheVaultDoes()
    {
        // Arrange
        var resolver = new CountingSecretResolver { [SecretUri] = "original" };

        var builder = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Password"] = Reference });
        builder.AddKeyVaultReferenceResolver(resolver);
        var config = builder.Build();

        Assert.Equal("original", config["Password"]);

        // Act - the secret is rotated after startup
        resolver[SecretUri] = "rotated";
        config.Reload();

        // Assert - resolution happened once, while the configuration was being built, and the
        // resolved value now lives in an in-memory source. Reload does not re-resolve it. This
        // is the documented rotation limitation; if it ever changes, this test should fail.
        Assert.Equal("original", config["Password"]);
        Assert.Equal(1, resolver.CallCount(SecretUri));
    }

    #endregion

    #region Resolver-level

    [Fact]
    public async Task SecondResolve_IsServedFromTheCache()
    {
        // Arrange
        using var resolver = new FakeVaultResolver(new KeyVaultReferenceResolverOptions());
        resolver[SecretUri] = "p@ssw0rd";

        // Act
        var first = await resolver.ResolveSecretAsync(SecretUri, TestContext.Current.CancellationToken);
        var second = await resolver.ResolveSecretAsync(SecretUri, TestContext.Current.CancellationToken);

        // Assert
        Assert.Equal("p@ssw0rd", first);
        Assert.Equal("p@ssw0rd", second);
        Assert.Equal(1, resolver.FetchCount(SecretUri));
    }

    [Fact]
    public async Task CachingDisabled_RefetchesEveryTime()
    {
        // Arrange
        using var resolver = new FakeVaultResolver(new KeyVaultReferenceResolverOptions
        {
            EnableCaching = false
        });
        resolver[SecretUri] = "p@ssw0rd";

        // Act
        await resolver.ResolveSecretAsync(SecretUri, TestContext.Current.CancellationToken);
        await resolver.ResolveSecretAsync(SecretUri, TestContext.Current.CancellationToken);

        // Assert
        Assert.Equal(2, resolver.FetchCount(SecretUri));
    }

    [Fact]
    public async Task DefaultCacheTtl_NeverExpiresOnItsOwn()
    {
        // Arrange - the default is Timeout.InfiniteTimeSpan
        using var resolver = new FakeVaultResolver(new KeyVaultReferenceResolverOptions());
        resolver[SecretUri] = "original";

        await resolver.ResolveSecretAsync(SecretUri, TestContext.Current.CancellationToken);

        // Act - rotate, wait, resolve again
        resolver[SecretUri] = "rotated";
        await Task.Delay(TimeSpan.FromMilliseconds(120), TestContext.Current.CancellationToken);
        var afterWaiting = await resolver.ResolveSecretAsync(SecretUri, TestContext.Current.CancellationToken);

        // Assert - no polling: the cached value stands until it is explicitly refreshed
        Assert.Equal("original", afterWaiting);
        Assert.Equal(1, resolver.FetchCount(SecretUri));
    }

    [Fact]
    public async Task FiniteCacheTtl_ExpiresAndRefetches()
    {
        // Arrange
        using var resolver = new FakeVaultResolver(new KeyVaultReferenceResolverOptions
        {
            CacheTtl = TimeSpan.FromMilliseconds(50)
        });
        resolver[SecretUri] = "original";

        await resolver.ResolveSecretAsync(SecretUri, TestContext.Current.CancellationToken);

        // Act
        resolver[SecretUri] = "rotated";
        await Task.Delay(TimeSpan.FromMilliseconds(150), TestContext.Current.CancellationToken);
        var afterExpiry = await resolver.ResolveSecretAsync(SecretUri, TestContext.Current.CancellationToken);

        // Assert - a finite TTL still works for callers who want time-based expiry
        Assert.Equal("rotated", afterExpiry);
        Assert.Equal(2, resolver.FetchCount(SecretUri));
    }

    [Fact]
    public async Task ForceRefresh_BypassesTheCacheAndPicksUpTheNewValue()
    {
        // Arrange
        using var resolver = new FakeVaultResolver(new KeyVaultReferenceResolverOptions());
        resolver[SecretUri] = "original";

        Assert.Equal("original", await resolver.ResolveSecretAsync(SecretUri, TestContext.Current.CancellationToken));

        // Act - the secret rotates, then the caller refreshes on demand
        resolver[SecretUri] = "rotated";
        var cached = await resolver.ResolveSecretAsync(SecretUri, TestContext.Current.CancellationToken);
        var refreshed = await resolver.ResolveSecretAsync(SecretUri, forceRefresh: true, TestContext.Current.CancellationToken);

        // Assert
        Assert.Equal("original", cached);
        Assert.Equal("rotated", refreshed);
        Assert.Equal(2, resolver.FetchCount(SecretUri));
    }

    [Fact]
    public async Task ForceRefresh_ReplacesTheCachedValue()
    {
        // Arrange
        using var resolver = new FakeVaultResolver(new KeyVaultReferenceResolverOptions());
        resolver[SecretUri] = "original";

        await resolver.ResolveSecretAsync(SecretUri, TestContext.Current.CancellationToken);
        resolver[SecretUri] = "rotated";
        await resolver.ResolveSecretAsync(SecretUri, forceRefresh: true, TestContext.Current.CancellationToken);

        // Act - a normal resolve after a forced refresh should serve the refreshed value
        var subsequent = await resolver.ResolveSecretAsync(SecretUri, TestContext.Current.CancellationToken);

        // Assert
        Assert.Equal("rotated", subsequent);
        Assert.Equal(2, resolver.FetchCount(SecretUri));
    }

    [Fact]
    public async Task InvalidateCache_ForcesTheNextCallToGoToTheVault()
    {
        // Arrange
        using var resolver = new FakeVaultResolver(new KeyVaultReferenceResolverOptions());
        resolver[SecretUri] = "original";

        await resolver.ResolveSecretAsync(SecretUri, TestContext.Current.CancellationToken);

        // Act
        resolver[SecretUri] = "rotated";
        resolver.InvalidateCache(SecretUri);
        var afterInvalidate = await resolver.ResolveSecretAsync(SecretUri, TestContext.Current.CancellationToken);

        // Assert
        Assert.Equal("rotated", afterInvalidate);
        Assert.Equal(2, resolver.FetchCount(SecretUri));
    }

    [Fact]
    public async Task InvalidateCache_WithoutAUri_ClearsEverything()
    {
        // Arrange
        using var resolver = new FakeVaultResolver(new KeyVaultReferenceResolverOptions());
        resolver[SecretUri] = "one";
        resolver[OtherUri] = "two";

        await resolver.ResolveSecretAsync(SecretUri, TestContext.Current.CancellationToken);
        await resolver.ResolveSecretAsync(OtherUri, TestContext.Current.CancellationToken);

        // Act
        resolver.InvalidateCache();
        await resolver.ResolveSecretAsync(SecretUri, TestContext.Current.CancellationToken);
        await resolver.ResolveSecretAsync(OtherUri, TestContext.Current.CancellationToken);

        // Assert
        Assert.Equal(2, resolver.FetchCount(SecretUri));
        Assert.Equal(2, resolver.FetchCount(OtherUri));
    }

    [Fact]
    public async Task InvalidateCache_OneUri_LeavesOthersCached()
    {
        // Arrange
        using var resolver = new FakeVaultResolver(new KeyVaultReferenceResolverOptions());
        resolver[SecretUri] = "one";
        resolver[OtherUri] = "two";

        await resolver.ResolveSecretAsync(SecretUri, TestContext.Current.CancellationToken);
        await resolver.ResolveSecretAsync(OtherUri, TestContext.Current.CancellationToken);

        // Act
        resolver.InvalidateCache(SecretUri);
        await resolver.ResolveSecretAsync(SecretUri, TestContext.Current.CancellationToken);
        await resolver.ResolveSecretAsync(OtherUri, TestContext.Current.CancellationToken);

        // Assert
        Assert.Equal(2, resolver.FetchCount(SecretUri));
        Assert.Equal(1, resolver.FetchCount(OtherUri));
    }

    [Fact]
    public async Task Dispose_DropsCachedValues()
    {
        // Arrange
        var resolver = new FakeVaultResolver(new KeyVaultReferenceResolverOptions());
        resolver[SecretUri] = "p@ssw0rd";

        await resolver.ResolveSecretAsync(SecretUri, TestContext.Current.CancellationToken);

        // Act
        resolver.Dispose();
        var afterDispose = await resolver.ResolveSecretAsync(SecretUri, TestContext.Current.CancellationToken);

        // Assert - the cache was cleared, so the value came from the vault again
        Assert.Equal("p@ssw0rd", afterDispose);
        Assert.Equal(2, resolver.FetchCount(SecretUri));
    }

    [Fact]
    public async Task ExpiredSecret_IsRejectedWhenConfigured()
    {
        // Arrange
        using var resolver = new FakeVaultResolver(new KeyVaultReferenceResolverOptions
        {
            RejectSecretsOutsideValidityPeriod = true
        });
        resolver[SecretUri] = "p@ssw0rd";
        resolver.ExpiresOn = DateTimeOffset.UtcNow.AddDays(-1);

        // Act
        var ex = await Assert.ThrowsAsync<KeyVaultReferenceResolutionException>(
            () => resolver.ResolveSecretAsync(SecretUri, TestContext.Current.CancellationToken));

        // Assert - the vault does not block reads of an expired secret, so this is the only
        // place the expiry can be enforced. The message must not name the secret.
        Assert.Contains("expired", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("db-password", ex.Message);
    }

    [Fact]
    public async Task ExpiredSecret_IsUsedByDefault()
    {
        // Arrange - the default is to warn and carry on
        using var resolver = new FakeVaultResolver(new KeyVaultReferenceResolverOptions());
        resolver[SecretUri] = "p@ssw0rd";
        resolver.ExpiresOn = DateTimeOffset.UtcNow.AddDays(-1);

        // Act
        var value = await resolver.ResolveSecretAsync(SecretUri, TestContext.Current.CancellationToken);

        // Assert
        Assert.Equal("p@ssw0rd", value);
    }

    [Fact]
    public async Task SecretNotYetValid_IsRejectedWhenConfigured()
    {
        // Arrange
        using var resolver = new FakeVaultResolver(new KeyVaultReferenceResolverOptions
        {
            RejectSecretsOutsideValidityPeriod = true
        });
        resolver[SecretUri] = "p@ssw0rd";
        resolver.NotBefore = DateTimeOffset.UtcNow.AddDays(1);

        // Act
        var ex = await Assert.ThrowsAsync<KeyVaultReferenceResolutionException>(
            () => resolver.ResolveSecretAsync(SecretUri, TestContext.Current.CancellationToken));

        // Assert
        Assert.Contains("not valid until", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    #endregion

    /// <summary>
    /// The real resolver with only the network call replaced, so the caching, TTL, refresh and
    /// validity-period logic under test is the shipping implementation.
    /// </summary>
    private sealed class FakeVaultResolver : KeyVaultSecretResolver
    {
        private readonly ConcurrentDictionary<string, string> _secrets = new();
        private readonly ConcurrentDictionary<string, int> _fetches = new();

        public FakeVaultResolver(KeyVaultReferenceResolverOptions options)
            // A credential is supplied so the constructor does not build a DefaultAzureCredential
            // and probe the environment; it is never used, because FetchSecretAsync is overridden.
            : base(Configure(options))
        {
        }

        public DateTimeOffset? ExpiresOn { get; set; }

        public DateTimeOffset? NotBefore { get; set; }

        public string this[string uri]
        {
            set => _secrets[uri] = value;
        }

        public int FetchCount(string uri) => _fetches.TryGetValue(uri, out var count) ? count : 0;

        protected override Task<KeyVaultSecret> FetchSecretAsync(
            Uri vaultUri,
            string secretName,
            string? version,
            CancellationToken cancellationToken)
        {
            var uri = $"{vaultUri.Scheme}://{vaultUri.Host}/secrets/{secretName}";
            _fetches.AddOrUpdate(uri, 1, (_, existing) => existing + 1);

            if (!_secrets.TryGetValue(uri, out var value))
                throw new KeyNotFoundException($"No fake secret configured for {secretName}.");

            var secret = new KeyVaultSecret(secretName, value);
            secret.Properties.ExpiresOn = ExpiresOn;
            secret.Properties.NotBefore = NotBefore;

            return Task.FromResult(secret);
        }

        private static KeyVaultReferenceResolverOptions Configure(KeyVaultReferenceResolverOptions options)
        {
            options.Credential = new StubCredential();
            return options;
        }
    }

    /// <summary>
    /// A credential that is never asked for a token, but keeps the resolver's constructor from
    /// building a DefaultAzureCredential and probing the host during tests.
    /// </summary>
    private sealed class StubCredential : Azure.Core.TokenCredential
    {
        public override Azure.Core.AccessToken GetToken(
            Azure.Core.TokenRequestContext requestContext, CancellationToken cancellationToken)
            => throw new NotSupportedException("The fake resolver never performs a network call.");

        public override ValueTask<Azure.Core.AccessToken> GetTokenAsync(
            Azure.Core.TokenRequestContext requestContext, CancellationToken cancellationToken)
            => throw new NotSupportedException("The fake resolver never performs a network call.");
    }

    /// <summary>
    /// An <see cref="ISecretResolver"/> that records how many times each URI was requested.
    /// </summary>
    private sealed class CountingSecretResolver : ISecretResolver
    {
        private readonly ConcurrentDictionary<string, string> _secrets = new();
        private readonly ConcurrentDictionary<string, int> _calls = new();

        public string this[string uri]
        {
            set => _secrets[uri] = value;
        }

        public int TotalCalls
        {
            get
            {
                var total = 0;
                foreach (var entry in _calls)
                    total += entry.Value;
                return total;
            }
        }

        public int CallCount(string uri) => _calls.TryGetValue(uri, out var count) ? count : 0;

        public string ResolveSecret(string secretUri)
        {
            _calls.AddOrUpdate(secretUri, 1, (_, existing) => existing + 1);
            return _secrets.TryGetValue(secretUri, out var value)
                ? value
                : throw new KeyNotFoundException("Secret not found.");
        }

        public Task<string> ResolveSecretAsync(string secretUri, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(ResolveSecret(secretUri));
        }
    }
}
