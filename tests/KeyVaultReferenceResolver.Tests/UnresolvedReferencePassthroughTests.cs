using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Xunit;
using KeyVaultReferenceResolver.Testing;

namespace KeyVaultReferenceResolver.Tests;

/// <summary>
/// Covers what happens to a reference the resolver never saw.
/// </summary>
/// <remarks>
/// Resolution is a single sweep performed while the configuration is built. Anything registered
/// after the resolver wins over the values it produced and is itself never resolved, so the
/// application reads the literal <c>@Microsoft.KeyVault(...)</c> string and uses it as a
/// credential - the one outcome the fail-closed behaviour elsewhere exists to prevent.
/// </remarks>
public class UnresolvedReferencePassthroughTests
{
    private const string Uri = "https://myvault.vault.azure.net/secrets/db-password";
    private const string Reference = "@Microsoft.KeyVault(SecretUri=https://myvault.vault.azure.net/secrets/db-password)";

    [Fact]
    public void SourceRegisteredAfterTheResolver_IsReported()
    {
        var logger = new RecordingLogger();

        var builder = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Db:Password"] = Reference });

        builder.AddKeyVaultReferenceResolver(Resolver(), options: null, logger: logger);

        // The footgun: a source added here overrides the resolved secret and is never resolved.
        builder.AddInMemoryCollection(new Dictionary<string, string?> { ["Db:Password"] = Reference });
        builder.Build();

        var error = Assert.Single(logger.Entries, e => e.EventId == LogEvents.ResolverNotLastSource);
        Assert.Equal(LogLevel.Error, error.Level);
    }

    [Fact]
    public void ResolverRegisteredLast_IsNotReported()
    {
        var logger = new RecordingLogger();

        var builder = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Db:Password"] = Reference });

        builder.AddKeyVaultReferenceResolver(Resolver(), options: null, logger: logger);
        builder.Build();

        Assert.DoesNotContain(logger.Entries, e => e.EventId == LogEvents.ResolverNotLastSource);
    }

    [Fact]
    public void FindUnresolvedReferences_ReportsAKeyALaterSourceReintroduced()
    {
        var builder = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Db:Password"] = Reference });

        builder.AddKeyVaultReferenceResolver(Resolver());
        builder.AddInMemoryCollection(new Dictionary<string, string?> { ["Db:Password"] = Reference });

        var configuration = builder.Build();

        // Proof that the literal reference is what the application would read.
        Assert.Equal(Reference, configuration["Db:Password"]);
        Assert.Equal("Db:Password", Assert.Single(configuration.FindUnresolvedReferences()));
    }

    [Fact]
    public void FindUnresolvedReferences_ReportsAKeyOnlyALaterSourceHas()
    {
        var builder = new ConfigurationBuilder();
        builder.AddKeyVaultReferenceResolver(Resolver());
        builder.AddInMemoryCollection(new Dictionary<string, string?> { ["Added:Later"] = Reference });

        Assert.Equal("Added:Later", Assert.Single(builder.Build().FindUnresolvedReferences()));
    }

    [Fact]
    public void FindUnresolvedReferences_IsEmptyWhenEverythingResolved()
    {
        var builder = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Db:Password"] = Reference });

        builder.AddKeyVaultReferenceResolver(Resolver());
        var configuration = builder.Build();

        Assert.Equal("p@ssw0rd", configuration["Db:Password"]);
        Assert.Empty(configuration.FindUnresolvedReferences());
    }

    [Fact]
    public void FindUnresolvedReferences_IgnoresProseThatMerelyMentionsTheSyntax()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Docs:Hint"] = "Use @Microsoft.KeyVault to reference a secret."
            })
            .Build();

        Assert.Empty(configuration.FindUnresolvedReferences());
    }

    [Fact]
    public void AssertNoUnresolvedReferences_ThrowsNamingTheKey()
    {
        var builder = new ConfigurationBuilder();
        builder.AddKeyVaultReferenceResolver(Resolver());
        builder.AddInMemoryCollection(new Dictionary<string, string?> { ["Added:Later"] = Reference });

        var configuration = builder.Build();
        var logger = new RecordingLogger();

        var ex = Assert.Throws<KeyVaultReferenceResolutionException>(
            () => configuration.AssertNoUnresolvedReferences(logger));

        Assert.Contains("Added:Later", ex.Message, StringComparison.Ordinal);

        // The key is named, but the reference itself - which identifies the vault and secret - is not.
        Assert.DoesNotContain("myvault.vault.azure.net", ex.Message, StringComparison.Ordinal);
        Assert.Contains(logger.Entries, e => e.EventId == LogEvents.UnresolvedReference);
    }

    [Fact]
    public void AssertNoUnresolvedReferences_PassesOnACleanConfiguration()
    {
        var builder = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Db:Password"] = Reference });

        builder.AddKeyVaultReferenceResolver(Resolver());

        builder.Build().AssertNoUnresolvedReferences();
    }

    /// <summary>
    /// A failed resolution stores null, which must still shadow the literal reference underneath
    /// it rather than letting that reference reach the application.
    /// </summary>
    [Fact]
    public void FailedResolution_StillShadowsTheLiteralReference()
    {
        var builder = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Db:Password"] = Reference });

        builder.AddKeyVaultReferenceResolver(
            new FakeSecretResolver(),
            new KeyVaultReferenceResolverOptions { ThrowOnResolveFailure = false });

        var configuration = builder.Build();

        Assert.Null(configuration["Db:Password"]);
        Assert.Empty(configuration.FindUnresolvedReferences());
    }

    private static FakeSecretResolver Resolver() => new FakeSecretResolver().AddSecret(Uri, "p@ssw0rd");

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
