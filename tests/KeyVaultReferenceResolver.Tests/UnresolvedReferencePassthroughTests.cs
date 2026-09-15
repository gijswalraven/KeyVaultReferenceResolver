using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using KeyVaultReferenceResolver.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Xunit;

namespace KeyVaultReferenceResolver.Tests;

/// <summary>
/// Covers what happens to a reference the resolver never saw.
/// </summary>
/// <remarks>
/// Resolution is a single sweep performed while the configuration is built. Anything registered
/// after the resolver wins over the values it produced and is itself never resolved, so the
/// application reads the literal <c>@Microsoft.KeyVault(...)</c> string and uses it as a
/// credential. In 1.4.x this was logged at Error; from 2.0 it fails the build, because a
/// credential that is silently a placeholder fails somewhere far away from its cause.
/// </remarks>
public class UnresolvedReferencePassthroughTests
{
    private const string Uri = "https://myvault.vault.azure.net/secrets/db-password";
    private const string Reference = "@Microsoft.KeyVault(SecretUri=https://myvault.vault.azure.net/secrets/db-password)";

    [Fact]
    public void LaterSourceCarryingAReference_FailsTheBuild()
    {
        var builder = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Db:Password"] = Reference });

        builder.AddKeyVaultReferenceResolver(Resolver());
        builder.AddInMemoryCollection(new Dictionary<string, string?> { ["Db:Password"] = Reference });

        var ex = Assert.Throws<KeyVaultReferenceResolutionException>(() => builder.Build());

        Assert.Contains("Db:Password", ex.Message, StringComparison.Ordinal);

        // The key is named; the reference, which identifies the vault and secret, is not.
        Assert.DoesNotContain("myvault.vault.azure.net", ex.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// The case that used to slip through entirely: with no references present at registration the
    /// resolver returned early and registered nothing, so nothing was left to notice the reference
    /// that arrived afterwards.
    /// </summary>
    [Fact]
    public void LaterSourceIsTheOnlySourceWithAReference_StillFailsTheBuild()
    {
        var builder = new ConfigurationBuilder();
        builder.AddKeyVaultReferenceResolver(Resolver());
        builder.AddInMemoryCollection(new Dictionary<string, string?> { ["Added:Later"] = Reference });

        var ex = Assert.Throws<KeyVaultReferenceResolutionException>(() => builder.Build());
        Assert.Contains("Added:Later", ex.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// Only a later <i>reference</i> is an error. Registering AddCommandLine or
    /// AddEnvironmentVariables last is both common and correct, and overriding a resolved secret
    /// with a literal value is legitimate for a test or a local run.
    /// </summary>
    [Fact]
    public void LaterSourceWithoutAReference_IsAllowedAndStillOverrides()
    {
        var builder = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Db:Password"] = Reference });

        builder.AddKeyVaultReferenceResolver(Resolver());
        builder.AddInMemoryCollection(new Dictionary<string, string?> { ["Db:Password"] = "local-override" });

        Assert.Equal("local-override", builder.Build()["Db:Password"]);
    }

    [Fact]
    public void ResolverRegisteredLast_Resolves()
    {
        var builder = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Db:Password"] = Reference });

        builder.AddKeyVaultReferenceResolver(Resolver());

        Assert.Equal("p@ssw0rd", builder.Build()["Db:Password"]);
    }

    [Fact]
    public void FindUnresolvedReferences_ReportsAReferenceLeftInAConfiguration()
    {
        // Built without the resolver, so nothing had the chance to fail the build. This is the
        // check for a configuration assembled somewhere the resolver was never registered.
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Db:Password"] = Reference })
            .Build();

        Assert.Equal("Db:Password", Assert.Single(configuration.FindUnresolvedReferences()));
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
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Added:Later"] = Reference })
            .Build();

        var logger = new RecordingLogger();

        var ex = Assert.Throws<KeyVaultReferenceResolutionException>(
            () => configuration.AssertNoUnresolvedReferences(logger));

        Assert.Contains("Added:Later", ex.Message, StringComparison.Ordinal);
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
