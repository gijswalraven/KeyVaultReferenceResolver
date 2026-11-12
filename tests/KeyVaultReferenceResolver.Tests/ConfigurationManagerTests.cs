using System.Collections.Generic;
using Microsoft.Extensions.Configuration;
using Xunit;
using KeyVaultReferenceResolver.Testing;

namespace KeyVaultReferenceResolver.Tests;

/// <summary>
/// Resolution against <see cref="ConfigurationManager"/>, which is what
/// <c>Host.CreateApplicationBuilder().Configuration</c> and
/// <c>WebApplication.CreateBuilder().Configuration</c> are.
/// </summary>
/// <remarks>
/// ConfigurationManager implements <see cref="IConfigurationBuilder"/> and
/// <see cref="IConfigurationRoot"/> at once, and its <c>Build()</c> returns <i>itself</i> rather
/// than a new root. The library builds the configuration once to discover which keys hold
/// references, and disposes that temporary root to avoid leaking a FileSystemWatcher per
/// reloading file source. Doing so unconditionally disposed the caller's own configuration, and
/// every later call - including the library's own - then threw ObjectDisposedException.
/// </remarks>
public class ConfigurationManagerTests
{
    private const string SecretUri = "https://myvault.vault.azure.net/secrets/my-secret";
    private const string Reference = "@Microsoft.KeyVault(SecretUri=https://myvault.vault.azure.net/secrets/my-secret)";
    private const string SecretValue = "super-secret-value";

    private static FakeSecretResolver Resolver() =>
        new(new Dictionary<string, string> { [SecretUri] = SecretValue });

    private static ConfigurationManager ManagerWith(params (string Key, string Value)[] values)
    {
        var manager = new ConfigurationManager();
        var pairs = new Dictionary<string, string?>();
        foreach (var (key, value) in values)
            pairs[key] = value;

        ((IConfigurationBuilder)manager).AddInMemoryCollection(pairs);
        return manager;
    }

    [Fact]
    public void AddKeyVaultReferenceResolver_OnConfigurationManager_DoesNotThrow()
    {
        var manager = ManagerWith(("Database:Password", Reference));

        // Before the fix this threw ObjectDisposedException: 'ConfigurationManager'.
        ((IConfigurationBuilder)manager).AddKeyVaultReferenceResolver(Resolver());

        Assert.Equal(SecretValue, manager["Database:Password"]);
    }

    [Fact]
    public void AddKeyVaultReferenceResolver_OnConfigurationManager_LeavesItUsable()
    {
        var manager = ManagerWith(("Database:Password", Reference), ("Plain", "literal"));

        ((IConfigurationBuilder)manager).AddKeyVaultReferenceResolver(Resolver());

        // Reading, enumerating and adding further sources all throw once the manager is disposed.
        Assert.Equal("literal", manager["Plain"]);
        Assert.NotEmpty(manager.AsEnumerable());

        ((IConfigurationBuilder)manager).AddInMemoryCollection(
            new Dictionary<string, string?> { ["Added:Later"] = "value" });

        Assert.Equal("value", manager["Added:Later"]);
        Assert.Equal(SecretValue, manager["Database:Password"]);
    }

    [Fact]
    public void AddKeyVaultReferenceResolver_OnConfigurationManager_WithNoReferences_LeavesItUsable()
    {
        var manager = ManagerWith(("Plain", "literal"));

        ((IConfigurationBuilder)manager).AddKeyVaultReferenceResolver(Resolver());

        Assert.Equal("literal", manager["Plain"]);
    }

    [Fact]
    public void AddKeyVaultReferenceResolver_OnPlainBuilder_StillDisposesItsTemporaryRoot()
    {
        // The conditional guard must not cost the FileSystemWatcher leak fix: a plain
        // ConfigurationBuilder does hand back a separate root, and that one still has to go.
        var source = new DisposalTrackingSource("Database:Password", Reference);
        var builder = new ConfigurationBuilder();
        builder.Add(source);

        builder.AddKeyVaultReferenceResolver(Resolver());

        Assert.True(source.LastProvider!.Disposed, "the temporary root's providers were not disposed");
    }

    private sealed class DisposalTrackingSource : IConfigurationSource
    {
        private readonly string _key;
        private readonly string _value;

        public DisposalTrackingSource(string key, string value)
        {
            _key = key;
            _value = value;
        }

        public TrackingProvider? LastProvider { get; private set; }

        public IConfigurationProvider Build(IConfigurationBuilder builder)
        {
            LastProvider = new TrackingProvider(_key, _value);
            return LastProvider;
        }
    }

    private sealed class TrackingProvider : ConfigurationProvider, IDisposable
    {
        public TrackingProvider(string key, string value)
        {
            Data = new Dictionary<string, string?> { [key] = value };
        }

        public bool Disposed { get; private set; }

        public void Dispose() => Disposed = true;
    }
}
