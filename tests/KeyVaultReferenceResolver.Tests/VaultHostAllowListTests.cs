using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Azure.Security.KeyVault.Secrets;
using Xunit;

namespace KeyVaultReferenceResolver.Tests;

/// <summary>
/// Covers which vault hosts the resolver is willing to contact.
/// </summary>
/// <remarks>
/// A reference is a configuration value, so the host in it is chosen by whoever can influence
/// configuration. Whatever host is named receives a token for this application's identity, and a
/// host that merely ends in <c>.vault.azure.net</c> can belong to anyone - so "is a Key Vault" and
/// "is our Key Vault" are different checks, and only the second is worth much.
/// </remarks>
public class VaultHostAllowListTests
{
    private const string Ours = "contoso-prod.vault.azure.net";
    private const string Theirs = "attacker.vault.azure.net";

    /// <summary>
    /// The lookalike: anyone can create <c>evilcontoso</c>, and an unanchored EndsWith on the
    /// suffix entry <c>contoso.vault.azure.net</c> accepts it.
    /// </summary>
    [Theory]
    [InlineData("evilcontoso-prod.vault.azure.net")]
    [InlineData("xcontoso-prod.vault.azure.net")]
    public async Task SuffixEntry_DoesNotMatchInsideALabel(string lookalike)
    {
        var resolver = Resolver(options => options.AllowedVaultHostSuffixes = new List<string> { Ours });

        await AssertRejectedAsync(resolver, lookalike);
    }

    [Theory]
    [InlineData("vault.azure.net", "contoso-prod.vault.azure.net")]
    [InlineData(".vault.azure.net", "contoso-prod.vault.azure.net")]
    [InlineData("contoso-prod.vault.azure.net", "contoso-prod.vault.azure.net")]
    public void MatchesHostSuffix_AcceptsWholeHostAndLabelBoundary(string suffix, string host)
    {
        Assert.True(KeyVaultSecretResolver.MatchesHostSuffix(host, suffix));
    }

    [Theory]
    [InlineData("vault.azure.net", "notvault.azure.net")]
    [InlineData(".vault.azure.net", "evil-vault.azure.net")]
    [InlineData("contoso.vault.azure.net", "evilcontoso.vault.azure.net")]
    [InlineData("vault.azure.net", "vault.azure.net.attacker.tld")]
    public void MatchesHostSuffix_RejectsPartialLabelAndPrefixMatches(string suffix, string host)
    {
        Assert.False(KeyVaultSecretResolver.MatchesHostSuffix(host, suffix));
    }

    /// <summary>
    /// The default suffix list establishes that a host is a Key Vault, not whose it is. This is
    /// the gap AllowedVaultHosts exists to close.
    /// </summary>
    [Fact]
    public async Task DefaultSuffixes_AcceptAnyAzureVaultIncludingSomeoneElses()
    {
        var resolver = Resolver(_ => { });

        await resolver.ResolveSecretAsync(Uri(Theirs), TestContext.Current.CancellationToken);

        Assert.Equal(Theirs, resolver.LastHost);
    }

    [Fact]
    public async Task AllowedVaultHosts_RejectsAnotherTenantsVault()
    {
        var resolver = Resolver(options => options.AllowedVaultHosts = new List<string> { Ours });

        var ex = await AssertRejectedAsync(resolver, Theirs);
        Assert.Contains(nameof(KeyVaultReferenceResolverOptions.AllowedVaultHosts), ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AllowedVaultHosts_RejectsALookalikeOfAListedHost()
    {
        var resolver = Resolver(options => options.AllowedVaultHosts = new List<string> { Ours });

        await AssertRejectedAsync(resolver, "contoso-prod.vault.azure.net.attacker.tld");
    }

    [Theory]
    [InlineData(Ours)]
    [InlineData("CONTOSO-PROD.vault.azure.net")]
    public async Task AllowedVaultHosts_AcceptsAListedHost(string host)
    {
        var resolver = Resolver(options => options.AllowedVaultHosts = new List<string> { Ours });

        await resolver.ResolveSecretAsync(Uri(host), TestContext.Current.CancellationToken);

        // Uri normalises the host to lower case, so the reference casing is not preserved here.
        Assert.Equal(Ours, resolver.LastHost);
    }

    /// <summary>
    /// A suffix entry must not be able to widen an exact-host list back out again.
    /// </summary>
    [Fact]
    public async Task AllowedVaultHosts_TakesPrecedenceOverSuffixes()
    {
        var resolver = Resolver(options =>
        {
            options.AllowedVaultHosts = new List<string> { Ours };
            options.AllowedVaultHostSuffixes = new List<string> { ".vault.azure.net" };
        });

        await AssertRejectedAsync(resolver, Theirs);
    }

    [Fact]
    public async Task EmptyLists_DisableTheCheckEntirely()
    {
        var resolver = Resolver(options =>
        {
            options.AllowedVaultHosts = new List<string>();
            options.AllowedVaultHostSuffixes = new List<string>();
        });

        await resolver.ResolveSecretAsync(Uri("vault.internal.contoso.tld"), TestContext.Current.CancellationToken);

        Assert.Equal("vault.internal.contoso.tld", resolver.LastHost);
    }

    [Fact]
    public async Task NonVaultHost_IsRejectedByDefault()
    {
        var resolver = Resolver(_ => { });

        await AssertRejectedAsync(resolver, "attacker.tld");
    }

    private static async Task<ArgumentException> AssertRejectedAsync(RecordingVaultResolver resolver, string host)
    {
        var ex = await Assert.ThrowsAsync<ArgumentException>(
            () => resolver.ResolveSecretAsync(Uri(host), TestContext.Current.CancellationToken));

        // The point of rejecting is that nothing was sent, so a message alone is not enough.
        Assert.Null(resolver.LastHost);
        return ex;
    }

    private static string Uri(string host) => $"https://{host}/secrets/db-password";

    private static RecordingVaultResolver Resolver(Action<KeyVaultReferenceResolverOptions> configure)
    {
        var options = new KeyVaultReferenceResolverOptions();
        configure(options);
        return new RecordingVaultResolver(options);
    }

    /// <summary>
    /// Records the host a fetch was attempted against, so a test can assert that a rejected
    /// reference produced no request at all rather than a request that happened to fail.
    /// </summary>
    private sealed class RecordingVaultResolver : KeyVaultSecretResolver
    {
        private readonly ConcurrentQueue<string> _hosts = new();

        public RecordingVaultResolver(KeyVaultReferenceResolverOptions options)
            // A credential is supplied so the constructor does not build a DefaultAzureCredential
            // and probe the environment; it is never used, because FetchSecretAsync is overridden.
            : base(Configure(options))
        {
        }

        public string? LastHost => _hosts.TryPeek(out var host) ? host : null;

        protected override Task<KeyVaultSecret> FetchSecretAsync(
            Uri vaultUri,
            string secretName,
            string? version,
            CancellationToken cancellationToken)
        {
            _hosts.Enqueue(vaultUri.Host);
            return Task.FromResult(new KeyVaultSecret(secretName, "value"));
        }

        private static KeyVaultReferenceResolverOptions Configure(KeyVaultReferenceResolverOptions options)
        {
            options.Credential = new StubCredential();
            return options;
        }
    }

    private sealed class StubCredential : Azure.Core.TokenCredential
    {
        public override Azure.Core.AccessToken GetToken(Azure.Core.TokenRequestContext requestContext, CancellationToken cancellationToken) =>
            throw new NotSupportedException("FetchSecretAsync is overridden; no token is ever requested.");

        public override ValueTask<Azure.Core.AccessToken> GetTokenAsync(Azure.Core.TokenRequestContext requestContext, CancellationToken cancellationToken) =>
            throw new NotSupportedException("FetchSecretAsync is overridden; no token is ever requested.");
    }
}
