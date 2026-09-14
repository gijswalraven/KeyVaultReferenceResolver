using System;
using System.Threading;
using System.Threading.Tasks;
using Azure.Security.KeyVault.Secrets;
using Xunit;

namespace KeyVaultReferenceResolver.Tests;

/// <summary>
/// Covers what is accepted as a secret name or version in a reference.
/// </summary>
/// <remarks>
/// The name is taken from a configuration value and handed to the Key Vault SDK, which puts it
/// into a request path. Parsing used to call <c>Uri.UnescapeDataString</c> on a path that
/// <c>Uri</c> had already partially decoded, so a doubly-escaped traversal such as
/// <c>%252e%252e%252f</c> became <c>../</c>. Azure.Core re-escapes the segment, so nothing was
/// exploitable - but a credential store should not depend on a dependency to undo its own
/// decoding. Key Vault names are alphanumerics and hyphens, so anything else is rejected.
/// </remarks>
public class SecretNameValidationTests
{
    [Theory]
    [InlineData("%252e%252e%252fsys%252fmounts")]
    [InlineData("%2e%2e%2f")]
    [InlineData("name%00")]
    [InlineData("name with spaces")]
    [InlineData("name_underscore")]
    [InlineData("name.dot")]
    public async Task SecretName_OutsideKeyVaultsNamingRules_IsRejected(string name)
    {
        var resolver = new NoNetworkResolver();

        var ex = await Assert.ThrowsAsync<ArgumentException>(
            () => resolver.ResolveSecretAsync(
                $"https://myvault.vault.azure.net/secrets/{name}",
                TestContext.Current.CancellationToken));

        Assert.Contains("alphanumerics and hyphens", ex.Message, StringComparison.Ordinal);

        // Nothing was sent, and the message does not echo the rejected name back.
        Assert.Null(resolver.LastSecretName);
        Assert.DoesNotContain(name, ex.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// Uri collapses dot segments during canonicalisation, so these never reach the name check -
    /// the path is left with no name at all and the format check rejects it first. Either way
    /// nothing is sent, which is what matters.
    /// </summary>
    [Theory]
    [InlineData(".")]
    [InlineData("..")]
    public async Task DotSegments_AreRejectedByTheFormatCheck(string name)
    {
        var resolver = new NoNetworkResolver();

        var ex = await Assert.ThrowsAsync<ArgumentException>(
            () => resolver.ResolveSecretAsync(
                $"https://myvault.vault.azure.net/secrets/{name}",
                TestContext.Current.CancellationToken));

        Assert.Contains("Invalid Key Vault secret URI format", ex.Message, StringComparison.Ordinal);
        Assert.Null(resolver.LastSecretName);
    }

    [Theory]
    [InlineData("db-password")]
    [InlineData("DbPassword")]
    [InlineData("secret123")]
    public async Task SecretName_WithinKeyVaultsNamingRules_IsAccepted(string name)
    {
        var resolver = new NoNetworkResolver();

        await resolver.ResolveSecretAsync(
            $"https://myvault.vault.azure.net/secrets/{name}",
            TestContext.Current.CancellationToken);

        Assert.Equal(name, resolver.LastSecretName);
    }

    [Fact]
    public async Task SecretVersion_OutsideTheNamingRules_IsRejected()
    {
        var resolver = new NoNetworkResolver();

        await Assert.ThrowsAsync<ArgumentException>(
            () => resolver.ResolveSecretAsync(
                "https://myvault.vault.azure.net/secrets/db-password/%252e%252e",
                TestContext.Current.CancellationToken));

        Assert.Null(resolver.LastSecretName);
    }

    [Fact]
    public async Task SecretVersion_Hexadecimal_IsAccepted()
    {
        var resolver = new NoNetworkResolver();

        await resolver.ResolveSecretAsync(
            "https://myvault.vault.azure.net/secrets/db-password/4387e9f3d6e14c459867679a90fd0f79",
            TestContext.Current.CancellationToken);

        Assert.Equal("4387e9f3d6e14c459867679a90fd0f79", resolver.LastVersion);
    }

    private sealed class NoNetworkResolver : KeyVaultSecretResolver
    {
        public NoNetworkResolver()
            : base(new KeyVaultReferenceResolverOptions { Credential = new Azure.Identity.DefaultAzureCredential() })
        {
        }

        public string? LastSecretName { get; private set; }

        public string? LastVersion { get; private set; }

        protected override Task<KeyVaultSecret> FetchSecretAsync(
            Uri vaultUri,
            string secretName,
            string? version,
            CancellationToken cancellationToken)
        {
            LastSecretName = secretName;
            LastVersion = version;
            return Task.FromResult(new KeyVaultSecret(secretName, "value"));
        }
    }
}
