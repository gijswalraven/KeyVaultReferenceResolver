using System;
using System.Collections.Generic;
using System.Linq;
using Azure.Security.KeyVault.Secrets;
using Xunit;

namespace KeyVaultReferenceResolver.Tests;

/// <summary>
/// Pins the parts of the credential chain and the client options that decide which identities
/// can be used and where a token may be sent.
/// </summary>
/// <remarks>
/// None of this is observable once <c>DefaultAzureCredential</c> and <c>SecretClient</c> are
/// constructed, so these assert on the option objects the resolver builds. That is the only way
/// to cover them without a live vault.
/// </remarks>
public class CredentialHardeningTests
{
    private static readonly string[] ExpectedTenants = { "tenant-a", "tenant-b" };

    [Fact]
    public void DeveloperCredentials_AreExcludedByDefault()
    {
        var credentialOptions = KeyVaultSecretResolver.BuildCredentialOptions(new KeyVaultReferenceResolverOptions());

        Assert.True(credentialOptions.ExcludeAzureCliCredential);
        Assert.True(credentialOptions.ExcludeAzureDeveloperCliCredential);
        Assert.True(credentialOptions.ExcludeVisualStudioCredential);
        Assert.True(credentialOptions.ExcludeAzurePowerShellCredential);
    }

    [Fact]
    public void InteractiveBrowserCredential_IsAlwaysExcluded()
    {
        var options = new KeyVaultReferenceResolverOptions { AllowDeveloperCredentials = true };

        Assert.True(KeyVaultSecretResolver.BuildCredentialOptions(options).ExcludeInteractiveBrowserCredential);
    }

    /// <summary>
    /// null leaves the Azure Identity default alone, so AZURE_ADDITIONALLY_ALLOWED_TENANTS keeps
    /// working for callers who rely on it.
    /// </summary>
    [Fact]
    public void AdditionallyAllowedTenants_Unset_LeavesTheSdkDefault()
    {
        var options = new KeyVaultReferenceResolverOptions();
        Assert.Null(options.AdditionallyAllowedTenants);

        var credentialOptions = KeyVaultSecretResolver.BuildCredentialOptions(options);

        Assert.Empty(credentialOptions.AdditionallyAllowedTenants);
    }

    [Fact]
    public void AdditionallyAllowedTenants_EmptyList_PinsToASingleTenant()
    {
        var options = new KeyVaultReferenceResolverOptions
        {
            TenantId = "00000000-0000-0000-0000-000000000001",
            AdditionallyAllowedTenants = new List<string>()
        };

        var credentialOptions = KeyVaultSecretResolver.BuildCredentialOptions(options);

        Assert.Empty(credentialOptions.AdditionallyAllowedTenants);
        Assert.Equal("00000000-0000-0000-0000-000000000001", credentialOptions.TenantId);
    }

    [Fact]
    public void AdditionallyAllowedTenants_Populated_IsPassedThrough()
    {
        var options = new KeyVaultReferenceResolverOptions
        {
            AdditionallyAllowedTenants = new List<string> { "tenant-a", "tenant-b" }
        };

        var credentialOptions = KeyVaultSecretResolver.BuildCredentialOptions(options);

        Assert.Equal(ExpectedTenants, credentialOptions.AdditionallyAllowedTenants.ToArray());
    }

    /// <summary>
    /// A caller-supplied SecretClientOptions must not be able to switch off the two protections
    /// this library forces on: secret payloads in the log, and challenge-driven token redirection.
    /// </summary>
    [Fact]
    public void CallerSuppliedClientOptions_CannotDisableTheForcedProtections()
    {
        var supplied = new SecretClientOptions
        {
            DisableChallengeResourceVerification = true
        };
        supplied.Diagnostics.IsLoggingContentEnabled = true;

        using var resolver = new KeyVaultSecretResolver(new KeyVaultReferenceResolverOptions
        {
            Credential = new Azure.Identity.DefaultAzureCredential(),
            ClientOptions = supplied
        });

        var effective = resolver.BuildClientOptions();

        Assert.False(effective.DisableChallengeResourceVerification);
        Assert.False(effective.Diagnostics.IsLoggingContentEnabled);
    }

    [Fact]
    public void DefaultClientOptions_KeepChallengeVerificationOn()
    {
        using var resolver = new KeyVaultSecretResolver(new KeyVaultReferenceResolverOptions
        {
            Credential = new Azure.Identity.DefaultAzureCredential()
        });

        Assert.False(resolver.BuildClientOptions().DisableChallengeResourceVerification);
    }
}
