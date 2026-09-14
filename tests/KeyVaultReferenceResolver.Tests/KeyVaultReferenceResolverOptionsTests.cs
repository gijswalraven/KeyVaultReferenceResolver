using System;
using Azure.Identity;
using Xunit;

namespace KeyVaultReferenceResolver.Tests;

public class KeyVaultReferenceResolverOptionsTests
{
    [Fact]
    public void DefaultValues_Credential_IsNull()
    {
        // Arrange & Act
        var options = new KeyVaultReferenceResolverOptions();

        // Assert
        Assert.Null(options.Credential);
    }

    [Fact]
    public void DefaultValues_ThrowOnResolveFailure_IsTrue()
    {
        // Arrange & Act
        var options = new KeyVaultReferenceResolverOptions();

        // Assert
        Assert.True(options.ThrowOnResolveFailure);
    }

    [Fact]
    public void DefaultValues_Timeout_Is30Seconds()
    {
        // Arrange & Act
        var options = new KeyVaultReferenceResolverOptions();

        // Assert
        Assert.Equal(TimeSpan.FromSeconds(30), options.Timeout);
    }

    [Fact]
    public void DefaultValues_EnableCaching_IsTrue()
    {
        // Arrange & Act
        var options = new KeyVaultReferenceResolverOptions();

        // Assert
        Assert.True(options.EnableCaching);
    }

    [Fact]
    public void Properties_CanBeSet()
    {
        // Arrange
        var options = new KeyVaultReferenceResolverOptions();
        var credential = new DefaultAzureCredential();
        var timeout = TimeSpan.FromMinutes(5);

        // Act
        options.Credential = credential;
        options.ThrowOnResolveFailure = false;
        options.Timeout = timeout;
        options.EnableCaching = false;

        // Assert
        Assert.Same(credential, options.Credential);
        Assert.False(options.ThrowOnResolveFailure);
        Assert.Equal(timeout, options.Timeout);
        Assert.False(options.EnableCaching);
    }

    [Fact]
    public void DefaultValues_CacheTtl_IsInfinite()
    {
        // Arrange & Act
        var options = new KeyVaultReferenceResolverOptions();

        // Assert - secrets are cached until explicitly refreshed, not re-fetched on a timer
        Assert.Equal(System.Threading.Timeout.InfiniteTimeSpan, options.CacheTtl);
    }

    [Fact]
    public void DefaultValues_DeveloperCredentials_AreExcluded()
    {
        // Arrange & Act
        var options = new KeyVaultReferenceResolverOptions();

        // Assert - a process running in Azure must not fall back to a developer's identity
        Assert.False(options.AllowDeveloperCredentials);
    }

    [Fact]
    public void DefaultValues_AllowedVaultHostSuffixes_CoverAzureClouds()
    {
        // Arrange & Act
        var options = new KeyVaultReferenceResolverOptions();

        // Assert
        Assert.Contains(".vault.azure.net", options.AllowedVaultHostSuffixes);
        Assert.Contains(".vault.usgovcloudapi.net", options.AllowedVaultHostSuffixes);
        Assert.Contains(".managedhsm.azure.net", options.AllowedVaultHostSuffixes);
    }

    [Fact]
    public void AllowedVaultHostSuffixes_IsPerInstance()
    {
        // Arrange
        var first = new KeyVaultReferenceResolverOptions();
        var second = new KeyVaultReferenceResolverOptions();

        // Act
        first.AllowedVaultHostSuffixes.Clear();

        // Assert - mutating one instance must not disarm the check for every other instance
        Assert.NotEmpty(second.AllowedVaultHostSuffixes);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Validate_NonPositiveMaxConcurrency_Throws(int maxConcurrency)
    {
        // Arrange
        var options = new KeyVaultReferenceResolverOptions { MaxConcurrency = maxConcurrency };

        // Act & Assert
        Assert.Throws<ArgumentOutOfRangeException>(() => options.Validate());
    }

    [Fact]
    public void Validate_NegativeTimeout_Throws()
    {
        // Arrange
        var options = new KeyVaultReferenceResolverOptions { Timeout = TimeSpan.FromSeconds(-5) };

        // Act & Assert
        Assert.Throws<ArgumentOutOfRangeException>(() => options.Validate());
    }

    [Fact]
    public void Validate_InfiniteTimeout_DoesNotThrow()
    {
        // Arrange
        var options = new KeyVaultReferenceResolverOptions
        {
            Timeout = System.Threading.Timeout.InfiniteTimeSpan
        };

        // Act & Assert
        options.Validate();
    }

    [Fact]
    public void Validate_Defaults_DoesNotThrow()
    {
        // Arrange
        var options = new KeyVaultReferenceResolverOptions();

        // Act & Assert
        options.Validate();
    }
}
