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
}
