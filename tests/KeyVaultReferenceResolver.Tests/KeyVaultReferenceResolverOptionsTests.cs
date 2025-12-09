using System;
using Azure.Identity;
using FluentAssertions;
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
        options.Credential.Should().BeNull();
    }

    [Fact]
    public void DefaultValues_ThrowOnResolveFailure_IsFalse()
    {
        // Arrange & Act
        var options = new KeyVaultReferenceResolverOptions();

        // Assert
        options.ThrowOnResolveFailure.Should().BeFalse();
    }

    [Fact]
    public void DefaultValues_Timeout_Is30Seconds()
    {
        // Arrange & Act
        var options = new KeyVaultReferenceResolverOptions();

        // Assert
        options.Timeout.Should().Be(TimeSpan.FromSeconds(30));
    }

    [Fact]
    public void DefaultValues_EnableCaching_IsTrue()
    {
        // Arrange & Act
        var options = new KeyVaultReferenceResolverOptions();

        // Assert
        options.EnableCaching.Should().BeTrue();
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
        options.ThrowOnResolveFailure = true;
        options.Timeout = timeout;
        options.EnableCaching = false;

        // Assert
        options.Credential.Should().BeSameAs(credential);
        options.ThrowOnResolveFailure.Should().BeTrue();
        options.Timeout.Should().Be(timeout);
        options.EnableCaching.Should().BeFalse();
    }
}
