using System;
using FluentAssertions;
using Xunit;

namespace KeyVaultReferenceResolver.Tests;

public class KeyVaultReferenceResolutionExceptionTests
{
    private const string TestMessage = "Failed to resolve secret";
    private const string TestConfigKey = "ConnectionStrings:Database";
    private const string TestSecretUri = "https://myvault.vault.azure.net/secrets/db-connection";

    [Fact]
    public void Constructor_SetsMessage()
    {
        // Arrange & Act
        var exception = new KeyVaultReferenceResolutionException(
            TestMessage,
            TestConfigKey,
            TestSecretUri);

        // Assert
        exception.Message.Should().Be(TestMessage);
    }

    [Fact]
    public void Constructor_SetsConfigurationKey()
    {
        // Arrange & Act
        var exception = new KeyVaultReferenceResolutionException(
            TestMessage,
            TestConfigKey,
            TestSecretUri);

        // Assert
        exception.ConfigurationKey.Should().Be(TestConfigKey);
    }

    [Fact]
    public void Constructor_SetsSecretUri()
    {
        // Arrange & Act
        var exception = new KeyVaultReferenceResolutionException(
            TestMessage,
            TestConfigKey,
            TestSecretUri);

        // Assert
        exception.SecretUri.Should().Be(TestSecretUri);
    }

    [Fact]
    public void Constructor_WithInnerException_SetsInnerException()
    {
        // Arrange
        var innerException = new InvalidOperationException("Inner error");

        // Act
        var exception = new KeyVaultReferenceResolutionException(
            TestMessage,
            TestConfigKey,
            TestSecretUri,
            innerException);

        // Assert
        exception.InnerException.Should().BeSameAs(innerException);
    }

    [Fact]
    public void Constructor_WithoutInnerException_InnerExceptionIsNull()
    {
        // Arrange & Act
        var exception = new KeyVaultReferenceResolutionException(
            TestMessage,
            TestConfigKey,
            TestSecretUri);

        // Assert
        exception.InnerException.Should().BeNull();
    }
}
