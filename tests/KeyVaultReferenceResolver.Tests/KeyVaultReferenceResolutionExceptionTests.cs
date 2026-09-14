using System;
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
        Assert.Equal(TestMessage, exception.Message);
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
        Assert.Equal(TestConfigKey, exception.ConfigurationKey);
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
        Assert.Equal(TestSecretUri, exception.SecretUri);
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
        Assert.Same(innerException, exception.InnerException);
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
        Assert.Null(exception.InnerException);
    }
}
