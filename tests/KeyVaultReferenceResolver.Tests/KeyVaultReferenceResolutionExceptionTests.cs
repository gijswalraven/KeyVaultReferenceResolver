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
    public void Constructor_MasksSecretNameInSecretUri()
    {
        // Arrange & Act
        var exception = new KeyVaultReferenceResolutionException(
            TestMessage,
            TestConfigKey,
            TestSecretUri);

        // Assert - the vault is identifiable, the secret name is not
        Assert.Equal("https://myvault.vault.azure.net/secrets/***", exception.SecretUri);
        Assert.DoesNotContain("db-connection", exception.SecretUri);
    }

    [Fact]
    public void Constructor_UnparseableSecretUri_MasksEntirely()
    {
        // Arrange & Act
        var exception = new KeyVaultReferenceResolutionException(
            TestMessage,
            TestConfigKey,
            "not-a-uri-db-connection");

        // Assert
        Assert.Equal("***", exception.SecretUri);
        Assert.DoesNotContain("db-connection", exception.SecretUri);
    }

    [Fact]
    public void Constructor_MessageOnly_LeavesReferencePropertiesEmpty()
    {
        // Arrange & Act
        var exception = new KeyVaultReferenceResolutionException(TestMessage);

        // Assert
        Assert.Equal(TestMessage, exception.Message);
        Assert.Equal(string.Empty, exception.ConfigurationKey);
        Assert.Equal(string.Empty, exception.SecretUri);
    }

    [Fact]
    public void Constructor_MessageAndInnerException_LeavesReferencePropertiesEmpty()
    {
        // Arrange
        var inner = new InvalidOperationException("inner");

        // Act
        var exception = new KeyVaultReferenceResolutionException(TestMessage, inner);

        // Assert
        Assert.Same(inner, exception.InnerException);
        Assert.Equal(string.Empty, exception.SecretUri);
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
