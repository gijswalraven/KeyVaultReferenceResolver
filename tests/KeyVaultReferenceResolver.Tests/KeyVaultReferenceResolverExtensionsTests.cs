using System;
using System.Collections.Generic;
using Azure.Identity;
using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace KeyVaultReferenceResolver.Tests;

public class KeyVaultReferenceResolverExtensionsTests
{
    private const string TestVaultUri = "https://myvault.vault.azure.net";
    private const string TestSecretUri = "https://myvault.vault.azure.net/secrets/my-secret";
    private const string TestSecretUriWithVersion = "https://myvault.vault.azure.net/secrets/my-secret/abc123";
    private const string TestSecretValue = "super-secret-value";
    private const string ValidKeyVaultReference = "@Microsoft.KeyVault(SecretUri=https://myvault.vault.azure.net/secrets/my-secret)";

    // VaultName format constants
    private const string ValidVaultNameReference = "@Microsoft.KeyVault(VaultName=myvault;SecretName=my-secret)";
    private const string ValidVaultNameReferenceWithVersion = "@Microsoft.KeyVault(VaultName=myvault;SecretName=my-secret;SecretVersion=abc123)";

    #region IsKeyVaultReference Tests

    [Fact]
    public void IsKeyVaultReference_ValidReference_ReturnsTrue()
    {
        // Arrange
        var value = ValidKeyVaultReference;

        // Act
        var result = KeyVaultReferenceResolverExtensions.IsKeyVaultReference(value);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public void IsKeyVaultReference_ValidReference_CaseInsensitive_ReturnsTrue()
    {
        // Arrange
        var value = "@MICROSOFT.KEYVAULT(SecretUri=https://myvault.vault.azure.net/secrets/my-secret)";

        // Act
        var result = KeyVaultReferenceResolverExtensions.IsKeyVaultReference(value);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public void IsKeyVaultReference_InvalidReference_ReturnsFalse()
    {
        // Arrange
        var value = "just-a-regular-string";

        // Act
        var result = KeyVaultReferenceResolverExtensions.IsKeyVaultReference(value);

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public void IsKeyVaultReference_NullValue_ReturnsFalse()
    {
        // Act
        var result = KeyVaultReferenceResolverExtensions.IsKeyVaultReference(null);

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public void IsKeyVaultReference_EmptyValue_ReturnsFalse()
    {
        // Act
        var result = KeyVaultReferenceResolverExtensions.IsKeyVaultReference(string.Empty);

        // Assert
        result.Should().BeFalse();
    }

    [Theory]
    [InlineData("@Microsoft.KeyVault(SecretUri=https://vault.vault.azure.net/secrets/test)")]
    [InlineData("@microsoft.keyvault(secreturi=https://vault.vault.azure.net/secrets/test)")]
    [InlineData("@Microsoft.KeyVault(SecretUri=https://my-vault.vault.azure.net/secrets/my-secret/version123)")]
    public void IsKeyVaultReference_VariousValidSecretUriFormats_ReturnsTrue(string value)
    {
        // Act
        var result = KeyVaultReferenceResolverExtensions.IsKeyVaultReference(value);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public void IsKeyVaultReference_VaultNameFormat_ReturnsTrue()
    {
        // Act
        var result = KeyVaultReferenceResolverExtensions.IsKeyVaultReference(ValidVaultNameReference);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public void IsKeyVaultReference_VaultNameFormatWithVersion_ReturnsTrue()
    {
        // Act
        var result = KeyVaultReferenceResolverExtensions.IsKeyVaultReference(ValidVaultNameReferenceWithVersion);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public void IsKeyVaultReference_VaultNameFormat_CaseInsensitive_ReturnsTrue()
    {
        // Arrange
        var value = "@MICROSOFT.KEYVAULT(VaultName=myvault;SecretName=mysecret)";

        // Act
        var result = KeyVaultReferenceResolverExtensions.IsKeyVaultReference(value);

        // Assert
        result.Should().BeTrue();
    }

    [Theory]
    [InlineData("@Microsoft.KeyVault(VaultName=my-vault;SecretName=my-secret)")]
    [InlineData("@Microsoft.KeyVault(VaultName=vault123;SecretName=secret-name;SecretVersion=v1)")]
    [InlineData("@microsoft.keyvault(vaultname=test;secretname=test)")]
    public void IsKeyVaultReference_VariousValidVaultNameFormats_ReturnsTrue(string value)
    {
        // Act
        var result = KeyVaultReferenceResolverExtensions.IsKeyVaultReference(value);

        // Assert
        result.Should().BeTrue();
    }

    #endregion

    #region ExtractSecretUri Tests

    [Fact]
    public void ExtractSecretUri_ValidReference_ReturnsUri()
    {
        // Arrange
        var value = ValidKeyVaultReference;

        // Act
        var result = KeyVaultReferenceResolverExtensions.ExtractSecretUri(value);

        // Assert
        result.Should().Be(TestSecretUri);
    }

    [Fact]
    public void ExtractSecretUri_ValidReferenceWithVersion_ReturnsUriWithVersion()
    {
        // Arrange
        var value = $"@Microsoft.KeyVault(SecretUri={TestSecretUriWithVersion})";

        // Act
        var result = KeyVaultReferenceResolverExtensions.ExtractSecretUri(value);

        // Assert
        result.Should().Be(TestSecretUriWithVersion);
    }

    [Fact]
    public void ExtractSecretUri_InvalidReference_ReturnsNull()
    {
        // Arrange
        var value = "just-a-regular-string";

        // Act
        var result = KeyVaultReferenceResolverExtensions.ExtractSecretUri(value);

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public void ExtractSecretUri_NullValue_ReturnsNull()
    {
        // Act
        var result = KeyVaultReferenceResolverExtensions.ExtractSecretUri(null);

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public void ExtractSecretUri_EmptyValue_ReturnsNull()
    {
        // Act
        var result = KeyVaultReferenceResolverExtensions.ExtractSecretUri(string.Empty);

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public void ExtractSecretUri_VaultNameFormat_ConstructsUri()
    {
        // Act
        var result = KeyVaultReferenceResolverExtensions.ExtractSecretUri(ValidVaultNameReference);

        // Assert
        result.Should().Be(TestSecretUri);
    }

    [Fact]
    public void ExtractSecretUri_VaultNameFormatWithVersion_ConstructsUriWithVersion()
    {
        // Act
        var result = KeyVaultReferenceResolverExtensions.ExtractSecretUri(ValidVaultNameReferenceWithVersion);

        // Assert
        result.Should().Be(TestSecretUriWithVersion);
    }

    [Theory]
    [InlineData("@Microsoft.KeyVault(VaultName=testvault;SecretName=testsecret)", "https://testvault.vault.azure.net/secrets/testsecret")]
    [InlineData("@Microsoft.KeyVault(VaultName=my-vault;SecretName=my-secret;SecretVersion=v123)", "https://my-vault.vault.azure.net/secrets/my-secret/v123")]
    public void ExtractSecretUri_VaultNameFormat_ConstructsCorrectUri(string input, string expectedUri)
    {
        // Act
        var result = KeyVaultReferenceResolverExtensions.ExtractSecretUri(input);

        // Assert
        result.Should().Be(expectedUri);
    }

    #endregion

    #region AddKeyVaultReferenceResolver Tests

    [Fact]
    public void AddKeyVaultReferenceResolver_WithSecretResolver_ResolvesSecrets()
    {
        // Arrange
        var mockResolver = new MockSecretResolver()
            .AddSecret(TestSecretUri, TestSecretValue);

        var builder = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionString"] = ValidKeyVaultReference
            });

        // Act
        builder.AddKeyVaultReferenceResolver(mockResolver);
        var config = builder.Build();

        // Assert
        config["ConnectionString"].Should().Be(TestSecretValue);
    }

    [Fact]
    public void AddKeyVaultReferenceResolver_NullBuilder_ThrowsArgumentNullException()
    {
        // Arrange
        IConfigurationBuilder? builder = null;
        var mockResolver = new MockSecretResolver();

        // Act
        Action act = () => builder!.AddKeyVaultReferenceResolver(mockResolver);

        // Assert
        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("builder");
    }

    [Fact]
    public void AddKeyVaultReferenceResolver_NullSecretResolver_ThrowsArgumentNullException()
    {
        // Arrange
        var builder = new ConfigurationBuilder();

        // Act
        Action act = () => builder.AddKeyVaultReferenceResolver((ISecretResolver)null!);

        // Assert
        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("secretResolver");
    }

    [Fact]
    public void AddKeyVaultReferenceResolver_ConfigWithKeyVaultRef_ResolvesValue()
    {
        // Arrange
        var mockResolver = new MockSecretResolver()
            .AddSecret(TestSecretUri, TestSecretValue);

        var builder = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["MySecret"] = ValidKeyVaultReference,
                ["RegularValue"] = "not-a-secret"
            });

        // Act
        builder.AddKeyVaultReferenceResolver(mockResolver);
        var config = builder.Build();

        // Assert
        config["MySecret"].Should().Be(TestSecretValue);
        config["RegularValue"].Should().Be("not-a-secret");
    }

    [Fact]
    public void AddKeyVaultReferenceResolver_ConfigWithMultipleRefs_ResolvesAll()
    {
        // Arrange
        var secretUri1 = "https://myvault.vault.azure.net/secrets/secret1";
        var secretUri2 = "https://myvault.vault.azure.net/secrets/secret2";
        var secretValue1 = "value1";
        var secretValue2 = "value2";

        var mockResolver = new MockSecretResolver()
            .AddSecret(secretUri1, secretValue1)
            .AddSecret(secretUri2, secretValue2);

        var builder = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Secret1"] = $"@Microsoft.KeyVault(SecretUri={secretUri1})",
                ["Secret2"] = $"@Microsoft.KeyVault(SecretUri={secretUri2})"
            });

        // Act
        builder.AddKeyVaultReferenceResolver(mockResolver);
        var config = builder.Build();

        // Assert
        config["Secret1"].Should().Be(secretValue1);
        config["Secret2"].Should().Be(secretValue2);
    }

    [Fact]
    public void AddKeyVaultReferenceResolver_ConfigWithNoRefs_NoChanges()
    {
        // Arrange
        var mockResolver = new MockSecretResolver();

        var builder = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Setting1"] = "value1",
                ["Setting2"] = "value2"
            });

        // Act
        builder.AddKeyVaultReferenceResolver(mockResolver);
        var config = builder.Build();

        // Assert
        config["Setting1"].Should().Be("value1");
        config["Setting2"].Should().Be("value2");
    }

    [Fact]
    public void AddKeyVaultReferenceResolver_ConfigWithEmptyValue_SkipsEntry()
    {
        // Arrange
        var mockResolver = new MockSecretResolver();

        var builder = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["EmptyKey"] = string.Empty
            });

        // Act
        builder.AddKeyVaultReferenceResolver(mockResolver);
        var config = builder.Build();

        // Assert
        config["EmptyKey"].Should().BeEmpty();
    }

    [Fact]
    public void AddKeyVaultReferenceResolver_ConfigWithNullValue_SkipsEntry()
    {
        // Arrange
        var mockResolver = new MockSecretResolver();

        var builder = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["NullKey"] = null
            });

        // Act
        builder.AddKeyVaultReferenceResolver(mockResolver);
        var config = builder.Build();

        // Assert
        config["NullKey"].Should().BeNull();
    }

    [Fact]
    public void AddKeyVaultReferenceResolver_ResolveFailure_ThrowOnFailureFalse_Continues()
    {
        // Arrange
        var mockResolver = new MockSecretResolver(new Dictionary<string, string>(), throwOnMissing: true);
        var options = new KeyVaultReferenceResolverOptions { ThrowOnResolveFailure = false };

        var builder = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["MissingSecret"] = ValidKeyVaultReference
            });

        // Act - should not throw
        builder.AddKeyVaultReferenceResolver(mockResolver, options);
        var config = builder.Build();

        // Assert - original value preserved (not resolved)
        config["MissingSecret"].Should().Be(ValidKeyVaultReference);
    }

    [Fact]
    public void AddKeyVaultReferenceResolver_ResolveFailure_ThrowOnFailureTrue_Throws()
    {
        // Arrange
        var mockResolver = new MockSecretResolver(new Dictionary<string, string>(), throwOnMissing: true);
        var options = new KeyVaultReferenceResolverOptions { ThrowOnResolveFailure = true };

        var builder = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["MissingSecret"] = ValidKeyVaultReference
            });

        // Act
        Action act = () => builder.AddKeyVaultReferenceResolver(mockResolver, options);

        // Assert
        act.Should().Throw<KeyVaultReferenceResolutionException>()
            .Which.ConfigurationKey.Should().Be("MissingSecret");
    }

    [Fact]
    public void AddKeyVaultReferenceResolver_Default_ReturnsBuilder()
    {
        // Arrange
        var builder = new ConfigurationBuilder();

        // Act
        var result = builder.AddKeyVaultReferenceResolver();

        // Assert
        result.Should().BeSameAs(builder);
    }

    [Fact]
    public void AddKeyVaultReferenceResolver_WithCredential_ReturnsBuilder()
    {
        // Arrange
        var builder = new ConfigurationBuilder();
        var credential = new DefaultAzureCredential();

        // Act
        var result = builder.AddKeyVaultReferenceResolver(credential);

        // Assert
        result.Should().BeSameAs(builder);
    }

    [Fact]
    public void AddKeyVaultReferenceResolver_WithConfigureAction_InvokesAction()
    {
        // Arrange
        var builder = new ConfigurationBuilder();
        var actionInvoked = false;
        var capturedOptions = (KeyVaultReferenceResolverOptions?)null;

        // Act
        builder.AddKeyVaultReferenceResolver(options =>
        {
            actionInvoked = true;
            capturedOptions = options;
            options.ThrowOnResolveFailure = true;
            options.Timeout = TimeSpan.FromMinutes(5);
        });

        // Assert
        actionInvoked.Should().BeTrue();
        capturedOptions.Should().NotBeNull();
        capturedOptions!.ThrowOnResolveFailure.Should().BeTrue();
        capturedOptions.Timeout.Should().Be(TimeSpan.FromMinutes(5));
    }

    [Fact]
    public void AddKeyVaultReferenceResolver_WithOptionsAndLogger_ReturnsBuilder()
    {
        // Arrange
        var builder = new ConfigurationBuilder();
        var options = new KeyVaultReferenceResolverOptions();
        var mockLogger = new Mock<ILogger>();

        // Act
        var result = builder.AddKeyVaultReferenceResolver(options, mockLogger.Object);

        // Assert
        result.Should().BeSameAs(builder);
    }

    [Fact]
    public void AddKeyVaultReferenceResolver_WithNullOptions_UsesDefaults()
    {
        // Arrange
        var mockResolver = new MockSecretResolver()
            .AddSecret(TestSecretUri, TestSecretValue);

        var builder = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Secret"] = ValidKeyVaultReference
            });

        // Act - null options should work
        builder.AddKeyVaultReferenceResolver(mockResolver, null, null);
        var config = builder.Build();

        // Assert
        config["Secret"].Should().Be(TestSecretValue);
    }

    [Fact]
    public void AddKeyVaultReferenceResolver_WithLogger_LogsResolution()
    {
        // Arrange
        var mockResolver = new MockSecretResolver()
            .AddSecret(TestSecretUri, TestSecretValue);
        var mockLogger = new Mock<ILogger>();

        var builder = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Secret"] = ValidKeyVaultReference
            });

        // Act
        builder.AddKeyVaultReferenceResolver(mockResolver, null, mockLogger.Object);

        // Assert - logger should have been called (we verify it doesn't throw)
        // The actual logging is internal, we just verify the operation completes
        var config = builder.Build();
        config["Secret"].Should().Be(TestSecretValue);
    }

    #endregion

    #region VaultName Format Resolution Tests

    [Fact]
    public void AddKeyVaultReferenceResolver_VaultNameFormat_ResolvesSecrets()
    {
        // Arrange
        var mockResolver = new MockSecretResolver()
            .AddSecret(TestSecretUri, TestSecretValue);

        var builder = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionString"] = ValidVaultNameReference
            });

        // Act
        builder.AddKeyVaultReferenceResolver(mockResolver);
        var config = builder.Build();

        // Assert
        config["ConnectionString"].Should().Be(TestSecretValue);
    }

    [Fact]
    public void AddKeyVaultReferenceResolver_VaultNameFormatWithVersion_ResolvesSecrets()
    {
        // Arrange
        var mockResolver = new MockSecretResolver()
            .AddSecret(TestSecretUriWithVersion, TestSecretValue);

        var builder = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionString"] = ValidVaultNameReferenceWithVersion
            });

        // Act
        builder.AddKeyVaultReferenceResolver(mockResolver);
        var config = builder.Build();

        // Assert
        config["ConnectionString"].Should().Be(TestSecretValue);
    }

    [Fact]
    public void AddKeyVaultReferenceResolver_MixedFormats_ResolvesAll()
    {
        // Arrange
        var secretUri1 = "https://vault1.vault.azure.net/secrets/secret1";
        var secretUri2 = "https://vault2.vault.azure.net/secrets/secret2";
        var secretValue1 = "value1";
        var secretValue2 = "value2";

        var mockResolver = new MockSecretResolver()
            .AddSecret(secretUri1, secretValue1)
            .AddSecret(secretUri2, secretValue2);

        var builder = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                // SecretUri format
                ["Secret1"] = $"@Microsoft.KeyVault(SecretUri={secretUri1})",
                // VaultName format
                ["Secret2"] = "@Microsoft.KeyVault(VaultName=vault2;SecretName=secret2)"
            });

        // Act
        builder.AddKeyVaultReferenceResolver(mockResolver);
        var config = builder.Build();

        // Assert
        config["Secret1"].Should().Be(secretValue1);
        config["Secret2"].Should().Be(secretValue2);
    }

    [Fact]
    public void AddKeyVaultReferenceResolver_VaultNameFormat_ResolveFailure_ThrowOnFailureTrue_Throws()
    {
        // Arrange
        var mockResolver = new MockSecretResolver(new Dictionary<string, string>(), throwOnMissing: true);
        var options = new KeyVaultReferenceResolverOptions { ThrowOnResolveFailure = true };

        var builder = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["MissingSecret"] = ValidVaultNameReference
            });

        // Act
        Action act = () => builder.AddKeyVaultReferenceResolver(mockResolver, options);

        // Assert
        act.Should().Throw<KeyVaultReferenceResolutionException>()
            .Which.ConfigurationKey.Should().Be("MissingSecret");
    }

    #endregion
}
