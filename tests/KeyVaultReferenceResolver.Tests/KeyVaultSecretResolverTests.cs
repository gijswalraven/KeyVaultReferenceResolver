using System;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace KeyVaultReferenceResolver.Tests;

public class KeyVaultSecretResolverTests
{
    #region Constructor Tests

    [Fact]
    public void Constructor_Default_UsesDefaultOptions()
    {
        // Arrange & Act
        var resolver = new KeyVaultSecretResolver();

        // Assert - resolver should be created without throwing
        resolver.Should().NotBeNull();
    }

    [Fact]
    public void Constructor_WithNullOptions_UsesDefaults()
    {
        // Arrange & Act
        var resolver = new KeyVaultSecretResolver(null);

        // Assert - resolver should be created without throwing
        resolver.Should().NotBeNull();
    }

    [Fact]
    public void Constructor_WithNullLogger_UsesNullLogger()
    {
        // Arrange
        var options = new KeyVaultReferenceResolverOptions();

        // Act
        var resolver = new KeyVaultSecretResolver(options, null);

        // Assert - resolver should be created without throwing
        resolver.Should().NotBeNull();
    }

    [Fact]
    public void Constructor_WithOptions_CreatesResolver()
    {
        // Arrange
        var options = new KeyVaultReferenceResolverOptions
        {
            EnableCaching = false,
            Timeout = TimeSpan.FromMinutes(1)
        };
        var mockLogger = new Mock<ILogger<KeyVaultSecretResolver>>();

        // Act
        var resolver = new KeyVaultSecretResolver(options, mockLogger.Object);

        // Assert
        resolver.Should().NotBeNull();
    }

    #endregion

    #region ResolveSecretAsync Validation Tests

    [Fact]
    public async Task ResolveSecretAsync_NullUri_ThrowsArgumentException()
    {
        // Arrange
        var resolver = new KeyVaultSecretResolver();

        // Act
        Func<Task> act = async () => await resolver.ResolveSecretAsync(null!);

        // Assert
        await act.Should().ThrowAsync<ArgumentException>()
            .WithParameterName("secretUri");
    }

    [Fact]
    public async Task ResolveSecretAsync_EmptyUri_ThrowsArgumentException()
    {
        // Arrange
        var resolver = new KeyVaultSecretResolver();

        // Act
        Func<Task> act = async () => await resolver.ResolveSecretAsync(string.Empty);

        // Assert
        await act.Should().ThrowAsync<ArgumentException>()
            .WithParameterName("secretUri");
    }

    [Fact]
    public async Task ResolveSecretAsync_WhitespaceUri_ThrowsArgumentException()
    {
        // Arrange
        var resolver = new KeyVaultSecretResolver();

        // Act
        Func<Task> act = async () => await resolver.ResolveSecretAsync("   ");

        // Assert
        await act.Should().ThrowAsync<ArgumentException>()
            .WithParameterName("secretUri");
    }

    [Fact]
    public async Task ResolveSecretAsync_InvalidUriFormat_ThrowsUriFormatException()
    {
        // Arrange
        var resolver = new KeyVaultSecretResolver();

        // Act
        Func<Task> act = async () => await resolver.ResolveSecretAsync("not-a-valid-uri");

        // Assert
        await act.Should().ThrowAsync<UriFormatException>();
    }

    [Fact]
    public async Task ResolveSecretAsync_UriWithoutSecrets_ThrowsArgumentException()
    {
        // Arrange
        var resolver = new KeyVaultSecretResolver();
        var uri = "https://myvault.vault.azure.net/keys/my-key";

        // Act
        Func<Task> act = async () => await resolver.ResolveSecretAsync(uri);

        // Assert
        await act.Should().ThrowAsync<ArgumentException>()
            .WithMessage("*Invalid Key Vault secret URI format*")
            .WithParameterName("secretUri");
    }

    [Fact]
    public async Task ResolveSecretAsync_UriWithInvalidPath_ThrowsArgumentException()
    {
        // Arrange
        var resolver = new KeyVaultSecretResolver();
        var uri = "https://myvault.vault.azure.net/invalid/path";

        // Act
        Func<Task> act = async () => await resolver.ResolveSecretAsync(uri);

        // Assert
        await act.Should().ThrowAsync<ArgumentException>()
            .WithMessage("*Invalid Key Vault secret URI format*")
            .WithParameterName("secretUri");
    }

    [Fact]
    public async Task ResolveSecretAsync_UriWithOnlySecretsPath_ThrowsArgumentException()
    {
        // Arrange
        var resolver = new KeyVaultSecretResolver();
        var uri = "https://myvault.vault.azure.net/secrets";

        // Act
        Func<Task> act = async () => await resolver.ResolveSecretAsync(uri);

        // Assert
        await act.Should().ThrowAsync<ArgumentException>()
            .WithMessage("*Invalid Key Vault secret URI format*")
            .WithParameterName("secretUri");
    }

    #endregion

    #region ResolveSecret Validation Tests

    [Fact]
    public void ResolveSecret_NullUri_ThrowsArgumentException()
    {
        // Arrange
        var resolver = new KeyVaultSecretResolver();

        // Act
        Action act = () => resolver.ResolveSecret(null!);

        // Assert
        act.Should().Throw<ArgumentException>()
            .WithParameterName("secretUri");
    }

    [Fact]
    public void ResolveSecret_EmptyUri_ThrowsArgumentException()
    {
        // Arrange
        var resolver = new KeyVaultSecretResolver();

        // Act
        Action act = () => resolver.ResolveSecret(string.Empty);

        // Assert
        act.Should().Throw<ArgumentException>()
            .WithParameterName("secretUri");
    }

    [Fact]
    public void ResolveSecret_InvalidUri_ThrowsArgumentException()
    {
        // Arrange
        var resolver = new KeyVaultSecretResolver();
        var uri = "https://myvault.vault.azure.net/keys/my-key";

        // Act
        Action act = () => resolver.ResolveSecret(uri);

        // Assert
        act.Should().Throw<ArgumentException>()
            .WithMessage("*Invalid Key Vault secret URI format*");
    }

    #endregion
}
