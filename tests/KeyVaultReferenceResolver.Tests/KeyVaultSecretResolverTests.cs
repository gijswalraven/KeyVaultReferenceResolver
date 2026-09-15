using System;
using System.Threading.Tasks;
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
        Assert.NotNull(resolver);
    }

    [Fact]
    public void Constructor_WithNullOptions_UsesDefaults()
    {
        // Arrange & Act
        var resolver = new KeyVaultSecretResolver(null);

        // Assert - resolver should be created without throwing
        Assert.NotNull(resolver);
    }

    [Fact]
    public void Constructor_WithNullLogger_UsesNullLogger()
    {
        // Arrange
        var options = new KeyVaultReferenceResolverOptions();

        // Act
        var resolver = new KeyVaultSecretResolver(options, null);

        // Assert - resolver should be created without throwing
        Assert.NotNull(resolver);
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
        Assert.NotNull(resolver);
    }

    #endregion

    #region ResolveSecretAsync Validation Tests

    [Fact]
    public async Task ResolveSecretAsync_NullUri_ThrowsArgumentException()
    {
        // Arrange
        var resolver = new KeyVaultSecretResolver();

        // Act
        Func<Task> act = async () => await resolver.ResolveSecretAsync(null!, TestContext.Current.CancellationToken);

        // Assert
        var ex = await Assert.ThrowsAsync<ArgumentException>(act);
        Assert.Equal("secretUri", ex.ParamName);
    }

    [Fact]
    public async Task ResolveSecretAsync_EmptyUri_ThrowsArgumentException()
    {
        // Arrange
        var resolver = new KeyVaultSecretResolver();

        // Act
        Func<Task> act = async () => await resolver.ResolveSecretAsync(string.Empty, TestContext.Current.CancellationToken);

        // Assert
        var ex = await Assert.ThrowsAsync<ArgumentException>(act);
        Assert.Equal("secretUri", ex.ParamName);
    }

    [Fact]
    public async Task ResolveSecretAsync_WhitespaceUri_ThrowsArgumentException()
    {
        // Arrange
        var resolver = new KeyVaultSecretResolver();

        // Act
        Func<Task> act = async () => await resolver.ResolveSecretAsync("   ", TestContext.Current.CancellationToken);

        // Assert
        var ex = await Assert.ThrowsAsync<ArgumentException>(act);
        Assert.Equal("secretUri", ex.ParamName);
    }

    [Fact]
    public async Task ResolveSecretAsync_InvalidUriFormat_ThrowsArgumentException()
    {
        // Arrange
        var resolver = new KeyVaultSecretResolver();

        // Act
        Func<Task> act = async () => await resolver.ResolveSecretAsync("not-a-valid-uri", TestContext.Current.CancellationToken);

        // Assert
        var ex = await Assert.ThrowsAsync<ArgumentException>(act);
        Assert.Equal("secretUri", ex.ParamName);
        // The malformed value must not be echoed back in the message.
        Assert.DoesNotContain("not-a-valid-uri", ex.Message);
    }

    [Fact]
    public async Task ResolveSecretAsync_NonHttpsUri_ThrowsArgumentException()
    {
        // Arrange
        var resolver = new KeyVaultSecretResolver();

        // Act
        Func<Task> act = async () => await resolver.ResolveSecretAsync(
            "http://myvault.vault.azure.net/secrets/mysecret", TestContext.Current.CancellationToken);

        // Assert
        var ex = await Assert.ThrowsAsync<ArgumentException>(act);
        Assert.Contains("https", ex.Message);
    }

    [Fact]
    public async Task ResolveSecretAsync_HostOutsideKeyVault_ThrowsArgumentException()
    {
        // Arrange
        var resolver = new KeyVaultSecretResolver();

        // Act - a tampered configuration value pointing at a host the process must not talk to
        Func<Task> act = async () => await resolver.ResolveSecretAsync(
            "https://attacker.example.com/secrets/mysecret", TestContext.Current.CancellationToken);

        // Assert
        var ex = await Assert.ThrowsAsync<ArgumentException>(act);
        Assert.Contains("attacker.example.com", ex.Message);
    }

    [Fact]
    public async Task ResolveSecretAsync_HostAllowListCleared_SkipsHostCheck()
    {
        // Arrange
        var options = new KeyVaultReferenceResolverOptions();
        options.AllowedVaultHostSuffixes.Clear();
        var resolver = new KeyVaultSecretResolver(options);

        // Act - the host check is opt-out; the URI shape is still validated
        Func<Task> act = async () => await resolver.ResolveSecretAsync(
            "https://internal.example.com/not-secrets/mysecret", TestContext.Current.CancellationToken);

        // Assert
        var ex = await Assert.ThrowsAsync<ArgumentException>(act);
        Assert.Contains("Expected format", ex.Message);
    }

    [Fact]
    public async Task ResolveSecretAsync_UriWithoutSecrets_ThrowsArgumentException()
    {
        // Arrange
        var resolver = new KeyVaultSecretResolver();
        var uri = "https://myvault.vault.azure.net/keys/my-key";

        // Act
        Func<Task> act = async () => await resolver.ResolveSecretAsync(uri, TestContext.Current.CancellationToken);

        // Assert
        var ex = await Assert.ThrowsAsync<ArgumentException>(act);
        Assert.Contains("Invalid Key Vault secret URI format", ex.Message);
        Assert.Equal("secretUri", ex.ParamName);
    }

    [Fact]
    public async Task ResolveSecretAsync_UriWithInvalidPath_ThrowsArgumentException()
    {
        // Arrange
        var resolver = new KeyVaultSecretResolver();
        var uri = "https://myvault.vault.azure.net/invalid/path";

        // Act
        Func<Task> act = async () => await resolver.ResolveSecretAsync(uri, TestContext.Current.CancellationToken);

        // Assert
        var ex = await Assert.ThrowsAsync<ArgumentException>(act);
        Assert.Contains("Invalid Key Vault secret URI format", ex.Message);
        Assert.Equal("secretUri", ex.ParamName);
    }

    [Fact]
    public async Task ResolveSecretAsync_UriWithOnlySecretsPath_ThrowsArgumentException()
    {
        // Arrange
        var resolver = new KeyVaultSecretResolver();
        var uri = "https://myvault.vault.azure.net/secrets";

        // Act
        Func<Task> act = async () => await resolver.ResolveSecretAsync(uri, TestContext.Current.CancellationToken);

        // Assert
        var ex = await Assert.ThrowsAsync<ArgumentException>(act);
        Assert.Contains("Invalid Key Vault secret URI format", ex.Message);
        Assert.Equal("secretUri", ex.ParamName);
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
        var ex = Assert.Throws<ArgumentException>(act);
        Assert.Equal("secretUri", ex.ParamName);
    }

    [Fact]
    public void ResolveSecret_EmptyUri_ThrowsArgumentException()
    {
        // Arrange
        var resolver = new KeyVaultSecretResolver();

        // Act
        Action act = () => resolver.ResolveSecret(string.Empty);

        // Assert
        var ex = Assert.Throws<ArgumentException>(act);
        Assert.Equal("secretUri", ex.ParamName);
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
        var ex = Assert.Throws<ArgumentException>(act);
        Assert.Contains("Invalid Key Vault secret URI format", ex.Message);
    }

    #endregion
}
