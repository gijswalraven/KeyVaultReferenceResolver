using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Xunit;

namespace KeyVaultReferenceResolver.Tests;

public class MockSecretResolverTests
{
    private const string TestSecretUri1 = "https://myvault.vault.azure.net/secrets/secret1";
    private const string TestSecretUri2 = "https://myvault.vault.azure.net/secrets/secret2";
    private const string TestSecretValue1 = "secret-value-1";
    private const string TestSecretValue2 = "secret-value-2";

    [Fact]
    public void Constructor_WithSecrets_StoresSecrets()
    {
        // Arrange
        var secrets = new Dictionary<string, string>
        {
            [TestSecretUri1] = TestSecretValue1,
            [TestSecretUri2] = TestSecretValue2
        };

        // Act
        var resolver = new MockSecretResolver(secrets);

        // Assert
        Assert.Equal(2, resolver.Count);
        Assert.True(resolver.ContainsSecret(TestSecretUri1));
        Assert.True(resolver.ContainsSecret(TestSecretUri2));
    }

    [Fact]
    public void Constructor_WithNullSecrets_ThrowsArgumentNullException()
    {
        // Arrange & Act
        Action act = () => new MockSecretResolver(null!);

        // Assert
        var ex = Assert.Throws<ArgumentNullException>(act);
        Assert.Equal("secrets", ex.ParamName);
    }

    [Fact]
    public void Constructor_Default_CreatesEmptyResolver()
    {
        // Arrange & Act
        var resolver = new MockSecretResolver();

        // Assert
        Assert.Equal(0, resolver.Count);
    }

    [Fact]
    public void AddSecret_SingleSecret_AddsToCollection()
    {
        // Arrange
        var resolver = new MockSecretResolver();

        // Act
        resolver.AddSecret(TestSecretUri1, TestSecretValue1);

        // Assert
        Assert.Equal(1, resolver.Count);
        Assert.True(resolver.ContainsSecret(TestSecretUri1));
        Assert.Equal(TestSecretValue1, resolver.ResolveSecret(TestSecretUri1));
    }

    [Fact]
    public void AddSecret_ReturnsThisForChaining()
    {
        // Arrange
        var resolver = new MockSecretResolver();

        // Act
        var result = resolver.AddSecret(TestSecretUri1, TestSecretValue1);

        // Assert
        Assert.Same(resolver, result);
    }

    [Fact]
    public void AddSecrets_MultipleSecrets_AddsAll()
    {
        // Arrange
        var resolver = new MockSecretResolver();
        var secrets = new Dictionary<string, string>
        {
            [TestSecretUri1] = TestSecretValue1,
            [TestSecretUri2] = TestSecretValue2
        };

        // Act
        resolver.AddSecrets(secrets);

        // Assert
        Assert.Equal(2, resolver.Count);
        Assert.Equal(TestSecretValue1, resolver.ResolveSecret(TestSecretUri1));
        Assert.Equal(TestSecretValue2, resolver.ResolveSecret(TestSecretUri2));
    }

    [Fact]
    public void AddSecrets_ReturnsThisForChaining()
    {
        // Arrange
        var resolver = new MockSecretResolver();
        var secrets = new Dictionary<string, string>
        {
            [TestSecretUri1] = TestSecretValue1
        };

        // Act
        var result = resolver.AddSecrets(secrets);

        // Assert
        Assert.Same(resolver, result);
    }

    [Fact]
    public void ResolveSecret_ExistingSecret_ReturnsValue()
    {
        // Arrange
        var resolver = new MockSecretResolver()
            .AddSecret(TestSecretUri1, TestSecretValue1);

        // Act
        var result = resolver.ResolveSecret(TestSecretUri1);

        // Assert
        Assert.Equal(TestSecretValue1, result);
    }

    [Fact]
    public void ResolveSecret_MissingSecret_ThrowOnMissingTrue_Throws()
    {
        // Arrange
        var resolver = new MockSecretResolver(new Dictionary<string, string>(), throwOnMissing: true);

        // Act
        Action act = () => resolver.ResolveSecret(TestSecretUri1);

        // Assert - the URI is masked, because this exception ends up as the InnerException
        // that the configuration extension logs
        var ex = Assert.Throws<KeyNotFoundException>(act);
        Assert.Equal("Secret not found: https://myvault.vault.azure.net/secrets/***", ex.Message);
        Assert.DoesNotContain("secret1", ex.Message);
    }

    [Fact]
    public void ResolveSecret_MissingSecret_ThrowOnMissingFalse_ReturnsEmpty()
    {
        // Arrange
        var resolver = new MockSecretResolver(new Dictionary<string, string>(), throwOnMissing: false);

        // Act
        var result = resolver.ResolveSecret(TestSecretUri1);

        // Assert
        Assert.Empty(result);
    }

    [Fact]
    public async Task ResolveSecretAsync_ExistingSecret_ReturnsValue()
    {
        // Arrange
        var resolver = new MockSecretResolver()
            .AddSecret(TestSecretUri1, TestSecretValue1);

        // Act
        var result = await resolver.ResolveSecretAsync(TestSecretUri1, TestContext.Current.CancellationToken);

        // Assert
        Assert.Equal(TestSecretValue1, result);
    }

    [Fact]
    public async Task ResolveSecretAsync_MissingSecret_ThrowOnMissingTrue_Throws()
    {
        // Arrange
        var resolver = new MockSecretResolver(new Dictionary<string, string>(), throwOnMissing: true);

        // Act
        Func<Task> act = async () => await resolver.ResolveSecretAsync(TestSecretUri1, TestContext.Current.CancellationToken);

        // Assert - masked, as in the synchronous case
        var ex = await Assert.ThrowsAsync<KeyNotFoundException>(act);
        Assert.Equal("Secret not found: https://myvault.vault.azure.net/secrets/***", ex.Message);
        Assert.DoesNotContain("secret1", ex.Message);
    }

    [Fact]
    public void Clear_RemovesAllSecrets()
    {
        // Arrange
        var resolver = new MockSecretResolver()
            .AddSecret(TestSecretUri1, TestSecretValue1)
            .AddSecret(TestSecretUri2, TestSecretValue2);

        // Act
        resolver.Clear();

        // Assert
        Assert.Equal(0, resolver.Count);
        Assert.False(resolver.ContainsSecret(TestSecretUri1));
        Assert.False(resolver.ContainsSecret(TestSecretUri2));
    }

    [Fact]
    public void Count_ReturnsCorrectCount()
    {
        // Arrange
        var resolver = new MockSecretResolver()
            .AddSecret(TestSecretUri1, TestSecretValue1)
            .AddSecret(TestSecretUri2, TestSecretValue2);

        // Act & Assert
        Assert.Equal(2, resolver.Count);
    }

    [Fact]
    public void ContainsSecret_ExistingSecret_ReturnsTrue()
    {
        // Arrange
        var resolver = new MockSecretResolver()
            .AddSecret(TestSecretUri1, TestSecretValue1);

        // Act & Assert
        Assert.True(resolver.ContainsSecret(TestSecretUri1));
    }

    [Fact]
    public void ContainsSecret_MissingSecret_ReturnsFalse()
    {
        // Arrange
        var resolver = new MockSecretResolver();

        // Act & Assert
        Assert.False(resolver.ContainsSecret(TestSecretUri1));
    }
}
