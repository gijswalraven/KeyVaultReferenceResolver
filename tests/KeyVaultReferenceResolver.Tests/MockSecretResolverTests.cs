using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using FluentAssertions;
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
        resolver.Count.Should().Be(2);
        resolver.ContainsSecret(TestSecretUri1).Should().BeTrue();
        resolver.ContainsSecret(TestSecretUri2).Should().BeTrue();
    }

    [Fact]
    public void Constructor_WithNullSecrets_ThrowsArgumentNullException()
    {
        // Arrange & Act
        Action act = () => new MockSecretResolver(null!);

        // Assert
        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("secrets");
    }

    [Fact]
    public void Constructor_Default_CreatesEmptyResolver()
    {
        // Arrange & Act
        var resolver = new MockSecretResolver();

        // Assert
        resolver.Count.Should().Be(0);
    }

    [Fact]
    public void AddSecret_SingleSecret_AddsToCollection()
    {
        // Arrange
        var resolver = new MockSecretResolver();

        // Act
        resolver.AddSecret(TestSecretUri1, TestSecretValue1);

        // Assert
        resolver.Count.Should().Be(1);
        resolver.ContainsSecret(TestSecretUri1).Should().BeTrue();
        resolver.ResolveSecret(TestSecretUri1).Should().Be(TestSecretValue1);
    }

    [Fact]
    public void AddSecret_ReturnsThisForChaining()
    {
        // Arrange
        var resolver = new MockSecretResolver();

        // Act
        var result = resolver.AddSecret(TestSecretUri1, TestSecretValue1);

        // Assert
        result.Should().BeSameAs(resolver);
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
        resolver.Count.Should().Be(2);
        resolver.ResolveSecret(TestSecretUri1).Should().Be(TestSecretValue1);
        resolver.ResolveSecret(TestSecretUri2).Should().Be(TestSecretValue2);
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
        result.Should().BeSameAs(resolver);
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
        result.Should().Be(TestSecretValue1);
    }

    [Fact]
    public void ResolveSecret_MissingSecret_ThrowOnMissingTrue_Throws()
    {
        // Arrange
        var resolver = new MockSecretResolver(new Dictionary<string, string>(), throwOnMissing: true);

        // Act
        Action act = () => resolver.ResolveSecret(TestSecretUri1);

        // Assert
        act.Should().Throw<KeyNotFoundException>()
            .WithMessage($"Secret not found: {TestSecretUri1}");
    }

    [Fact]
    public void ResolveSecret_MissingSecret_ThrowOnMissingFalse_ReturnsEmpty()
    {
        // Arrange
        var resolver = new MockSecretResolver(new Dictionary<string, string>(), throwOnMissing: false);

        // Act
        var result = resolver.ResolveSecret(TestSecretUri1);

        // Assert
        result.Should().BeEmpty();
    }

    [Fact]
    public async Task ResolveSecretAsync_ExistingSecret_ReturnsValue()
    {
        // Arrange
        var resolver = new MockSecretResolver()
            .AddSecret(TestSecretUri1, TestSecretValue1);

        // Act
        var result = await resolver.ResolveSecretAsync(TestSecretUri1);

        // Assert
        result.Should().Be(TestSecretValue1);
    }

    [Fact]
    public async Task ResolveSecretAsync_MissingSecret_ThrowOnMissingTrue_Throws()
    {
        // Arrange
        var resolver = new MockSecretResolver(new Dictionary<string, string>(), throwOnMissing: true);

        // Act
        Func<Task> act = async () => await resolver.ResolveSecretAsync(TestSecretUri1);

        // Assert
        await act.Should().ThrowAsync<KeyNotFoundException>()
            .WithMessage($"Secret not found: {TestSecretUri1}");
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
        resolver.Count.Should().Be(0);
        resolver.ContainsSecret(TestSecretUri1).Should().BeFalse();
        resolver.ContainsSecret(TestSecretUri2).Should().BeFalse();
    }

    [Fact]
    public void Count_ReturnsCorrectCount()
    {
        // Arrange
        var resolver = new MockSecretResolver()
            .AddSecret(TestSecretUri1, TestSecretValue1)
            .AddSecret(TestSecretUri2, TestSecretValue2);

        // Act & Assert
        resolver.Count.Should().Be(2);
    }

    [Fact]
    public void ContainsSecret_ExistingSecret_ReturnsTrue()
    {
        // Arrange
        var resolver = new MockSecretResolver()
            .AddSecret(TestSecretUri1, TestSecretValue1);

        // Act & Assert
        resolver.ContainsSecret(TestSecretUri1).Should().BeTrue();
    }

    [Fact]
    public void ContainsSecret_MissingSecret_ReturnsFalse()
    {
        // Arrange
        var resolver = new MockSecretResolver();

        // Act & Assert
        resolver.ContainsSecret(TestSecretUri1).Should().BeFalse();
    }
}
