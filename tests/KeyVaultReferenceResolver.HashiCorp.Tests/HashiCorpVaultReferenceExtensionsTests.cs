using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace KeyVaultReferenceResolver.HashiCorp.Tests
{
    public class HashiCorpVaultReferenceExtensionsTests
    {
        [Theory]
        [InlineData("@HashiCorp.Vault(VaultAddress=https://vault.example.com;SecretPath=secret/data/myapp;SecretKey=password)")]
        [InlineData("hashicorp://vault.example.com/secret/data/myapp#password")]
        public void IsHashiCorpVaultReference_ValidFormats_ReturnsTrue(string value)
        {
            var result = HashiCorpVaultReferenceExtensions.IsHashiCorpVaultReference(value);
            result.Should().BeTrue();
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("regular-value")]
        [InlineData("@Microsoft.KeyVault(SecretUri=https://vault.azure.net/secrets/test)")]
        public void IsHashiCorpVaultReference_InvalidFormats_ReturnsFalse(string? value)
        {
            var result = HashiCorpVaultReferenceExtensions.IsHashiCorpVaultReference(value);
            result.Should().BeFalse();
        }

        [Fact]
        public void ExtractSecretInfo_AttributeFormat_ReturnsCorrectInfo()
        {
            var value = "@HashiCorp.Vault(VaultAddress=https://vault.example.com;SecretPath=secret/data/myapp;SecretKey=db-password)";

            var result = HashiCorpVaultReferenceExtensions.ExtractSecretInfo(value);

            result.Should().NotBeNull();
            result!.Value.vaultAddress.Should().Be("https://vault.example.com");
            result.Value.secretPath.Should().Be("secret/data/myapp");
            result.Value.secretKey.Should().Be("db-password");
        }

        [Fact]
        public void ExtractSecretInfo_UriFormat_ReturnsCorrectInfo()
        {
            var value = "hashicorp://vault.example.com/secret/data/myapp#db-password";

            var result = HashiCorpVaultReferenceExtensions.ExtractSecretInfo(value);

            result.Should().NotBeNull();
            result!.Value.vaultAddress.Should().Be("https://vault.example.com");
            result.Value.secretPath.Should().Be("secret/data/myapp");
            result.Value.secretKey.Should().Be("db-password");
        }

        [Fact]
        public void ExtractSecretInfo_InvalidValue_ReturnsNull()
        {
            var result = HashiCorpVaultReferenceExtensions.ExtractSecretInfo("not-a-reference");
            result.Should().BeNull();
        }

        [Fact]
        public void AddHashiCorpVaultResolver_WithMockResolver_ResolvesReferences()
        {
            // Arrange
            var mockResolver = new MockSecretResolver()
                .AddSecret(
                    "@HashiCorp.Vault(VaultAddress=https://vault.example.com;SecretPath=secret/data/myapp;SecretKey=password)",
                    "resolved-password");

            var builder = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["ConnectionStrings:Database"] = "@HashiCorp.Vault(VaultAddress=https://vault.example.com;SecretPath=secret/data/myapp;SecretKey=password)",
                    ["RegularSetting"] = "regular-value"
                });

            // Act
            builder.AddHashiCorpVaultResolver(mockResolver);
            var config = builder.Build();

            // Assert
            config["ConnectionStrings:Database"].Should().Be("resolved-password");
            config["RegularSetting"].Should().Be("regular-value");
        }

        [Fact]
        public void AddHashiCorpVaultResolver_WithUriFormat_ResolvesReferences()
        {
            // Arrange
            var mockResolver = new MockSecretResolver()
                .AddSecret(
                    "hashicorp://vault.example.com/secret/data/myapp#api-key",
                    "resolved-api-key");

            var builder = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["ApiKey"] = "hashicorp://vault.example.com/secret/data/myapp#api-key"
                });

            // Act
            builder.AddHashiCorpVaultResolver(mockResolver);
            var config = builder.Build();

            // Assert
            config["ApiKey"].Should().Be("resolved-api-key");
        }

        [Fact]
        public void AddHashiCorpVaultResolver_NoReferences_LeavesConfigUnchanged()
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
            builder.AddHashiCorpVaultResolver(mockResolver);
            var config = builder.Build();

            // Assert
            config["Setting1"].Should().Be("value1");
            config["Setting2"].Should().Be("value2");
        }

        [Fact]
        public void AddHashiCorpVaultResolver_ThrowOnResolveFailureFalse_DoesNotThrow()
        {
            // Arrange
            var mockResolver = new MockSecretResolver(new Dictionary<string, string>(), throwOnMissing: true);

            var builder = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Secret"] = "@HashiCorp.Vault(VaultAddress=https://vault.example.com;SecretPath=secret/data/myapp;SecretKey=missing)"
                });

            // Act & Assert
            var options = new HashiCorpVaultResolverOptions { ThrowOnResolveFailure = false };
            var act = () => builder.AddHashiCorpVaultResolver(mockResolver, options);

            act.Should().NotThrow();
        }

        [Fact]
        public void AddHashiCorpVaultResolver_ThrowOnResolveFailureTrue_ThrowsException()
        {
            // Arrange
            var mockResolver = new MockSecretResolver(new Dictionary<string, string>(), throwOnMissing: true);

            var builder = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Secret"] = "@HashiCorp.Vault(VaultAddress=https://vault.example.com;SecretPath=secret/data/myapp;SecretKey=missing)"
                });

            // Act & Assert
            var options = new HashiCorpVaultResolverOptions { ThrowOnResolveFailure = true };
            var act = () => builder.AddHashiCorpVaultResolver(mockResolver, options);

            act.Should().Throw<HashiCorpVaultReferenceResolutionException>()
                .Which.ConfigurationKey.Should().Be("Secret");
        }
    }
}
