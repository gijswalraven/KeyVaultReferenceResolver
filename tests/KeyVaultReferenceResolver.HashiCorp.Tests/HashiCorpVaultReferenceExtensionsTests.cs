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
            Assert.True(result);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("regular-value")]
        [InlineData("@Microsoft.KeyVault(SecretUri=https://vault.azure.net/secrets/test)")]
        public void IsHashiCorpVaultReference_InvalidFormats_ReturnsFalse(string? value)
        {
            var result = HashiCorpVaultReferenceExtensions.IsHashiCorpVaultReference(value);
            Assert.False(result);
        }

        [Fact]
        public void ExtractSecretInfo_AttributeFormat_ReturnsCorrectInfo()
        {
            var value = "@HashiCorp.Vault(VaultAddress=https://vault.example.com;SecretPath=secret/data/myapp;SecretKey=db-password)";

            var result = HashiCorpVaultReferenceExtensions.ExtractSecretInfo(value);

            Assert.NotNull(result);
            Assert.Equal("https://vault.example.com", result!.Value.vaultAddress);
            Assert.Equal("secret/data/myapp", result.Value.secretPath);
            Assert.Equal("db-password", result.Value.secretKey);
        }

        [Fact]
        public void ExtractSecretInfo_UriFormat_ReturnsCorrectInfo()
        {
            var value = "hashicorp://vault.example.com/secret/data/myapp#db-password";

            var result = HashiCorpVaultReferenceExtensions.ExtractSecretInfo(value);

            Assert.NotNull(result);
            Assert.Equal("https://vault.example.com", result!.Value.vaultAddress);
            Assert.Equal("secret/data/myapp", result.Value.secretPath);
            Assert.Equal("db-password", result.Value.secretKey);
        }

        [Fact]
        public void ExtractSecretInfo_InvalidValue_ReturnsNull()
        {
            var result = HashiCorpVaultReferenceExtensions.ExtractSecretInfo("not-a-reference");
            Assert.Null(result);
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
            Assert.Equal("resolved-password", config["ConnectionStrings:Database"]);
            Assert.Equal("regular-value", config["RegularSetting"]);
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
            Assert.Equal("resolved-api-key", config["ApiKey"]);
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
            Assert.Equal("value1", config["Setting1"]);
            Assert.Equal("value2", config["Setting2"]);
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

            Assert.Null(Record.Exception(act));
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

            var ex = Assert.Throws<HashiCorpVaultReferenceResolutionException>(act);
            Assert.Equal("Secret", ex.ConfigurationKey);
        }
    }
}
