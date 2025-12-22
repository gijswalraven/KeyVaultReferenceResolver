using FluentAssertions;
using Xunit;

namespace KeyVaultReferenceResolver.HashiCorp.Tests
{
    public class HashiCorpVaultSecretResolverTests
    {
        [Theory]
        [InlineData("@HashiCorp.Vault(VaultAddress=https://vault.example.com;SecretPath=secret/data/myapp;SecretKey=password)")]
        [InlineData("@hashicorp.vault(vaultaddress=https://vault.example.com;secretpath=secret/data/myapp;secretkey=password)")]
        [InlineData("hashicorp://vault.example.com/secret/data/myapp#password")]
        public void IsHashiCorpVaultReference_ValidReferences_ReturnsTrue(string value)
        {
            var result = HashiCorpVaultSecretResolver.IsHashiCorpVaultReference(value);
            result.Should().BeTrue();
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        [InlineData("regular-value")]
        [InlineData("@Microsoft.KeyVault(SecretUri=https://vault.azure.net/secrets/test)")]
        [InlineData("https://vault.example.com/secret/data/myapp")]
        public void IsHashiCorpVaultReference_InvalidReferences_ReturnsFalse(string? value)
        {
            var result = HashiCorpVaultSecretResolver.IsHashiCorpVaultReference(value);
            result.Should().BeFalse();
        }

        [Fact]
        public void TryExtractSecretInfo_AttributeFormat_ExtractsCorrectly()
        {
            var value = "@HashiCorp.Vault(VaultAddress=https://vault.example.com;SecretPath=secret/data/myapp;SecretKey=password)";

            var result = HashiCorpVaultSecretResolver.TryExtractSecretInfo(value);

            result.Should().NotBeNull();
            result!.Value.vaultAddress.Should().Be("https://vault.example.com");
            result.Value.secretPath.Should().Be("secret/data/myapp");
            result.Value.secretKey.Should().Be("password");
        }

        [Fact]
        public void TryExtractSecretInfo_UriFormat_ExtractsCorrectly()
        {
            var value = "hashicorp://vault.example.com/secret/data/myapp#password";

            var result = HashiCorpVaultSecretResolver.TryExtractSecretInfo(value);

            result.Should().NotBeNull();
            result!.Value.vaultAddress.Should().Be("https://vault.example.com");
            result.Value.secretPath.Should().Be("secret/data/myapp");
            result.Value.secretKey.Should().Be("password");
        }

        [Fact]
        public void TryExtractSecretInfo_InvalidValue_ReturnsNull()
        {
            var result = HashiCorpVaultSecretResolver.TryExtractSecretInfo("not-a-vault-reference");
            result.Should().BeNull();
        }

        [Fact]
        public void TryExtractSecretInfo_NullValue_ReturnsNull()
        {
            var result = HashiCorpVaultSecretResolver.TryExtractSecretInfo(null);
            result.Should().BeNull();
        }

        [Fact]
        public void TryExtractSecretInfo_EmptyValue_ReturnsNull()
        {
            var result = HashiCorpVaultSecretResolver.TryExtractSecretInfo("");
            result.Should().BeNull();
        }

        [Theory]
        [InlineData("hashicorp://vault.example.com:8200/secret/data/myapp#password", "https://vault.example.com:8200")]
        [InlineData("hashicorp://localhost/kv/data/test#key", "https://localhost")]
        public void TryExtractSecretInfo_UriFormatWithPort_ExtractsCorrectly(string value, string expectedAddress)
        {
            var result = HashiCorpVaultSecretResolver.TryExtractSecretInfo(value);

            result.Should().NotBeNull();
            result!.Value.vaultAddress.Should().Be(expectedAddress);
        }

        [Fact]
        public void TryExtractSecretInfo_AttributeFormatCaseInsensitive_ExtractsCorrectly()
        {
            var value = "@HASHICORP.VAULT(VAULTADDRESS=https://vault.example.com;SECRETPATH=secret/data/myapp;SECRETKEY=password)";

            var result = HashiCorpVaultSecretResolver.TryExtractSecretInfo(value);

            result.Should().NotBeNull();
            result!.Value.vaultAddress.Should().Be("https://vault.example.com");
        }

        #region Path Parsing Edge Cases

        [Theory]
        [InlineData("secret/data/myapp", "secret/data/myapp")]
        [InlineData("kv/data/nested/path/config", "kv/data/nested/path/config")]
        [InlineData("secret/myapp", "secret/myapp")]
        [InlineData("kv/simple", "kv/simple")]
        public void TryExtractSecretInfo_VariousPathFormats_ExtractsPath(string path, string expectedPath)
        {
            var value = $"@HashiCorp.Vault(VaultAddress=https://vault.example.com;SecretPath={path};SecretKey=password)";

            var result = HashiCorpVaultSecretResolver.TryExtractSecretInfo(value);

            result.Should().NotBeNull();
            result!.Value.secretPath.Should().Be(expectedPath);
        }

        [Theory]
        [InlineData("hashicorp://vault.example.com/secret/data/myapp#password", "secret/data/myapp")]
        [InlineData("hashicorp://vault.example.com/kv/data/nested/path#key", "kv/data/nested/path")]
        [InlineData("hashicorp://vault.example.com/secret/simple#key", "secret/simple")]
        public void TryExtractSecretInfo_UriFormat_VariousPaths_ExtractsCorrectly(string uri, string expectedPath)
        {
            var result = HashiCorpVaultSecretResolver.TryExtractSecretInfo(uri);

            result.Should().NotBeNull();
            result!.Value.secretPath.Should().Be(expectedPath);
        }

        [Theory]
        [InlineData("hashicorp://vault.example.com/a#key", "a")]
        [InlineData("hashicorp://vault.example.com/a/b#key", "a/b")]
        [InlineData("hashicorp://vault.example.com/a/b/c/d/e#key", "a/b/c/d/e")]
        public void TryExtractSecretInfo_UriFormat_DeepPaths_ExtractsCorrectly(string uri, string expectedPath)
        {
            var result = HashiCorpVaultSecretResolver.TryExtractSecretInfo(uri);

            result.Should().NotBeNull();
            result!.Value.secretPath.Should().Be(expectedPath);
        }

        [Theory]
        [InlineData("@HashiCorp.Vault(VaultAddress=https://vault.example.com;SecretPath=secret/data/app;SecretKey=key-with-dash)")]
        [InlineData("@HashiCorp.Vault(VaultAddress=https://vault.example.com;SecretPath=secret/data/app;SecretKey=key_with_underscore)")]
        [InlineData("@HashiCorp.Vault(VaultAddress=https://vault.example.com;SecretPath=secret/data/app;SecretKey=key.with.dots)")]
        public void TryExtractSecretInfo_SpecialCharactersInKey_ExtractsCorrectly(string value)
        {
            var result = HashiCorpVaultSecretResolver.TryExtractSecretInfo(value);
            result.Should().NotBeNull();
        }

        #endregion
    }
}
