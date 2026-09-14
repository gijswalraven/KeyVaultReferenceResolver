using Xunit;

namespace KeyVaultReferenceResolver.HashiCorp.Tests
{
    /// <summary>
    /// The secret path and key come from a configuration value and end up in the Vault request
    /// URL, so a path that can address a different API endpoint must be rejected rather than sent.
    /// </summary>
    public class SecretPathValidationTests
    {
        private static string AttributeReference(string path, string key = "password") =>
            $"@HashiCorp.Vault(VaultAddress=https://vault.example.com;SecretPath={path};SecretKey={key})";

        [Theory]
        // Dot segments are normalised away by Uri, so this reaches sys/mounts, not the KV mount.
        [InlineData("secret/data/../../sys/mounts")]
        [InlineData("secret/data/../other")]
        [InlineData("../secret/data/app")]
        [InlineData("secret/./data/app")]
        public void DotSegmentsInPath_AreRejected(string path)
        {
            // Act
            var result = HashiCorpVaultSecretResolver.TryExtractSecretInfo(AttributeReference(path));

            // Assert
            Assert.Null(result);
        }

        [Theory]
        // '?' would splice a query string onto the Vault request; '#' a fragment.
        [InlineData("secret/data/app?list=true")]
        [InlineData("secret/data/app#fragment")]
        [InlineData("secret\\data\\app")]
        public void UrlMetacharactersInPath_AreRejected(string path)
        {
            // Act
            var result = HashiCorpVaultSecretResolver.TryExtractSecretInfo(AttributeReference(path));

            // Assert
            Assert.Null(result);
        }

        [Fact]
        public void ControlCharacterInPath_IsRejected()
        {
            // Arrange - composed in code rather than written as a literal, so the character is
            // visible in the source
            var path = "secret/data/app" + (char)0x01;

            // Act
            var result = HashiCorpVaultSecretResolver.TryExtractSecretInfo(AttributeReference(path));

            // Assert
            Assert.Null(result);
        }

        [Fact]
        public void ControlCharacterInKey_IsRejected()
        {
            // Arrange
            var key = "pass" + (char)0x01 + "word";

            // Act
            var result = HashiCorpVaultSecretResolver.TryExtractSecretInfo(
                AttributeReference("secret/data/app", key));

            // Assert
            Assert.Null(result);
        }

        [Theory]
        [InlineData("secret/data/myapp")]
        [InlineData("secret/data/myapp/config")]
        [InlineData("kv/data/team-a/service-b")]
        [InlineData("secret/data/app.with.dots")]
        [InlineData("secret/data/app-with-dashes_and_underscores")]
        public void OrdinaryPaths_AreAccepted(string path)
        {
            // Act
            var result = HashiCorpVaultSecretResolver.TryExtractSecretInfo(AttributeReference(path));

            // Assert - a name containing dots is fine; only '.' and '..' whole segments are not
            Assert.NotNull(result);
            Assert.Equal(path, result!.Value.secretPath);
            Assert.Equal("password", result.Value.secretKey);
        }

        [Fact]
        public void UriFormat_PathIsValidatedToo()
        {
            // Act - the hashicorp:// form goes through the same validation
            var result = HashiCorpVaultSecretResolver.TryExtractSecretInfo(
                "hashicorp://vault.example.com/secret/data/../../sys/mounts#password");

            // Assert
            Assert.Null(result);
        }

        [Fact]
        public void UriFormat_OrdinaryPathIsAccepted()
        {
            // Act
            var result = HashiCorpVaultSecretResolver.TryExtractSecretInfo(
                "hashicorp://vault.example.com/secret/data/myapp#password");

            // Assert
            Assert.NotNull(result);
            Assert.Equal("https://vault.example.com", result!.Value.vaultAddress);
            Assert.Equal("secret/data/myapp", result.Value.secretPath);
            Assert.Equal("password", result.Value.secretKey);
        }
    }
}
