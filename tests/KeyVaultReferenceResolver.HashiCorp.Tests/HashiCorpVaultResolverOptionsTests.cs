using System;
using KeyVaultReferenceResolver.HashiCorp.Authentication;
using Xunit;

namespace KeyVaultReferenceResolver.HashiCorp.Tests
{
    public class HashiCorpVaultResolverOptionsTests
    {
        [Fact]
        public void DefaultValues_AreCorrect()
        {
            var options = new HashiCorpVaultResolverOptions();

            Assert.Null(options.VaultAddress);
            Assert.Null(options.AuthMethod);
            Assert.Null(options.KubernetesRoleName);
            Assert.Equal("secret", options.MountPath);
            Assert.Null(options.KvVersion);
            Assert.True(options.ThrowOnResolveFailure);
            Assert.Equal(TimeSpan.FromSeconds(30), options.Timeout);
            Assert.True(options.EnableCaching);
            Assert.Null(options.Namespace);
        }

        [Fact]
        public void GetEffectiveVaultAddress_WithExplicitAddress_ReturnsExplicit()
        {
            var options = new HashiCorpVaultResolverOptions
            {
                VaultAddress = "https://vault.example.com"
            };

            var result = options.GetEffectiveVaultAddress();

            Assert.Equal("https://vault.example.com", result);
        }

        [Fact]
        public void GetEffectiveVaultAddress_WithEnvironmentVariable_ReturnsEnvVar()
        {
            var originalValue = Environment.GetEnvironmentVariable("VAULT_ADDR");
            try
            {
                Environment.SetEnvironmentVariable("VAULT_ADDR", "https://env-vault.example.com");

                var options = new HashiCorpVaultResolverOptions();

                var result = options.GetEffectiveVaultAddress();

                Assert.Equal("https://env-vault.example.com", result);
            }
            finally
            {
                Environment.SetEnvironmentVariable("VAULT_ADDR", originalValue);
            }
        }

        [Fact]
        public void GetEffectiveVaultAddress_ExplicitOverridesEnvVar()
        {
            var originalValue = Environment.GetEnvironmentVariable("VAULT_ADDR");
            try
            {
                Environment.SetEnvironmentVariable("VAULT_ADDR", "https://env-vault.example.com");

                var options = new HashiCorpVaultResolverOptions
                {
                    VaultAddress = "https://explicit-vault.example.com"
                };

                var result = options.GetEffectiveVaultAddress();

                Assert.Equal("https://explicit-vault.example.com", result);
            }
            finally
            {
                Environment.SetEnvironmentVariable("VAULT_ADDR", originalValue);
            }
        }

        [Fact]
        public void GetEffectiveVaultAddress_WhenNotSet_ThrowsException()
        {
            var originalValue = Environment.GetEnvironmentVariable("VAULT_ADDR");
            try
            {
                Environment.SetEnvironmentVariable("VAULT_ADDR", null);

                var options = new HashiCorpVaultResolverOptions();

                var act = () => options.GetEffectiveVaultAddress();

                var ex = Assert.Throws<InvalidOperationException>(act);
                Assert.Contains("Vault address not configured", ex.Message);
            }
            finally
            {
                Environment.SetEnvironmentVariable("VAULT_ADDR", originalValue);
            }
        }

        [Fact]
        public void GetEffectiveAuthMethod_WithExplicitAuthMethod_ReturnsExplicit()
        {
            var tokenAuth = new TokenAuthMethod("my-token");
            var options = new HashiCorpVaultResolverOptions
            {
                AuthMethod = tokenAuth
            };

            var result = options.GetEffectiveAuthMethod();

            Assert.Same(tokenAuth, result);
        }

        [Fact]
        public void GetEffectiveAuthMethod_WithVaultToken_ReturnsTokenAuth()
        {
            var originalToken = Environment.GetEnvironmentVariable("VAULT_TOKEN");
            var originalRoleId = Environment.GetEnvironmentVariable("VAULT_ROLE_ID");
            var originalSecretId = Environment.GetEnvironmentVariable("VAULT_SECRET_ID");
            try
            {
                Environment.SetEnvironmentVariable("VAULT_TOKEN", "test-token");
                Environment.SetEnvironmentVariable("VAULT_ROLE_ID", null);
                Environment.SetEnvironmentVariable("VAULT_SECRET_ID", null);

                var options = new HashiCorpVaultResolverOptions();

                var result = options.GetEffectiveAuthMethod();

                Assert.IsType<TokenAuthMethod>(result);
            }
            finally
            {
                Environment.SetEnvironmentVariable("VAULT_TOKEN", originalToken);
                Environment.SetEnvironmentVariable("VAULT_ROLE_ID", originalRoleId);
                Environment.SetEnvironmentVariable("VAULT_SECRET_ID", originalSecretId);
            }
        }

        [Fact]
        public void GetEffectiveAuthMethod_WithAppRoleCredentials_ReturnsAppRoleAuth()
        {
            var originalToken = Environment.GetEnvironmentVariable("VAULT_TOKEN");
            var originalRoleId = Environment.GetEnvironmentVariable("VAULT_ROLE_ID");
            var originalSecretId = Environment.GetEnvironmentVariable("VAULT_SECRET_ID");
            try
            {
                Environment.SetEnvironmentVariable("VAULT_TOKEN", null);
                Environment.SetEnvironmentVariable("VAULT_ROLE_ID", "test-role-id");
                Environment.SetEnvironmentVariable("VAULT_SECRET_ID", "test-secret-id");

                var options = new HashiCorpVaultResolverOptions();

                var result = options.GetEffectiveAuthMethod();

                Assert.IsType<AppRoleAuthMethod>(result);
            }
            finally
            {
                Environment.SetEnvironmentVariable("VAULT_TOKEN", originalToken);
                Environment.SetEnvironmentVariable("VAULT_ROLE_ID", originalRoleId);
                Environment.SetEnvironmentVariable("VAULT_SECRET_ID", originalSecretId);
            }
        }

        [Fact]
        public void GetEffectiveAuthMethod_WhenNoAuthConfigured_ThrowsException()
        {
            var originalToken = Environment.GetEnvironmentVariable("VAULT_TOKEN");
            var originalRoleId = Environment.GetEnvironmentVariable("VAULT_ROLE_ID");
            var originalSecretId = Environment.GetEnvironmentVariable("VAULT_SECRET_ID");
            try
            {
                Environment.SetEnvironmentVariable("VAULT_TOKEN", null);
                Environment.SetEnvironmentVariable("VAULT_ROLE_ID", null);
                Environment.SetEnvironmentVariable("VAULT_SECRET_ID", null);

                var options = new HashiCorpVaultResolverOptions();

                var act = () => options.GetEffectiveAuthMethod();

                var ex = Assert.Throws<InvalidOperationException>(act);
                Assert.Contains("No authentication method configured", ex.Message);
            }
            finally
            {
                Environment.SetEnvironmentVariable("VAULT_TOKEN", originalToken);
                Environment.SetEnvironmentVariable("VAULT_ROLE_ID", originalRoleId);
                Environment.SetEnvironmentVariable("VAULT_SECRET_ID", originalSecretId);
            }
        }

        [Fact]
        public void Timeout_CanBeCustomized()
        {
            var options = new HashiCorpVaultResolverOptions
            {
                Timeout = TimeSpan.FromMinutes(2)
            };

            Assert.Equal(TimeSpan.FromMinutes(2), options.Timeout);
        }

        [Fact]
        public void MountPath_CanBeCustomized()
        {
            var options = new HashiCorpVaultResolverOptions
            {
                MountPath = "kv"
            };

            Assert.Equal("kv", options.MountPath);
        }

        [Fact]
        public void KvVersion_CanBeSet()
        {
            var options = new HashiCorpVaultResolverOptions
            {
                KvVersion = 1
            };

            Assert.Equal(1, options.KvVersion);
        }

        [Fact]
        public void Namespace_CanBeSet()
        {
            var options = new HashiCorpVaultResolverOptions
            {
                Namespace = "my-namespace"
            };

            Assert.Equal("my-namespace", options.Namespace);
        }
    }
}
