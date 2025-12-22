using System;
using FluentAssertions;
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

            options.VaultAddress.Should().BeNull();
            options.AuthMethod.Should().BeNull();
            options.KubernetesRoleName.Should().BeNull();
            options.MountPath.Should().Be("secret");
            options.KvVersion.Should().BeNull();
            options.ThrowOnResolveFailure.Should().BeTrue();
            options.Timeout.Should().Be(TimeSpan.FromSeconds(30));
            options.EnableCaching.Should().BeTrue();
            options.Namespace.Should().BeNull();
        }

        [Fact]
        public void GetEffectiveVaultAddress_WithExplicitAddress_ReturnsExplicit()
        {
            var options = new HashiCorpVaultResolverOptions
            {
                VaultAddress = "https://vault.example.com"
            };

            var result = options.GetEffectiveVaultAddress();

            result.Should().Be("https://vault.example.com");
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

                result.Should().Be("https://env-vault.example.com");
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

                result.Should().Be("https://explicit-vault.example.com");
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

                act.Should().Throw<InvalidOperationException>()
                    .WithMessage("*Vault address not configured*");
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

            result.Should().BeSameAs(tokenAuth);
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

                result.Should().BeOfType<TokenAuthMethod>();
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

                result.Should().BeOfType<AppRoleAuthMethod>();
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

                act.Should().Throw<InvalidOperationException>()
                    .WithMessage("*No authentication method configured*");
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

            options.Timeout.Should().Be(TimeSpan.FromMinutes(2));
        }

        [Fact]
        public void MountPath_CanBeCustomized()
        {
            var options = new HashiCorpVaultResolverOptions
            {
                MountPath = "kv"
            };

            options.MountPath.Should().Be("kv");
        }

        [Fact]
        public void KvVersion_CanBeSet()
        {
            var options = new HashiCorpVaultResolverOptions
            {
                KvVersion = 1
            };

            options.KvVersion.Should().Be(1);
        }

        [Fact]
        public void Namespace_CanBeSet()
        {
            var options = new HashiCorpVaultResolverOptions
            {
                Namespace = "my-namespace"
            };

            options.Namespace.Should().Be("my-namespace");
        }
    }
}
