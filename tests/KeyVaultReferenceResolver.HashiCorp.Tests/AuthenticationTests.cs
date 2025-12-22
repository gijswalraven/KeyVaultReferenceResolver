using System;
using FluentAssertions;
using KeyVaultReferenceResolver.HashiCorp.Authentication;
using Xunit;

namespace KeyVaultReferenceResolver.HashiCorp.Tests
{
    public class AuthenticationTests
    {
        #region TokenAuthMethod Tests

        [Fact]
        public void TokenAuthMethod_WithExplicitToken_CreatesSuccessfully()
        {
            var authMethod = new TokenAuthMethod("my-vault-token");

            var authInfo = authMethod.GetAuthMethodInfo();

            authInfo.Should().NotBeNull();
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public void TokenAuthMethod_WithInvalidToken_ThrowsArgumentException(string? token)
        {
            var act = () => new TokenAuthMethod(token!);

            act.Should().Throw<ArgumentException>()
                .WithMessage("*Token cannot be null or empty*");
        }

        [Fact]
        public void TokenAuthMethod_TryFromEnvironment_ReturnsFalse_WhenNotSet()
        {
            // Ensure environment variable is not set
            Environment.SetEnvironmentVariable("VAULT_TOKEN", null);

            var result = TokenAuthMethod.TryFromEnvironment(out var authMethod);

            result.Should().BeFalse();
            authMethod.Should().BeNull();
        }

        [Fact]
        public void TokenAuthMethod_TryFromEnvironment_ReturnsTrue_WhenSet()
        {
            var originalValue = Environment.GetEnvironmentVariable("VAULT_TOKEN");
            try
            {
                Environment.SetEnvironmentVariable("VAULT_TOKEN", "test-token");

                var result = TokenAuthMethod.TryFromEnvironment(out var authMethod);

                result.Should().BeTrue();
                authMethod.Should().NotBeNull();
            }
            finally
            {
                Environment.SetEnvironmentVariable("VAULT_TOKEN", originalValue);
            }
        }

        [Fact]
        public void TokenAuthMethod_FromEnvironment_Throws_WhenNotSet()
        {
            Environment.SetEnvironmentVariable("VAULT_TOKEN", null);

            var act = () => TokenAuthMethod.FromEnvironment();

            act.Should().Throw<InvalidOperationException>()
                .WithMessage("*VAULT_TOKEN environment variable is not set*");
        }

        #endregion

        #region AppRoleAuthMethod Tests

        [Fact]
        public void AppRoleAuthMethod_WithExplicitCredentials_CreatesSuccessfully()
        {
            var authMethod = new AppRoleAuthMethod("my-role-id", "my-secret-id");

            var authInfo = authMethod.GetAuthMethodInfo();

            authInfo.Should().NotBeNull();
        }

        [Fact]
        public void AppRoleAuthMethod_WithCustomMountPoint_CreatesSuccessfully()
        {
            var authMethod = new AppRoleAuthMethod("my-role-id", "my-secret-id", "custom-approle");

            var authInfo = authMethod.GetAuthMethodInfo();

            authInfo.Should().NotBeNull();
        }

        [Theory]
        [InlineData(null, "secret-id")]
        [InlineData("", "secret-id")]
        [InlineData("   ", "secret-id")]
        public void AppRoleAuthMethod_WithInvalidRoleId_ThrowsArgumentException(string? roleId, string secretId)
        {
            var act = () => new AppRoleAuthMethod(roleId!, secretId);

            act.Should().Throw<ArgumentException>()
                .WithMessage("*Role ID cannot be null or empty*");
        }

        [Theory]
        [InlineData("role-id", null)]
        [InlineData("role-id", "")]
        [InlineData("role-id", "   ")]
        public void AppRoleAuthMethod_WithInvalidSecretId_ThrowsArgumentException(string roleId, string? secretId)
        {
            var act = () => new AppRoleAuthMethod(roleId, secretId!);

            act.Should().Throw<ArgumentException>()
                .WithMessage("*Secret ID cannot be null or empty*");
        }

        [Fact]
        public void AppRoleAuthMethod_TryFromEnvironment_ReturnsFalse_WhenNotSet()
        {
            Environment.SetEnvironmentVariable("VAULT_ROLE_ID", null);
            Environment.SetEnvironmentVariable("VAULT_SECRET_ID", null);

            var result = AppRoleAuthMethod.TryFromEnvironment(out var authMethod);

            result.Should().BeFalse();
            authMethod.Should().BeNull();
        }

        [Fact]
        public void AppRoleAuthMethod_TryFromEnvironment_ReturnsFalse_WhenPartiallySet()
        {
            var originalRoleId = Environment.GetEnvironmentVariable("VAULT_ROLE_ID");
            var originalSecretId = Environment.GetEnvironmentVariable("VAULT_SECRET_ID");
            try
            {
                Environment.SetEnvironmentVariable("VAULT_ROLE_ID", "test-role-id");
                Environment.SetEnvironmentVariable("VAULT_SECRET_ID", null);

                var result = AppRoleAuthMethod.TryFromEnvironment(out var authMethod);

                result.Should().BeFalse();
                authMethod.Should().BeNull();
            }
            finally
            {
                Environment.SetEnvironmentVariable("VAULT_ROLE_ID", originalRoleId);
                Environment.SetEnvironmentVariable("VAULT_SECRET_ID", originalSecretId);
            }
        }

        [Fact]
        public void AppRoleAuthMethod_TryFromEnvironment_ReturnsTrue_WhenFullySet()
        {
            var originalRoleId = Environment.GetEnvironmentVariable("VAULT_ROLE_ID");
            var originalSecretId = Environment.GetEnvironmentVariable("VAULT_SECRET_ID");
            try
            {
                Environment.SetEnvironmentVariable("VAULT_ROLE_ID", "test-role-id");
                Environment.SetEnvironmentVariable("VAULT_SECRET_ID", "test-secret-id");

                var result = AppRoleAuthMethod.TryFromEnvironment(out var authMethod);

                result.Should().BeTrue();
                authMethod.Should().NotBeNull();
            }
            finally
            {
                Environment.SetEnvironmentVariable("VAULT_ROLE_ID", originalRoleId);
                Environment.SetEnvironmentVariable("VAULT_SECRET_ID", originalSecretId);
            }
        }

        #endregion

        #region KubernetesAuthMethod Tests

        [Fact]
        public void KubernetesAuthMethod_WithExplicitJwt_CreatesSuccessfully()
        {
            var authMethod = new KubernetesAuthMethod("my-role", "my-jwt-token");

            var authInfo = authMethod.GetAuthMethodInfo();

            authInfo.Should().NotBeNull();
        }

        [Fact]
        public void KubernetesAuthMethod_WithCustomMountPoint_CreatesSuccessfully()
        {
            var authMethod = new KubernetesAuthMethod("my-role", "my-jwt-token", "custom-k8s");

            var authInfo = authMethod.GetAuthMethodInfo();

            authInfo.Should().NotBeNull();
        }

        [Theory]
        [InlineData(null, "jwt")]
        [InlineData("", "jwt")]
        [InlineData("   ", "jwt")]
        public void KubernetesAuthMethod_WithInvalidRoleName_ThrowsArgumentException(string? roleName, string jwt)
        {
            var act = () => new KubernetesAuthMethod(roleName!, jwt);

            act.Should().Throw<ArgumentException>()
                .WithMessage("*Role name cannot be null or empty*");
        }

        [Theory]
        [InlineData("role", null)]
        [InlineData("role", "")]
        [InlineData("role", "   ")]
        public void KubernetesAuthMethod_WithInvalidJwt_ThrowsArgumentException(string roleName, string? jwt)
        {
            var act = () => new KubernetesAuthMethod(roleName, jwt!);

            act.Should().Throw<ArgumentException>()
                .WithMessage("*JWT cannot be null or empty*");
        }

        [Fact]
        public void KubernetesAuthMethod_TryFromFile_ReturnsFalse_WhenFileNotExists()
        {
            var result = KubernetesAuthMethod.TryFromFile(
                "my-role",
                out var authMethod,
                "/non/existent/path/token");

            result.Should().BeFalse();
            authMethod.Should().BeNull();
        }

        [Fact]
        public void KubernetesAuthMethod_TryFromFile_ReturnsFalse_WhenRoleNameEmpty()
        {
            var result = KubernetesAuthMethod.TryFromFile(
                "",
                out var authMethod);

            result.Should().BeFalse();
            authMethod.Should().BeNull();
        }

        [Fact]
        public void KubernetesAuthMethod_IsRunningInKubernetes_ReturnsFalse_WhenNotInK8s()
        {
            // This test assumes we're not running in Kubernetes
            var result = KubernetesAuthMethod.IsRunningInKubernetes();

            // On a dev machine, this should be false
            // In K8s, the service account token file would exist
            result.Should().BeFalse();
        }

        [Fact]
        public void KubernetesAuthMethod_DefaultTokenPath_IsCorrect()
        {
            KubernetesAuthMethod.DefaultTokenPath.Should().Be("/var/run/secrets/kubernetes.io/serviceaccount/token");
        }

        #endregion
    }
}
