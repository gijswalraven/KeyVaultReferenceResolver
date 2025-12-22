using System;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.AuthMethods.AppRole;

namespace KeyVaultReferenceResolver.HashiCorp.Authentication
{
    /// <summary>
    /// AppRole-based authentication for HashiCorp Vault.
    /// </summary>
    public class AppRoleAuthMethod : IVaultAuthMethod
    {
        private readonly string _roleId;
        private readonly string _secretId;
        private readonly string _mountPoint;

        /// <summary>
        /// Creates a new instance using explicit role ID and secret ID.
        /// </summary>
        /// <param name="roleId">The AppRole role ID.</param>
        /// <param name="secretId">The AppRole secret ID.</param>
        /// <param name="mountPoint">The mount point for AppRole auth. Defaults to "approle".</param>
        public AppRoleAuthMethod(string roleId, string secretId, string mountPoint = "approle")
        {
            if (string.IsNullOrWhiteSpace(roleId))
                throw new ArgumentException("Role ID cannot be null or empty.", nameof(roleId));
            if (string.IsNullOrWhiteSpace(secretId))
                throw new ArgumentException("Secret ID cannot be null or empty.", nameof(secretId));

            _roleId = roleId;
            _secretId = secretId;
            _mountPoint = mountPoint;
        }

        /// <summary>
        /// Creates a new instance using VAULT_ROLE_ID and VAULT_SECRET_ID environment variables.
        /// </summary>
        /// <param name="mountPoint">The mount point for AppRole auth. Defaults to "approle".</param>
        /// <returns>A new AppRoleAuthMethod instance.</returns>
        /// <exception cref="InvalidOperationException">Thrown when required environment variables are not set.</exception>
        public static AppRoleAuthMethod FromEnvironment(string mountPoint = "approle")
        {
            var roleId = Environment.GetEnvironmentVariable("VAULT_ROLE_ID");
            var secretId = Environment.GetEnvironmentVariable("VAULT_SECRET_ID");

            if (string.IsNullOrWhiteSpace(roleId))
                throw new InvalidOperationException("VAULT_ROLE_ID environment variable is not set.");
            if (string.IsNullOrWhiteSpace(secretId))
                throw new InvalidOperationException("VAULT_SECRET_ID environment variable is not set.");

            return new AppRoleAuthMethod(roleId, secretId, mountPoint);
        }

        /// <summary>
        /// Tries to create a new instance using VAULT_ROLE_ID and VAULT_SECRET_ID environment variables.
        /// </summary>
        /// <param name="authMethod">The created auth method, or null if environment variables are not set.</param>
        /// <param name="mountPoint">The mount point for AppRole auth. Defaults to "approle".</param>
        /// <returns>True if successful, false otherwise.</returns>
        public static bool TryFromEnvironment(out AppRoleAuthMethod? authMethod, string mountPoint = "approle")
        {
            var roleId = Environment.GetEnvironmentVariable("VAULT_ROLE_ID");
            var secretId = Environment.GetEnvironmentVariable("VAULT_SECRET_ID");

            if (string.IsNullOrWhiteSpace(roleId) || string.IsNullOrWhiteSpace(secretId))
            {
                authMethod = null;
                return false;
            }

            authMethod = new AppRoleAuthMethod(roleId, secretId, mountPoint);
            return true;
        }

        /// <inheritdoc />
        public IAuthMethodInfo GetAuthMethodInfo()
        {
            return new AppRoleAuthMethodInfo(_mountPoint, _roleId, _secretId);
        }
    }
}
