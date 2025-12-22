using System;
using KeyVaultReferenceResolver.HashiCorp.Authentication;

namespace KeyVaultReferenceResolver.HashiCorp
{
    /// <summary>
    /// Configuration options for HashiCorp Vault secret resolution.
    /// </summary>
    public class HashiCorpVaultResolverOptions
    {
        /// <summary>
        /// Gets or sets the HashiCorp Vault server address.
        /// If null, reads from VAULT_ADDR environment variable.
        /// </summary>
        public string? VaultAddress { get; set; }

        /// <summary>
        /// Gets or sets the authentication method to use.
        /// If null, auto-detects from environment variables in order:
        /// 1. VAULT_TOKEN (Token auth)
        /// 2. VAULT_ROLE_ID + VAULT_SECRET_ID (AppRole auth)
        /// 3. Kubernetes service account token (if running in K8s)
        /// </summary>
        public IVaultAuthMethod? AuthMethod { get; set; }

        /// <summary>
        /// Gets or sets the Kubernetes role name for auto-detected Kubernetes auth.
        /// Only used when AuthMethod is null and running in Kubernetes.
        /// </summary>
        public string? KubernetesRoleName { get; set; }

        /// <summary>
        /// Gets or sets the default secrets engine mount path.
        /// Defaults to "secret".
        /// </summary>
        public string MountPath { get; set; } = "secret";

        /// <summary>
        /// Gets or sets the KV secrets engine version.
        /// If null, auto-detects. Valid values: 1 or 2.
        /// </summary>
        public int? KvVersion { get; set; }

        /// <summary>
        /// Gets or sets whether to throw an exception when a secret cannot be resolved.
        /// Default is true (fail fast).
        /// </summary>
        public bool ThrowOnResolveFailure { get; set; } = true;

        /// <summary>
        /// Gets or sets the timeout for secret retrieval operations.
        /// Default is 30 seconds.
        /// </summary>
        public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);

        /// <summary>
        /// Gets or sets whether to cache resolved secrets in memory.
        /// Default is true.
        /// </summary>
        public bool EnableCaching { get; set; } = true;

        /// <summary>
        /// Gets or sets the Vault namespace (Enterprise feature).
        /// Leave null for open source Vault.
        /// </summary>
        public string? Namespace { get; set; }

        /// <summary>
        /// Gets the effective vault address, falling back to VAULT_ADDR environment variable.
        /// </summary>
        /// <returns>The vault address.</returns>
        /// <exception cref="InvalidOperationException">Thrown when vault address cannot be determined.</exception>
        public string GetEffectiveVaultAddress()
        {
            var address = VaultAddress ?? Environment.GetEnvironmentVariable("VAULT_ADDR");
            if (string.IsNullOrWhiteSpace(address))
                throw new InvalidOperationException(
                    "Vault address not configured. Set VaultAddress option or VAULT_ADDR environment variable.");

            return address;
        }

        /// <summary>
        /// Gets the effective authentication method, auto-detecting from environment if not set.
        /// </summary>
        /// <returns>The authentication method.</returns>
        /// <exception cref="InvalidOperationException">Thrown when no authentication method can be determined.</exception>
        public IVaultAuthMethod GetEffectiveAuthMethod()
        {
            if (AuthMethod != null)
                return AuthMethod;

            // Try Token auth from environment
            if (TokenAuthMethod.TryFromEnvironment(out var tokenAuth))
                return tokenAuth;

            // Try AppRole auth from environment
            if (AppRoleAuthMethod.TryFromEnvironment(out var appRoleAuth))
                return appRoleAuth;

            // Try Kubernetes auth if running in K8s
            if (!string.IsNullOrWhiteSpace(KubernetesRoleName) &&
                KubernetesAuthMethod.TryFromFile(KubernetesRoleName, out var k8sAuth))
                return k8sAuth;

            throw new InvalidOperationException(
                "No authentication method configured. Set AuthMethod option, VAULT_TOKEN, " +
                "VAULT_ROLE_ID + VAULT_SECRET_ID, or configure KubernetesRoleName when running in Kubernetes.");
        }
    }
}
