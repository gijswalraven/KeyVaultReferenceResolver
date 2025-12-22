using System;
using System.IO;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.AuthMethods.Kubernetes;

namespace KeyVaultReferenceResolver.HashiCorp.Authentication
{
    /// <summary>
    /// Kubernetes-based authentication for HashiCorp Vault.
    /// Uses the service account token mounted by Kubernetes.
    /// </summary>
    public class KubernetesAuthMethod : IVaultAuthMethod
    {
        /// <summary>
        /// Default path where Kubernetes mounts the service account token.
        /// </summary>
        public const string DefaultTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token";

        private readonly string _roleName;
        private readonly string _jwt;
        private readonly string _mountPoint;

        /// <summary>
        /// Creates a new instance using explicit JWT token.
        /// </summary>
        /// <param name="roleName">The Vault role name configured for Kubernetes auth.</param>
        /// <param name="jwt">The JWT token (service account token).</param>
        /// <param name="mountPoint">The mount point for Kubernetes auth. Defaults to "kubernetes".</param>
        public KubernetesAuthMethod(string roleName, string jwt, string mountPoint = "kubernetes")
        {
            if (string.IsNullOrWhiteSpace(roleName))
                throw new ArgumentException("Role name cannot be null or empty.", nameof(roleName));
            if (string.IsNullOrWhiteSpace(jwt))
                throw new ArgumentException("JWT cannot be null or empty.", nameof(jwt));

            _roleName = roleName;
            _jwt = jwt;
            _mountPoint = mountPoint;
        }

        /// <summary>
        /// Creates a new instance by reading the JWT from a file (typically the Kubernetes service account token).
        /// </summary>
        /// <param name="roleName">The Vault role name configured for Kubernetes auth.</param>
        /// <param name="tokenPath">Path to the JWT token file. Defaults to the Kubernetes service account token path.</param>
        /// <param name="mountPoint">The mount point for Kubernetes auth. Defaults to "kubernetes".</param>
        /// <returns>A new KubernetesAuthMethod instance.</returns>
        /// <exception cref="FileNotFoundException">Thrown when the token file does not exist.</exception>
        public static KubernetesAuthMethod FromFile(
            string roleName,
            string tokenPath = DefaultTokenPath,
            string mountPoint = "kubernetes")
        {
            if (!File.Exists(tokenPath))
                throw new FileNotFoundException($"Kubernetes service account token not found at: {tokenPath}", tokenPath);

            var jwt = File.ReadAllText(tokenPath).Trim();
            return new KubernetesAuthMethod(roleName, jwt, mountPoint);
        }

        /// <summary>
        /// Tries to create a new instance by reading the JWT from a file.
        /// </summary>
        /// <param name="roleName">The Vault role name configured for Kubernetes auth.</param>
        /// <param name="authMethod">The created auth method, or null if the token file doesn't exist.</param>
        /// <param name="tokenPath">Path to the JWT token file. Defaults to the Kubernetes service account token path.</param>
        /// <param name="mountPoint">The mount point for Kubernetes auth. Defaults to "kubernetes".</param>
        /// <returns>True if successful, false otherwise.</returns>
        public static bool TryFromFile(
            string roleName,
            out KubernetesAuthMethod? authMethod,
            string tokenPath = DefaultTokenPath,
            string mountPoint = "kubernetes")
        {
            if (string.IsNullOrWhiteSpace(roleName) || !File.Exists(tokenPath))
            {
                authMethod = null;
                return false;
            }

            try
            {
                var jwt = File.ReadAllText(tokenPath).Trim();
                if (string.IsNullOrWhiteSpace(jwt))
                {
                    authMethod = null;
                    return false;
                }

                authMethod = new KubernetesAuthMethod(roleName, jwt, mountPoint);
                return true;
            }
            catch
            {
                authMethod = null;
                return false;
            }
        }

        /// <summary>
        /// Checks if running in a Kubernetes environment by checking for the service account token.
        /// </summary>
        /// <returns>True if running in Kubernetes, false otherwise.</returns>
        public static bool IsRunningInKubernetes()
        {
            return File.Exists(DefaultTokenPath);
        }

        /// <inheritdoc />
        public IAuthMethodInfo GetAuthMethodInfo()
        {
            return new KubernetesAuthMethodInfo(_mountPoint, _roleName, _jwt);
        }
    }
}
