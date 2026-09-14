using System;
using System.Diagnostics.CodeAnalysis;
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
        private readonly string? _tokenPath;
        private readonly string _mountPoint;

        /// <summary>
        /// Creates a new instance using explicit JWT token.
        /// </summary>
        /// <param name="roleName">The Vault role name configured for Kubernetes auth.</param>
        /// <param name="jwt">The JWT token (service account token).</param>
        /// <param name="mountPoint">The mount point for Kubernetes auth. Defaults to "kubernetes".</param>
        /// <remarks>
        /// The JWT supplied here is used as-is for the lifetime of this instance. Prefer
        /// <see cref="FromFile"/> in Kubernetes, so that the rotated service account token is picked
        /// up on each login rather than a stale copy being reused.
        /// </remarks>
        public KubernetesAuthMethod(string roleName, string jwt, string mountPoint = "kubernetes")
        {
            if (string.IsNullOrWhiteSpace(roleName))
                throw new ArgumentException("Role name cannot be null or empty.", nameof(roleName));
            if (string.IsNullOrWhiteSpace(jwt))
                throw new ArgumentException("JWT cannot be null or empty.", nameof(jwt));

            _roleName = roleName;
            _jwt = jwt;
            _tokenPath = null;
            _mountPoint = mountPoint;
        }

        private KubernetesAuthMethod(string roleName, string jwt, string tokenPath, string mountPoint)
        {
            _roleName = roleName;
            _jwt = jwt;
            _tokenPath = tokenPath;
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
            if (string.IsNullOrWhiteSpace(roleName))
                throw new ArgumentException("Role name cannot be null or empty.", nameof(roleName));
            if (!File.Exists(tokenPath))
                throw new FileNotFoundException($"Kubernetes service account token not found at: {tokenPath}", tokenPath);

            var jwt = File.ReadAllText(tokenPath).Trim();
            if (string.IsNullOrWhiteSpace(jwt))
                throw new InvalidOperationException($"Kubernetes service account token at '{tokenPath}' is empty.");

            return new KubernetesAuthMethod(roleName, jwt, tokenPath, mountPoint);
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
            [NotNullWhen(true)] out KubernetesAuthMethod? authMethod,
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

                authMethod = new KubernetesAuthMethod(roleName, jwt, tokenPath, mountPoint);
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
        /// <remarks>
        /// When this instance was created from a token file, the file is re-read on every call.
        /// Kubernetes rotates projected service account tokens at roughly 80% of their lifetime, so
        /// a JWT captured once would become a stale credential and later logins would fail.
        /// </remarks>
        public IAuthMethodInfo GetAuthMethodInfo()
        {
            return new KubernetesAuthMethodInfo(_mountPoint, _roleName, ReadCurrentJwt());
        }

        private string ReadCurrentJwt()
        {
            if (_tokenPath == null)
                return _jwt;

            try
            {
                var jwt = File.ReadAllText(_tokenPath).Trim();
                if (!string.IsNullOrWhiteSpace(jwt))
                    return jwt;
            }
            catch (IOException)
            {
                // Fall through to the last known good token.
            }
            catch (UnauthorizedAccessException)
            {
                // Fall through to the last known good token.
            }

            return _jwt;
        }
    }
}
