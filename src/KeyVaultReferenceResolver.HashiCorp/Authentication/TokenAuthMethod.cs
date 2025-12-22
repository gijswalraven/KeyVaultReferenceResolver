using System;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.AuthMethods.Token;

namespace KeyVaultReferenceResolver.HashiCorp.Authentication
{
    /// <summary>
    /// Token-based authentication for HashiCorp Vault.
    /// </summary>
    public class TokenAuthMethod : IVaultAuthMethod
    {
        private readonly string _token;

        /// <summary>
        /// Creates a new instance using an explicit token.
        /// </summary>
        /// <param name="token">The Vault token.</param>
        public TokenAuthMethod(string token)
        {
            if (string.IsNullOrWhiteSpace(token))
                throw new ArgumentException("Token cannot be null or empty.", nameof(token));

            _token = token;
        }

        /// <summary>
        /// Creates a new instance using the VAULT_TOKEN environment variable.
        /// </summary>
        /// <returns>A new TokenAuthMethod instance.</returns>
        /// <exception cref="InvalidOperationException">Thrown when VAULT_TOKEN is not set.</exception>
        public static TokenAuthMethod FromEnvironment()
        {
            var token = Environment.GetEnvironmentVariable("VAULT_TOKEN");
            if (string.IsNullOrWhiteSpace(token))
                throw new InvalidOperationException("VAULT_TOKEN environment variable is not set.");

            return new TokenAuthMethod(token);
        }

        /// <summary>
        /// Tries to create a new instance using the VAULT_TOKEN environment variable.
        /// </summary>
        /// <param name="authMethod">The created auth method, or null if VAULT_TOKEN is not set.</param>
        /// <returns>True if successful, false otherwise.</returns>
        public static bool TryFromEnvironment(out TokenAuthMethod? authMethod)
        {
            var token = Environment.GetEnvironmentVariable("VAULT_TOKEN");
            if (string.IsNullOrWhiteSpace(token))
            {
                authMethod = null;
                return false;
            }

            authMethod = new TokenAuthMethod(token);
            return true;
        }

        /// <inheritdoc />
        public IAuthMethodInfo GetAuthMethodInfo()
        {
            return new TokenAuthMethodInfo(_token);
        }
    }
}
