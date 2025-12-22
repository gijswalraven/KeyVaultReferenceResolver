using VaultSharp.V1.AuthMethods;

namespace KeyVaultReferenceResolver.HashiCorp.Authentication
{
    /// <summary>
    /// Interface for HashiCorp Vault authentication methods.
    /// </summary>
    public interface IVaultAuthMethod
    {
        /// <summary>
        /// Gets the VaultSharp authentication method info.
        /// </summary>
        /// <returns>The authentication method info for VaultSharp client.</returns>
        IAuthMethodInfo GetAuthMethodInfo();
    }
}
