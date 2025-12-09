using System.Threading;
using System.Threading.Tasks;

namespace KeyVaultReferenceResolver
{
    /// <summary>
    /// Interface for resolving secrets from Azure Key Vault.
    /// </summary>
    public interface ISecretResolver
    {
        /// <summary>
        /// Resolves a secret from the given Key Vault secret URI.
        /// </summary>
        /// <param name="secretUri">The full URI to the secret (e.g., https://vault.vault.azure.net/secrets/secret-name)</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>The secret value.</returns>
        Task<string> ResolveSecretAsync(string secretUri, CancellationToken cancellationToken = default);

        /// <summary>
        /// Resolves a secret from the given Key Vault secret URI synchronously.
        /// </summary>
        /// <param name="secretUri">The full URI to the secret.</param>
        /// <returns>The secret value.</returns>
        string ResolveSecret(string secretUri);
    }
}
