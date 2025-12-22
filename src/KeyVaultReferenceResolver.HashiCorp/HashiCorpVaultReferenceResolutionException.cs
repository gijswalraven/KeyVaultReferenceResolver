using System;

namespace KeyVaultReferenceResolver.HashiCorp
{
    /// <summary>
    /// Exception thrown when a HashiCorp Vault reference cannot be resolved.
    /// </summary>
    public class HashiCorpVaultReferenceResolutionException : Exception
    {
        /// <summary>
        /// Gets the configuration key that failed to resolve.
        /// </summary>
        public string ConfigurationKey { get; }

        /// <summary>
        /// Gets the vault reference that could not be resolved.
        /// </summary>
        public string VaultReference { get; }

        /// <summary>
        /// Creates a new instance of <see cref="HashiCorpVaultReferenceResolutionException"/>.
        /// </summary>
        /// <param name="message">The error message.</param>
        /// <param name="configurationKey">The configuration key that failed.</param>
        /// <param name="vaultReference">The vault reference that could not be resolved.</param>
        /// <param name="innerException">The inner exception.</param>
        public HashiCorpVaultReferenceResolutionException(
            string message,
            string configurationKey,
            string vaultReference,
            Exception? innerException = null)
            : base(message, innerException)
        {
            ConfigurationKey = configurationKey;
            VaultReference = vaultReference;
        }
    }
}
