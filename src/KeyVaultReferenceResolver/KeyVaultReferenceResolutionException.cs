using System;

namespace KeyVaultReferenceResolver
{
    /// <summary>
    /// Exception thrown when a Key Vault reference cannot be resolved.
    /// </summary>
    public class KeyVaultReferenceResolutionException : Exception
    {
        /// <summary>
        /// Gets the configuration key that failed to resolve.
        /// </summary>
        public string ConfigurationKey { get; }

        /// <summary>
        /// Gets the secret URI that could not be resolved.
        /// </summary>
        public string SecretUri { get; }

        /// <summary>
        /// Creates a new instance of <see cref="KeyVaultReferenceResolutionException"/>.
        /// </summary>
        /// <param name="message">The error message.</param>
        /// <param name="configurationKey">The configuration key that failed.</param>
        /// <param name="secretUri">The secret URI that could not be resolved.</param>
        /// <param name="innerException">The inner exception.</param>
        public KeyVaultReferenceResolutionException(
            string message,
            string configurationKey,
            string secretUri,
            Exception? innerException = null)
            : base(message, innerException)
        {
            ConfigurationKey = configurationKey;
            SecretUri = secretUri;
        }
    }
}
