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
        /// Gets the secret URI that could not be resolved, with the secret name masked.
        /// </summary>
        /// <remarks>
        /// The secret name is removed deliberately. This exception surfaces out of
        /// <see cref="Microsoft.Extensions.Configuration.IConfigurationBuilder.Build"/> during
        /// startup, so it reaches crash dumps, developer error pages and APM sinks - several of
        /// which serialize exception properties by reflection. The vault host is retained, since
        /// identifying which vault failed is the point of the exception; the inventory of secret
        /// names inside it is not.
        /// </remarks>
        public string SecretUri { get; }

        /// <summary>
        /// Creates a new instance of <see cref="KeyVaultReferenceResolutionException"/>.
        /// </summary>
        /// <param name="message">The error message.</param>
        /// <param name="configurationKey">The configuration key that failed.</param>
        /// <param name="secretUri">The secret URI that could not be resolved. Stored masked.</param>
        /// <param name="innerException">The inner exception.</param>
        public KeyVaultReferenceResolutionException(
            string message,
            string configurationKey,
            string secretUri,
            Exception? innerException = null)
            : base(message, innerException)
        {
            ConfigurationKey = configurationKey;
            SecretUri = MaskSecretUri(secretUri);
        }

        /// <summary>
        /// Creates a new instance of <see cref="KeyVaultReferenceResolutionException"/>.
        /// </summary>
        /// <param name="message">The error message.</param>
        public KeyVaultReferenceResolutionException(string message)
            : this(message, string.Empty, string.Empty)
        {
        }

        /// <summary>
        /// Creates a new instance of <see cref="KeyVaultReferenceResolutionException"/>.
        /// </summary>
        /// <param name="message">The error message.</param>
        /// <param name="innerException">The inner exception.</param>
        public KeyVaultReferenceResolutionException(string message, Exception? innerException)
            : this(message, string.Empty, string.Empty, innerException)
        {
        }

        /// <summary>
        /// Replaces the secret name and version in a Key Vault secret URI with <c>***</c>,
        /// keeping the scheme and host.
        /// </summary>
        /// <param name="secretUri">The secret URI to mask.</param>
        /// <returns>The masked URI, or <c>***</c> if it cannot be parsed.</returns>
        public static string MaskSecretUri(string? secretUri)
        {
            if (string.IsNullOrWhiteSpace(secretUri))
                return string.Empty;

            return Uri.TryCreate(secretUri, UriKind.Absolute, out var parsed)
                ? $"{parsed.Scheme}://{parsed.Host}/secrets/***"
                : "***";
        }
    }
}
