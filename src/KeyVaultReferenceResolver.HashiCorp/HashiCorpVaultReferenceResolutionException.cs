using System;
using System.Text.RegularExpressions;

namespace KeyVaultReferenceResolver.HashiCorp
{
    /// <summary>
    /// Exception thrown when a HashiCorp Vault reference cannot be resolved.
    /// </summary>
    public class HashiCorpVaultReferenceResolutionException : Exception
    {
        private static readonly TimeSpan RegexTimeout = TimeSpan.FromSeconds(1);

        private static readonly Regex AttributeAddress = new Regex(
            @"@HashiCorp\.Vault\(VaultAddress=(?<addr>[^;)]+);",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);

        private static readonly Regex UriHost = new Regex(
            @"^hashicorp://(?<host>[^/]+)/",
            RegexOptions.IgnoreCase | RegexOptions.Compiled,
            RegexTimeout);

        /// <summary>
        /// Gets the configuration key that failed to resolve.
        /// </summary>
        public string ConfigurationKey { get; }

        /// <summary>
        /// Gets the vault reference that could not be resolved, with the secret path and key masked.
        /// </summary>
        /// <remarks>
        /// The path and key are removed deliberately. The reference is taken verbatim from a
        /// configuration value, so a compound value - a connection string with an inline password
        /// alongside an embedded reference, for example - would otherwise be captured whole into a
        /// public property that APM sinks serialize by reflection. The vault address is retained so
        /// the failure can still be attributed.
        /// </remarks>
        public string VaultReference { get; }

        /// <summary>
        /// Creates a new instance of <see cref="HashiCorpVaultReferenceResolutionException"/>.
        /// </summary>
        /// <param name="message">The error message.</param>
        /// <param name="configurationKey">The configuration key that failed.</param>
        /// <param name="vaultReference">The vault reference that could not be resolved. Stored masked.</param>
        /// <param name="innerException">The inner exception.</param>
        public HashiCorpVaultReferenceResolutionException(
            string message,
            string configurationKey,
            string vaultReference,
            Exception? innerException = null)
            : base(message, innerException)
        {
            ConfigurationKey = configurationKey;
            VaultReference = MaskVaultReference(vaultReference);
        }

        /// <summary>
        /// Creates a new instance of <see cref="HashiCorpVaultReferenceResolutionException"/>.
        /// </summary>
        /// <param name="message">The error message.</param>
        public HashiCorpVaultReferenceResolutionException(string message)
            : this(message, string.Empty, string.Empty)
        {
        }

        /// <summary>
        /// Creates a new instance of <see cref="HashiCorpVaultReferenceResolutionException"/>.
        /// </summary>
        /// <param name="message">The error message.</param>
        /// <param name="innerException">The inner exception.</param>
        public HashiCorpVaultReferenceResolutionException(string message, Exception? innerException)
            : this(message, string.Empty, string.Empty, innerException)
        {
        }

        /// <summary>
        /// Replaces the secret path and key in a HashiCorp Vault reference with <c>***</c>,
        /// keeping the vault address.
        /// </summary>
        /// <param name="vaultReference">The reference to mask.</param>
        /// <returns>The masked reference, or <c>***</c> if no known reference shape is found.</returns>
        public static string MaskVaultReference(string? vaultReference)
        {
            if (string.IsNullOrWhiteSpace(vaultReference))
                return string.Empty;

            try
            {
                var attrMatch = AttributeAddress.Match(vaultReference);
                if (attrMatch.Success)
                    return $"@HashiCorp.Vault(VaultAddress={attrMatch.Groups["addr"].Value};SecretPath=***;SecretKey=***)";

                var uriMatch = UriHost.Match(vaultReference);
                if (uriMatch.Success)
                    return $"hashicorp://{uriMatch.Groups["host"].Value}/***#***";
            }
            catch (RegexMatchTimeoutException)
            {
                // Fall through: an unparseable value is masked entirely.
            }

            return "***";
        }
    }
}
