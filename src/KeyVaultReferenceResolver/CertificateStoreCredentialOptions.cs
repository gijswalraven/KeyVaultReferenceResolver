using System;
using System.Security.Cryptography.X509Certificates;
using X509StoreLocation = System.Security.Cryptography.X509Certificates.StoreLocation;

namespace KeyVaultReferenceResolver
{
    /// <summary>
    /// Identifies a client certificate in the certificate store that an Entra service principal
    /// authenticates with. Set on <see cref="KeyVaultReferenceResolverOptions.ClientCertificate"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The certificate is looked up in the <c>My</c> (personal) store, either by thumbprint or, when
    /// no thumbprint is given, by the client ID: the certificate whose subject or friendly name
    /// contains the client ID. Its private key stays in the store, so it can be non-exportable:
    /// nothing is read from or written to disk. This is the case <c>EnvironmentCredential</c> cannot
    /// serve, because it only reads a certificate from a file (<c>AZURE_CLIENT_CERTIFICATE_PATH</c>).
    /// </para>
    /// <para>
    /// The values are identifiers, not secrets. They are still validated and normalised here so
    /// that a thumbprint copied out of the Certificates MMC snap-in works as pasted.
    /// </para>
    /// <para>
    /// Unlike the environment convention, which silently does nothing when no certificate matches,
    /// naming the certificate here means it is required: a missing, key-less or expired certificate
    /// throws <see cref="InvalidOperationException"/> when the resolver is created.
    /// </para>
    /// </remarks>
    public sealed class CertificateStoreCredentialOptions
    {
        /// <summary>
        /// Creates the settings for a store certificate identified by thumbprint.
        /// </summary>
        /// <param name="tenantId">The Entra tenant (directory) ID the service principal lives in.</param>
        /// <param name="clientId">The application (client) ID of the service principal.</param>
        /// <param name="thumbprint">
        /// The certificate thumbprint. Spaces, colons, hyphens and invisible characters (such as the
        /// U+200E that the Certificates snap-in adds when copying) are removed and the value is
        /// upper-cased.
        /// </param>
        /// <param name="storeLocation">The store location to search. Default is <see cref="X509StoreLocation.CurrentUser"/>.</param>
        /// <exception cref="ArgumentException">A value is empty, or the thumbprint is not hexadecimal.</exception>
        public CertificateStoreCredentialOptions(
            string tenantId,
            string clientId,
            string thumbprint,
            StoreLocation storeLocation = X509StoreLocation.CurrentUser)
            : this(tenantId, clientId, (StoreLocation?)storeLocation, NormalizeRequired(thumbprint))
        {
        }

        /// <summary>
        /// Creates the settings for the store certificate named after the client ID, searching
        /// <c>CurrentUser\My</c> and then <c>LocalMachine\My</c>.
        /// </summary>
        /// <param name="tenantId">The Entra tenant (directory) ID the service principal lives in.</param>
        /// <param name="clientId">
        /// The application (client) ID. The certificate is the one whose subject or friendly name
        /// contains it, case-insensitively. Among several, a valid one with a private key wins, then the
        /// one that expires last, so a renewed certificate is picked up without a change here.
        /// </param>
        /// <exception cref="ArgumentException">A value is empty.</exception>
        public CertificateStoreCredentialOptions(string tenantId, string clientId)
            : this(tenantId, clientId, null, null)
        {
        }

        /// <summary>
        /// Creates the settings for the store certificate named after the client ID, searching one
        /// store location only.
        /// </summary>
        /// <param name="tenantId">The Entra tenant (directory) ID the service principal lives in.</param>
        /// <param name="clientId">The application (client) ID; see <see cref="CertificateStoreCredentialOptions(string, string)"/>.</param>
        /// <param name="storeLocation">The store location to search.</param>
        /// <exception cref="ArgumentException">A value is empty.</exception>
        public CertificateStoreCredentialOptions(string tenantId, string clientId, StoreLocation storeLocation)
            : this(tenantId, clientId, storeLocation, null)
        {
        }

        private CertificateStoreCredentialOptions(string tenantId, string clientId, StoreLocation? storeLocation, string? thumbprint)
        {
            if (string.IsNullOrWhiteSpace(tenantId))
                throw new ArgumentException("A tenant ID is required.", nameof(tenantId));
            if (string.IsNullOrWhiteSpace(clientId))
                throw new ArgumentException("A client ID is required.", nameof(clientId));

            TenantId = tenantId.Trim();
            ClientId = clientId.Trim();
            Thumbprint = thumbprint;
            StoreLocation = storeLocation;
        }

        private static string NormalizeRequired(string thumbprint)
        {
            if (thumbprint == null)
                throw new ArgumentNullException(nameof(thumbprint));

            var normalized = CertificateStoreLoader.NormalizeThumbprint(thumbprint);
            if (normalized.Length == 0)
                throw new ArgumentException("A certificate thumbprint is required.", nameof(thumbprint));
            if (!CertificateStoreLoader.IsHex(normalized))
                throw new ArgumentException("The certificate thumbprint must be hexadecimal.", nameof(thumbprint));

            return normalized;
        }

        /// <summary>Gets the Entra tenant (directory) ID.</summary>
        public string TenantId { get; }

        /// <summary>Gets the application (client) ID of the service principal.</summary>
        public string ClientId { get; }

        /// <summary>
        /// Gets the normalised thumbprint (upper-case hexadecimal, no separators), or <c>null</c> when
        /// the certificate is to be found by <see cref="ClientId"/>.
        /// </summary>
        public string? Thumbprint { get; }

        /// <summary>
        /// Gets the store location searched, or <c>null</c> to search <c>CurrentUser</c> and then
        /// <c>LocalMachine</c> (only when no <see cref="Thumbprint"/> is given).
        /// </summary>
        public StoreLocation? StoreLocation { get; }
    }
}
