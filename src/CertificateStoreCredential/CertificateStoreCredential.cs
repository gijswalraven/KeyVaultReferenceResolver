using System;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Azure.Core;
using Azure.Identity;

namespace CertificateStoreCredentials
{
    /// <summary>
    /// A <see cref="TokenCredential"/> that authenticates as an Entra service principal with a client
    /// certificate from the Windows certificate store, whose private key may be non-exportable.
    /// </summary>
    /// <remarks>
    /// <para>
    /// It can supply a token for any Azure resource that accepts an Entra token, for example Key Vault
    /// or an access token for Azure SQL (scope <c>https://database.windows.net/.default</c>) in a custom
    /// authentication provider. It depends on no client library, only on Azure.Identity.
    /// </para>
    /// <para>
    /// The instance owns the loaded <see cref="X509Certificate2"/> and wraps one
    /// <see cref="ClientCertificateCredential"/>, so there is a single object and a single
    /// <see cref="Dispose"/>. Tokens are cached by the wrapped credential; nothing is cached here. Create
    /// one instance and keep it for the lifetime of the application rather than one per call, which would
    /// discard the token cache.
    /// </para>
    /// <para>
    /// The certificate is found and validated when the instance is created, not on the first token
    /// request, so a missing, key-less or expired certificate fails at startup with a clear message.
    /// </para>
    /// </remarks>
    public sealed class CertificateStoreCredential : TokenCredential, IDisposable
    {
        private readonly X509Certificate2 _certificate;
        private readonly ClientCertificateCredential _inner;
        private int _disposed;

        private CertificateStoreCredential(X509Certificate2 certificate, ClientCertificateCredential inner, string thumbprint)
        {
            _certificate = certificate;
            _inner = inner;
            Thumbprint = thumbprint;
        }

        /// <summary>
        /// Creates the credential the environment convention names, or <c>null</c> when the convention
        /// does not apply.
        /// </summary>
        /// <returns>
        /// <c>null</c> when <c>AZURE_TENANT_ID</c> or <c>AZURE_CLIENT_ID</c> is missing, when none of the
        /// <c>CurrentUser\My</c> or <c>LocalMachine\My</c> certificates names the client ID in its subject or
        /// friendly name, or when <c>AZURE_CLIENT_SECRET</c>, <c>AZURE_CLIENT_CERTIFICATE_PATH</c> or
        /// <c>AZURE_FEDERATED_TOKEN_FILE</c> is set. These are the rules
        /// <c>AddKeyVaultReferenceResolver</c> applies.
        /// </returns>
        /// <exception cref="InvalidOperationException">
        /// A certificate names the client ID but is unusable: expired, not yet valid, or without an
        /// accessible private key. It is not treated as "convention does not apply", so a broken setup is
        /// not mistaken for an unconfigured one.
        /// </exception>
        public static CertificateStoreCredential? TryCreateFromEnvironment()
        {
            return TryCreateFromEnvironment((ClientCertificateCredentialOptions?)null);
        }

        /// <summary>
        /// The same as <see cref="TryCreateFromEnvironment()"/>, with options for the wrapped
        /// <see cref="ClientCertificateCredential"/>.
        /// </summary>
        /// <param name="credentialOptions">
        /// Authority host, additionally allowed tenants and retry behaviour, or <c>null</c> for the Azure
        /// Identity defaults (which include the <c>AZURE_AUTHORITY_HOST</c> environment variable).
        /// </param>
        /// <inheritdoc cref="TryCreateFromEnvironment()" path="/returns"/>
        /// <inheritdoc cref="TryCreateFromEnvironment()" path="/exception"/>
        public static CertificateStoreCredential? TryCreateFromEnvironment(ClientCertificateCredentialOptions? credentialOptions)
        {
            return TryCreateFromEnvironment(
                Environment.GetEnvironmentVariable, CertificateStoreLoader.ReadStore, DateTimeOffset.UtcNow, credentialOptions);
        }

        /// <summary>
        /// Creates the credential for the certificate that <paramref name="options"/> names. Unlike
        /// <see cref="TryCreateFromEnvironment()"/> the certificate is required.
        /// </summary>
        /// <param name="options">Identifies the service principal and the certificate.</param>
        /// <exception cref="ArgumentNullException"><paramref name="options"/> is <c>null</c>.</exception>
        /// <exception cref="InvalidOperationException">
        /// The certificate is not in the store, has no accessible private key, has expired, or is not yet valid.
        /// </exception>
        public static CertificateStoreCredential Create(CertificateStoreCredentialOptions options)
        {
            return Create(options, null);
        }

        /// <summary>
        /// The same as <see cref="Create(CertificateStoreCredentialOptions)"/>, with options for the
        /// wrapped <see cref="ClientCertificateCredential"/>.
        /// </summary>
        /// <param name="options">Identifies the service principal and the certificate.</param>
        /// <param name="credentialOptions">
        /// Authority host, additionally allowed tenants and retry behaviour, or <c>null</c> for the Azure
        /// Identity defaults.
        /// </param>
        /// <exception cref="ArgumentNullException"><paramref name="options"/> is <c>null</c>.</exception>
        /// <exception cref="InvalidOperationException">
        /// The certificate is not in the store, has no accessible private key, has expired, or is not yet valid.
        /// </exception>
        public static CertificateStoreCredential Create(
            CertificateStoreCredentialOptions options,
            ClientCertificateCredentialOptions? credentialOptions)
        {
            if (options == null)
                throw new ArgumentNullException(nameof(options));

            return CreateFrom(options, credentialOptions, null, DateTimeOffset.UtcNow);
        }

        /// <inheritdoc />
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();
            return _inner.GetToken(requestContext, cancellationToken);
        }

        /// <inheritdoc />
        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();
            return _inner.GetTokenAsync(requestContext, cancellationToken);
        }

        /// <summary>
        /// Releases the loaded certificate. Safe to call more than once. The credential cannot be used
        /// afterwards.
        /// </summary>
        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0)
                _certificate.Dispose();
        }

        /// <summary>
        /// Gets the thumbprint of the certificate in use, for diagnostics such as logging which certificate was
        /// picked. Not a secret. Still readable after <see cref="Dispose"/>.
        /// </summary>
        public string Thumbprint { get; }

        /// <summary>The loaded certificate, for tests that assert on ownership.</summary>
        internal X509Certificate2 Certificate => _certificate;

        /// <summary>
        /// Test seam: the convention with the environment and the stores supplied.
        /// </summary>
        internal static CertificateStoreCredential? TryCreateFromEnvironment(
            Func<string, string?> getVariable,
            Func<StoreLocation, X509Certificate2Collection> candidatesFor,
            DateTimeOffset now,
            ClientCertificateCredentialOptions? credentialOptions = null)
        {
            var settings = CertificateStoreLoader.FromEnvironment(getVariable, candidatesFor, now);
            return settings == null
                ? null
                : CreateFrom(settings, credentialOptions, candidatesFor, now);
        }

        /// <summary>
        /// The one path that loads the certificate and builds the credential, behind every public
        /// factory. <paramref name="candidatesFor"/> is <c>null</c> in production, which reads the
        /// real store.
        /// </summary>
        internal static CertificateStoreCredential CreateFrom(
            CertificateStoreCredentialOptions settings,
            ClientCertificateCredentialOptions? credentialOptions,
            Func<StoreLocation, X509Certificate2Collection>? candidatesFor,
            DateTimeOffset now)
        {
            var certificate = candidatesFor == null
                ? CertificateStoreLoader.Load(settings)
                : CertificateStoreLoader.LoadFrom(settings, candidatesFor, now);

            try
            {
                var inner = CertificateStoreLoader.CreateCredential(settings, certificate, credentialOptions);
                return new CertificateStoreCredential(certificate, inner, certificate.Thumbprint);
            }
            catch
            {
                certificate.Dispose();
                throw;
            }
        }

        private void ThrowIfDisposed()
        {
            if (Volatile.Read(ref _disposed) != 0)
                throw new ObjectDisposedException(nameof(CertificateStoreCredential));
        }
    }
}
