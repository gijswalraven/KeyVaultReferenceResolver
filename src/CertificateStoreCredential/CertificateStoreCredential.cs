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
        private readonly object _gate = new object();
        private int _active;
        private bool _disposeRequested;

        private CertificateStoreCredential(X509Certificate2 certificate, ClientCertificateCredential inner, string thumbprint)
        {
            _certificate = certificate;
            _inner = inner;
            Thumbprint = thumbprint;
        }

        /// <summary>
        /// Creates the credential for the certificate that <paramref name="options"/> names. The certificate is required.
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
            Enter();
            try
            {
                return _inner.GetToken(requestContext, cancellationToken);
            }
            finally
            {
                Exit();
            }
        }

        /// <inheritdoc />
        public override async ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
            Enter();
            try
            {
                return await _inner.GetTokenAsync(requestContext, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                Exit();
            }
        }

        /// <summary>
        /// Releases the loaded certificate. Safe to call more than once. The credential cannot be used
        /// afterwards. A token request already in progress finishes first: the certificate is released
        /// when the last such request completes, so a shutdown does not make it sign with a disposed
        /// certificate.
        /// </summary>
        public void Dispose()
        {
            bool releaseNow;
            lock (_gate)
            {
                if (_disposeRequested)
                    return;

                _disposeRequested = true;
                releaseNow = _active == 0;
            }

            if (releaseNow)
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

            return CreateFromCertificate(settings, certificate, credentialOptions);
        }

        /// <summary>Builds the credential around a validated certificate, which it takes ownership of.</summary>
        private static CertificateStoreCredential CreateFromCertificate(
            CertificateStoreCredentialOptions settings,
            X509Certificate2 certificate,
            ClientCertificateCredentialOptions? credentialOptions)
        {
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

        /// <summary>Marks a use of the certificate, which defers its release; the test seam of <see cref="GetToken"/>.</summary>
        internal void Enter()
        {
            lock (_gate)
            {
                if (_disposeRequested)
                    throw new ObjectDisposedException(nameof(CertificateStoreCredential));

                _active++;
            }
        }

        internal void Exit()
        {
            bool releaseNow;
            lock (_gate)
            {
                _active--;
                releaseNow = _disposeRequested && _active == 0;
            }

            if (releaseNow)
                _certificate.Dispose();
        }
    }
}
