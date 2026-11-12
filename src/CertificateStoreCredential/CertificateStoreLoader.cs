using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Azure.Identity;

namespace CertificateStoreCredentials
{
    /// <summary>
    /// Finds and validates the client certificate named by
    /// <see cref="CertificateStoreCredentialOptions"/> and builds the credential from it.
    /// </summary>
    /// <remarks>
    /// Split into <see cref="Select"/> (pure, takes the candidates) and <see cref="Load"/> (opens
    /// the store) so the validation rules can be tested with in-memory certificates, without
    /// touching the machine's certificate store.
    /// </remarks>
    internal static class CertificateStoreLoader
    {
        /// <summary>
        /// Tolerance for a certificate whose NotBefore is a moment ahead of this machine's clock,
        /// such as one issued seconds ago on a host with slight drift.
        /// </summary>
        private static readonly TimeSpan ClockSkew = TimeSpan.FromMinutes(5);

        /// <summary>
        /// Removes whitespace, colons, hyphens and invisible characters, and upper-cases.
        /// </summary>
        /// <remarks>
        /// "Invisible" is the Unicode Format and Control categories. That covers U+200E (left-to-right
        /// mark), which the Certificates snap-in prepends when a thumbprint is copied from it, along
        /// with its siblings (U+200F, U+200B, U+FEFF, ...).
        /// </remarks>
        internal static string NormalizeThumbprint(string thumbprint)
        {
            var builder = new StringBuilder(thumbprint.Length);
            foreach (var c in thumbprint)
            {
                if (char.IsWhiteSpace(c) || c == ':' || c == '-')
                    continue;

                var category = CharUnicodeInfo.GetUnicodeCategory(c);
                if (category == UnicodeCategory.Format || category == UnicodeCategory.Control)
                    continue;

                builder.Append(char.ToUpperInvariant(c));
            }

            return builder.ToString();
        }

        /// <summary>A certificate picked from a store, with the settings that name it. The holder owns the certificate.</summary>
        internal sealed class Match
        {
            public Match(CertificateStoreCredentialOptions settings, X509Certificate2 certificate, bool keyUsable)
            {
                Settings = settings;
                Certificate = certificate;
                KeyUsable = keyUsable;
            }

            /// <summary>
            /// Whether the private key was opened successfully during the search, so validating the match
            /// does not open it (and perhaps prompt for a PIN) again.
            /// </summary>
            public bool KeyUsable { get; }

            public CertificateStoreCredentialOptions Settings { get; }

            public X509Certificate2 Certificate { get; }
        }

        /// <summary>
        /// Searches the given store locations, in order, for the certificate that names
        /// <paramref name="clientId"/>. Returns it with settings carrying its thumbprint, or <c>null</c>.
        /// The caller owns the returned certificate; every other one read is disposed.
        /// </summary>
        private static Match? FindByClientId(
            string tenantId,
            string clientId,
            StoreLocation[] locations,
            Func<StoreLocation, X509Certificate2Collection> candidatesFor,
            DateTimeOffset now)
        {
            // The best unusable match, used only when no location holds a usable one, so that Load
            // fails with the specific reason rather than falling back to the default chain.
            Match? fallback = null;

            try
            {
                foreach (var location in locations)
                {
                    var all = candidatesFor(location).Cast<X509Certificate2>().ToList();
                    X509Certificate2? kept = null;
                    try
                    {
                        // The key is opened once per matching certificate, here; the result travels with the match.
                        var matches = all
                            .Where(c => Names(c, clientId))
                            .Select(c => new { Certificate = c, KeyUsable = HasUsablePrivateKey(c) })
                            .ToList();

                        var usable = matches
                            .Where(m => m.KeyUsable && IsWithinValidity(m.Certificate, now))
                            .OrderByDescending(m => m.Certificate.NotAfter)
                            .FirstOrDefault();

                        if (usable != null)
                        {
                            var settings = new CertificateStoreCredentialOptions(
                                tenantId, clientId, usable.Certificate.Thumbprint, location);
                            kept = usable.Certificate;
                            return new Match(settings, usable.Certificate, keyUsable: true);
                        }

                        if (fallback == null)
                        {
                            var best = matches.OrderByDescending(m => m.Certificate.NotAfter).FirstOrDefault();
                            if (best != null)
                            {
                                var settings = new CertificateStoreCredentialOptions(
                                    tenantId, clientId, best.Certificate.Thumbprint, location);
                                kept = best.Certificate;
                                fallback = new Match(settings, best.Certificate, best.KeyUsable);
                            }
                        }
                    }
                    finally
                    {
                        foreach (var certificate in all)
                        {
                            if (!ReferenceEquals(certificate, kept))
                                certificate.Dispose();
                        }
                    }
                }

                var result = fallback;
                fallback = null;
                return result;
            }
            finally
            {
                // Reached with a fallback still held when a usable match returned from a later
                // location (or on an exception): it is not the one handed out.
                fallback?.Certificate.Dispose();
            }
        }

        /// <summary>
        /// Turns settings without a thumbprint into settings with one, by finding the certificate that
        /// names the client ID. Settings that already carry a thumbprint are returned unchanged.
        /// </summary>
        /// <exception cref="InvalidOperationException">No certificate in the searched stores names the client ID.</exception>
        internal static CertificateStoreCredentialOptions Resolve(
            CertificateStoreCredentialOptions settings,
            Func<StoreLocation, X509Certificate2Collection> candidatesFor,
            DateTimeOffset now)
        {
            if (settings.Thumbprint != null)
                return settings;

            var found = FindForSettings(settings, candidatesFor, now);
            found.Certificate.Dispose();
            return found.Settings;
        }

        private static Match FindForSettings(
            CertificateStoreCredentialOptions settings,
            Func<StoreLocation, X509Certificate2Collection> candidatesFor,
            DateTimeOffset now)
        {
            var locations = settings.StoreLocation is StoreLocation single
                ? new[] { single }
                : new[] { StoreLocation.CurrentUser, StoreLocation.LocalMachine };

            var found = FindByClientId(settings.TenantId, settings.ClientId, locations, candidatesFor, now);
            if (found != null)
                return found;

            throw new InvalidOperationException(
                $"No client certificate whose subject or friendly name contains the client ID {settings.ClientId} " +
                $"was found in the {StoreName.My} certificate store of {string.Join(" or ", locations)} " +
                $"(process user '{Environment.UserDomainName}\\{Environment.UserName}'). " +
                "Name the certificate after the client ID, install it for the account this process runs as, or specify its thumbprint.");
        }

        /// <summary>Reads the <c>My</c> store at a location; empty when it cannot be opened.</summary>
        internal static X509Certificate2Collection ReadStore(StoreLocation location)
        {
            using (var store = new X509Store(StoreName.My, location))
            {
                try
                {
                    store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                    return store.Certificates;
                }
                catch (Exception ex) when (ex is CryptographicException || ex is PlatformNotSupportedException)
                {
                    return new X509Certificate2Collection();
                }
            }
        }

        private static bool Names(X509Certificate2 certificate, string clientId)
        {
            return certificate.Subject.IndexOf(clientId, StringComparison.OrdinalIgnoreCase) >= 0
                   || FriendlyNameOf(certificate).IndexOf(clientId, StringComparison.OrdinalIgnoreCase) >= 0;
        }

        /// <summary>
        /// The friendly name, or empty where the platform cannot supply one. Reading it throws on some
        /// platforms, and one such certificate must not turn "no match" into a
        /// startup crash.
        /// </summary>
        private static string FriendlyNameOf(X509Certificate2 certificate)
        {
            try
            {
                return certificate.FriendlyName ?? string.Empty;
            }
            catch (Exception ex) when (ex is PlatformNotSupportedException || ex is CryptographicException)
            {
                return string.Empty;
            }
        }

        /// <summary>
        /// Whether this process can use the private key. <c>HasPrivateKey</c> only says a key is
        /// associated with the certificate; on Windows it is true even when the key's ACL denies this
        /// account, which would otherwise surface as a <see cref="CryptographicException"/> on the first
        /// token request. Opening the key here moves that failure to creation.
        /// </summary>
        private static bool HasUsablePrivateKey(X509Certificate2 certificate)
        {
            if (!certificate.HasPrivateKey)
                return false;

            try
            {
                using (var rsa = certificate.GetRSAPrivateKey())
                {
                    if (rsa != null)
                        return true;
                }

                using (var ecdsa = certificate.GetECDsaPrivateKey())
                {
                    return ecdsa != null;
                }
            }
            catch (CryptographicException)
            {
                return false;
            }
        }

        /// <summary>Inside its validity window, with the clock skew tolerated at the start.</summary>
        private static bool IsWithinValidity(X509Certificate2 certificate, DateTimeOffset now)
        {
            return new DateTimeOffset(certificate.NotBefore) <= now + ClockSkew
                   && new DateTimeOffset(certificate.NotAfter) > now;
        }

        internal static bool IsHex(string value)
        {
            return value.All(c => (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F'));
        }

        /// <summary>
        /// Opens the store named by <paramref name="requested"/> and returns the validated certificate.
        /// The caller owns the returned certificate and must dispose it.
        /// </summary>
        /// <exception cref="InvalidOperationException">See <see cref="Select"/>.</exception>
        internal static X509Certificate2 Load(CertificateStoreCredentialOptions requested)
        {
            if (requested.Thumbprint == null)
            {
                var now = DateTimeOffset.UtcNow;
                return LoadFound(FindForSettings(requested, ReadStore, now), now);
            }

            using (var store = new X509Store(StoreName.My, LocationOf(requested)))
            {
                try
                {
                    store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                }
                catch (Exception ex) when (ex is CryptographicException || ex is PlatformNotSupportedException)
                {
                    // A store that does not exist (OpenExistingOnly) or is unsupported on this
                    // platform: the certificate cannot be there.
                    throw new InvalidOperationException(
                        $"The client certificate with thumbprint {requested.Thumbprint} could not be found: " +
                        $"the {Describe(requested)} could not be opened ({ex.GetType().Name}).", ex);
                }

                return SelectByThumbprint(store.Certificates, requested, DateTimeOffset.UtcNow);
            }
        }

        /// <summary>
        /// The same as <see cref="Load"/> with the store contents supplied, so the whole path from
        /// settings to validated certificate can be tested with in-memory certificates.
        /// </summary>
        internal static X509Certificate2 LoadFrom(
            CertificateStoreCredentialOptions requested,
            Func<StoreLocation, X509Certificate2Collection> candidatesFor,
            DateTimeOffset now)
        {
            if (requested.Thumbprint == null)
                return LoadFound(FindForSettings(requested, candidatesFor, now), now);

            return SelectByThumbprint(candidatesFor(LocationOf(requested)), requested, now);
        }

        /// <summary>
        /// Validates the certificate a client-ID search already picked, without reading the store again.
        /// Takes ownership of the match's certificate.
        /// </summary>
        internal static X509Certificate2 LoadFound(Match found, DateTimeOffset now)
        {
            return Select(new X509Certificate2Collection(found.Certificate), found.Settings, now, _ => found.KeyUsable);
        }

        /// <summary>
        /// The store location of settings that carry a thumbprint: the one given, else
        /// <c>CurrentUser</c>.
        /// </summary>
        private static StoreLocation LocationOf(CertificateStoreCredentialOptions settings)
        {
            return settings.StoreLocation ?? StoreLocation.CurrentUser;
        }

        /// <summary>
        /// Keeps the certificates carrying the settings' thumbprint, disposes the rest, and selects the
        /// usable one. The single implementation behind both <see cref="Load"/> and <see cref="LoadFrom"/>.
        /// </summary>
        private static X509Certificate2 SelectByThumbprint(
            X509Certificate2Collection all,
            CertificateStoreCredentialOptions settings,
            DateTimeOffset now)
        {
            var candidates = all.Cast<X509Certificate2>().ToList();
            List<X509Certificate2> matching;
            try
            {
                matching = candidates
                    .Where(c => string.Equals(c.Thumbprint, settings.Thumbprint, StringComparison.OrdinalIgnoreCase))
                    .ToList();
            }
            catch
            {
                // A certificate that cannot even report its thumbprint: release every handle read
                // so far rather than leaving them to the finalizer.
                foreach (var certificate in candidates)
                    certificate.Dispose();
                throw;
            }

            foreach (var certificate in candidates)
            {
                if (!matching.Any(m => ReferenceEquals(m, certificate)))
                    certificate.Dispose();
            }

            return Select(new X509Certificate2Collection(matching.ToArray()), settings, now);
        }

        /// <summary>
        /// Picks the usable certificate from <paramref name="candidates"/>, disposing every other one.
        /// </summary>
        /// <exception cref="InvalidOperationException">
        /// No candidate, none with a private key, or the only usable ones have expired.
        /// The messages carry the thumbprint, store and user, never key material.
        /// </exception>
        internal static X509Certificate2 Select(
            X509Certificate2Collection candidates,
            CertificateStoreCredentialOptions settings,
            DateTimeOffset now,
            Func<X509Certificate2, bool>? hasUsableKey = null)
        {
            // Each candidate's key is opened once. A caller that already did so passes the answer.
            hasUsableKey = hasUsableKey ?? HasUsablePrivateKey;

            var all = candidates.Cast<X509Certificate2>().ToList();
            X509Certificate2? chosen = null;
            string? failure = null;

            try
            {
                if (all.Count == 0)
                {
                    failure = $"The client certificate with thumbprint {settings.Thumbprint} was not found in the " +
                              $"{Describe(settings)}. Install it for the account this process runs as, " +
                              "and check the thumbprint.";
                }
                else
                {
                    var withKey = all.Where(hasUsableKey).ToList();
                    if (withKey.Count == 0)
                    {
                        failure = $"The client certificate with thumbprint {settings.Thumbprint} in the " +
                                  $"{Describe(settings)} has no private key, or this account cannot access it. " +
                                  "Authentication needs the private key; import the certificate with its key for this account.";
                    }
                    else
                    {
                        chosen = withKey.Where(c => IsWithinValidity(c, now))
                                        .OrderByDescending(c => c.NotAfter)
                                        .FirstOrDefault();
                        if (chosen == null)
                        {
                            // A certificate that is not valid yet is the one that will become usable, so
                            // it is the cause to report even when older, expired ones sit beside it.
                            var notYetValid = withKey.Where(c => new DateTimeOffset(c.NotAfter) > now).ToList();
                            if (notYetValid.Count == 0)
                            {
                                var notAfter = withKey.Max(c => c.NotAfter).ToUniversalTime();
                                failure = $"The client certificate with thumbprint {settings.Thumbprint} in the " +
                                          $"{Describe(settings)} expired on {notAfter.ToString("u", CultureInfo.InvariantCulture)}. " +
                                          "Renew it and register the new certificate with the service principal.";
                            }
                            else
                            {
                                var notBefore = notYetValid.Min(c => c.NotBefore).ToUniversalTime();
                                failure = $"The client certificate with thumbprint {settings.Thumbprint} in the " +
                                          $"{Describe(settings)} is not valid before {notBefore.ToString("u", CultureInfo.InvariantCulture)}. " +
                                          "Check the certificate's start date and this machine's clock.";
                            }
                        }
                    }
                }
            }
            finally
            {
                foreach (var certificate in all)
                {
                    if (!ReferenceEquals(certificate, chosen))
                        certificate.Dispose();
                }
            }

            if (chosen == null)
                throw new InvalidOperationException(failure);

            return chosen;
        }

        /// <summary>
        /// Builds the credential. The certificate must outlive the credential.
        /// </summary>
        /// <param name="settings">The service principal.</param>
        /// <param name="certificate">The validated certificate.</param>
        /// <param name="credentialOptions">
        /// Authority host, additionally allowed tenants and retry behaviour of the wrapped credential,
        /// or <c>null</c> for the Azure Identity defaults. Token acquisition therefore follows whatever
        /// timeouts and retries the caller wraps around it.
        /// </param>
        internal static ClientCertificateCredential CreateCredential(
            CertificateStoreCredentialOptions settings,
            X509Certificate2 certificate,
            ClientCertificateCredentialOptions? credentialOptions)
        {
            return new ClientCertificateCredential(
                settings.TenantId,
                settings.ClientId,
                certificate,
                credentialOptions ?? new ClientCertificateCredentialOptions());
        }

        private static string Describe(CertificateStoreCredentialOptions settings)
        {
            return $"{StoreName.My} certificate store of {LocationOf(settings)} " +
                   $"(process user '{Environment.UserDomainName}\\{Environment.UserName}')";
        }
    }
}
