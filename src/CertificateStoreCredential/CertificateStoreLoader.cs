using System;
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

        internal const string TenantIdVariable = "AZURE_TENANT_ID";
        internal const string ClientIdVariable = "AZURE_CLIENT_ID";

        /// <summary>
        /// Environment variables that mean the environment already names another way to
        /// authenticate (client secret, certificate file, federated token). The convention then
        /// stays out of the way.
        /// </summary>
        private static readonly string[] OtherMechanismVariables =
        {
            "AZURE_CLIENT_SECRET",
            "AZURE_CLIENT_CERTIFICATE_PATH",
            "AZURE_FEDERATED_TOKEN_FILE",
            // Username/password (ROPC): the fourth mode EnvironmentCredential supports. A user
            // identity is not the service principal, so the convention stays out of the way.
            "AZURE_USERNAME",
            "AZURE_PASSWORD"
        };

        /// <summary>
        /// Finds the store certificate for the service principal named by <c>AZURE_TENANT_ID</c> and
        /// <c>AZURE_CLIENT_ID</c>: the certificate whose subject or friendly name contains the client
        /// ID, in <c>CurrentUser\My</c> and then <c>LocalMachine\My</c>.
        /// </summary>
        /// <param name="getVariable">Reads an environment variable.</param>
        /// <param name="candidatesFor">Returns the certificates of the <c>My</c> store at a location. Takes ownership of nothing; the caller disposes what it returns.</param>
        /// <param name="now">The time the certificate validity is judged against.</param>
        /// <returns>
        /// The settings, or <c>null</c> when the tenant or client ID is missing, another authentication
        /// mechanism is configured, or no certificate carries the client ID. Those variables are
        /// standard and set for other reasons too (a user-assigned managed identity uses
        /// <c>AZURE_CLIENT_ID</c>), so they only opt in when a matching certificate exists.
        /// </returns>
        /// <remarks>
        /// Among matches, a certificate that is valid and has a private key wins, then the one that
        /// expires last, so a renewed certificate is picked up without any configuration change. A
        /// usable match in any searched location wins over an unusable one in an earlier location. If
        /// every match is unusable the best one is still returned, and <see cref="Load"/> then fails with
        /// the specific reason (expired, no private key, ...) rather than silently falling back to a
        /// credential chain that would fail less clearly.
        /// </remarks>
        internal static CertificateStoreCredentialOptions? FromEnvironment(
            Func<string, string?> getVariable,
            Func<StoreLocation, X509Certificate2Collection> candidatesFor,
            DateTimeOffset now)
        {
            var tenantId = getVariable(TenantIdVariable);
            var clientId = getVariable(ClientIdVariable);
            if (string.IsNullOrWhiteSpace(tenantId) || string.IsNullOrWhiteSpace(clientId))
                return null;

            if (OtherMechanismVariables.Any(name => !string.IsNullOrWhiteSpace(getVariable(name))))
                return null;

            tenantId = tenantId!.Trim();
            clientId = clientId!.Trim();

            return FindByClientId(
                tenantId, clientId, new[] { StoreLocation.CurrentUser, StoreLocation.LocalMachine }, candidatesFor, now);
        }

        /// <summary>
        /// Searches the given store locations, in order, for the certificate that names
        /// <paramref name="clientId"/>. Returns settings carrying its thumbprint, or <c>null</c>.
        /// </summary>
        private static CertificateStoreCredentialOptions? FindByClientId(
            string tenantId,
            string clientId,
            StoreLocation[] locations,
            Func<StoreLocation, X509Certificate2Collection> candidatesFor,
            DateTimeOffset now)
        {
            // The best unusable match, used only when no location holds a usable one, so that Load
            // fails with the specific reason rather than falling back to the default chain.
            CertificateStoreCredentialOptions? fallback = null;

            foreach (var location in locations)
            {
                var all = candidatesFor(location).Cast<X509Certificate2>().ToList();
                try
                {
                    var matches = all.Where(c => Names(c, clientId)).ToList();

                    var usable = matches
                        .Where(c => IsUsable(c, now))
                        .OrderByDescending(c => c.NotAfter)
                        .FirstOrDefault();

                    if (usable != null)
                        return new CertificateStoreCredentialOptions(tenantId, clientId, usable.Thumbprint, location);

                    if (fallback == null)
                    {
                        var best = matches.OrderByDescending(c => c.NotAfter).FirstOrDefault();
                        if (best != null)
                            fallback = new CertificateStoreCredentialOptions(tenantId, clientId, best.Thumbprint, location);
                    }
                }
                finally
                {
                    foreach (var certificate in all)
                        certificate.Dispose();
                }
            }

            return fallback;
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
                   || certificate.FriendlyName.IndexOf(clientId, StringComparison.OrdinalIgnoreCase) >= 0;
        }

        /// <summary>Has an accessible private key and is inside its validity window.</summary>
        private static bool IsUsable(X509Certificate2 certificate, DateTimeOffset now)
        {
            return certificate.HasPrivateKey
                   && new DateTimeOffset(certificate.NotBefore) <= now + ClockSkew
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
            // From here on the settings carry a thumbprint and a location.
            var settings = Resolve(requested, ReadStore, DateTimeOffset.UtcNow);

            using (var store = new X509Store(StoreName.My, settings.StoreLocation!.Value))
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
                        $"The client certificate with thumbprint {settings.Thumbprint} could not be found: " +
                        $"the {Describe(settings)} could not be opened ({ex.GetType().Name}).", ex);
                }

                return SelectByThumbprint(store.Certificates, settings, DateTimeOffset.UtcNow);
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
            var settings = Resolve(requested, candidatesFor, now);
            return SelectByThumbprint(candidatesFor(settings.StoreLocation!.Value), settings, now);
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
            var matching = new System.Collections.Generic.List<X509Certificate2>();
            foreach (var certificate in all.Cast<X509Certificate2>())
            {
                if (string.Equals(certificate.Thumbprint, settings.Thumbprint, StringComparison.OrdinalIgnoreCase))
                    matching.Add(certificate);
                else
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
            DateTimeOffset now)
        {
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
                    var withKey = all.Where(c => c.HasPrivateKey).ToList();
                    if (withKey.Count == 0)
                    {
                        failure = $"The client certificate with thumbprint {settings.Thumbprint} in the " +
                                  $"{Describe(settings)} has no private key, or this account cannot access it. " +
                                  "Authentication needs the private key; import the certificate with its key for this account.";
                    }
                    else
                    {
                        chosen = withKey.Where(c => IsUsable(c, now))
                                        .OrderByDescending(c => c.NotAfter)
                                        .FirstOrDefault();
                        if (chosen == null)
                        {
                            if (withKey.All(c => new DateTimeOffset(c.NotAfter) <= now))
                            {
                                var notAfter = withKey.Max(c => c.NotAfter).ToUniversalTime();
                                failure = $"The client certificate with thumbprint {settings.Thumbprint} in the " +
                                          $"{Describe(settings)} expired on {notAfter.ToString("u", CultureInfo.InvariantCulture)}. " +
                                          "Renew it and register the new certificate with the service principal.";
                            }
                            else
                            {
                                var notBefore = withKey.Min(c => c.NotBefore).ToUniversalTime();
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
            return $"{StoreName.My} certificate store of {settings.StoreLocation} " +
                   $"(process user '{Environment.UserDomainName}\\{Environment.UserName}')";
        }
    }
}
