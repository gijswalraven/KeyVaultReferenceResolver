using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Azure.Identity;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace KeyVaultReferenceResolver.Tests;

/// <summary>
/// Client-certificate authentication from the certificate store. Certificates are created in
/// memory (<see cref="CertificateRequest"/>) and fed to the selection logic directly, so these
/// tests do not touch the machine's store; the one test that does goes through the real store
/// and removes everything it added in a <c>finally</c>.
/// </summary>
public class CertificateStoreCredentialTests
{
    private const string Tenant = "00000000-0000-0000-0000-000000000001";
    private const string Client = "00000000-0000-0000-0000-000000000002";

    private static X509Certificate2 CreateCertificate(DateTimeOffset notBefore, DateTimeOffset notAfter)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=kvrr-test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return request.CreateSelfSigned(notBefore, notAfter);
    }

    private static X509Certificate2 CreateValidCertificate() =>
        CreateCertificate(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));

    private static CertificateStoreCredentialOptions SettingsFor(X509Certificate2 certificate) =>
        new(Tenant, Client, certificate.Thumbprint);

    // ---- thumbprint normalisation ----

    [Theory]
    [InlineData("ab cd ef 01", "ABCDEF01")]
    [InlineData("ab:cd:ef:01", "ABCDEF01")]
    [InlineData("ab-cd-ef-01", "ABCDEF01")]
    [InlineData("‎ab cd‎ ef01", "ABCDEF01")]   // U+200E: what MMC adds when copying
    [InlineData("‏​﻿AB\tCD\r\nEF01", "ABCDEF01")]
    [InlineData("ABCDEF01", "ABCDEF01")]
    public void Thumbprint_IsNormalised(string input, string expected)
    {
        var settings = new CertificateStoreCredentialOptions(Tenant, Client, input);

        Assert.Equal(expected, settings.Thumbprint);
    }

    [Fact]
    public void StoreLocation_DefaultsToCurrentUser_AndIsConfigurable()
    {
        Assert.Equal(StoreLocation.CurrentUser, new CertificateStoreCredentialOptions(Tenant, Client, "AB").StoreLocation);
        Assert.Equal(StoreLocation.LocalMachine,
            new CertificateStoreCredentialOptions(Tenant, Client, "AB", StoreLocation.LocalMachine).StoreLocation);
    }

    [Theory]
    [InlineData("", Client, "AB")]
    [InlineData(Tenant, " ", "AB")]
    [InlineData(Tenant, Client, "")]
    [InlineData(Tenant, Client, " ‎ - : ")]
    [InlineData(Tenant, Client, "not-hex-zz")]
    public void InvalidValues_AreRejected(string tenant, string client, string thumbprint)
    {
        Assert.Throws<ArgumentException>(() => new CertificateStoreCredentialOptions(tenant, client, thumbprint));
    }

    // ---- certificate selection ----

    [Fact]
    public void ValidCertificate_IsSelected_AndYieldsACredential()
    {
        using var certificate = CreateValidCertificate();
        var settings = SettingsFor(certificate);

        using var selected = CertificateStoreLoader.Select(
            new X509Certificate2Collection(certificate), settings, DateTimeOffset.UtcNow);
        var credential = CertificateStoreLoader.CreateCredential(settings, selected, new KeyVaultReferenceResolverOptions());

        Assert.IsType<ClientCertificateCredential>(credential);
    }

    [Fact]
    public void NoCandidates_ThrowsNamingThumbprintStoreAndUser()
    {
        var settings = new CertificateStoreCredentialOptions(Tenant, Client, "AABBCCDD");

        var ex = Assert.Throws<InvalidOperationException>(() =>
            CertificateStoreLoader.Select(new X509Certificate2Collection(), settings, DateTimeOffset.UtcNow));

        Assert.Contains("AABBCCDD", ex.Message);
        Assert.Contains("CurrentUser", ex.Message);
        Assert.Contains(Environment.UserName, ex.Message);
        Assert.Contains("not found", ex.Message);
    }

    [Fact]
    public void CertificateWithoutPrivateKey_Throws()
    {
        using var full = CreateValidCertificate();
        using var publicOnly = new X509Certificate2(full.RawData);
        var settings = SettingsFor(publicOnly);

        var ex = Assert.Throws<InvalidOperationException>(() =>
            CertificateStoreLoader.Select(new X509Certificate2Collection(publicOnly), settings, DateTimeOffset.UtcNow));

        Assert.Contains("private key", ex.Message);
        Assert.Contains(settings.Thumbprint!, ex.Message);
    }

    [Fact]
    public void ExpiredCertificate_ThrowsWithTheEndDate()
    {
        using var certificate = CreateCertificate(
            new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero),
            new DateTimeOffset(2021, 3, 4, 5, 6, 7, TimeSpan.Zero));
        var settings = SettingsFor(certificate);

        var ex = Assert.Throws<InvalidOperationException>(() =>
            CertificateStoreLoader.Select(new X509Certificate2Collection(certificate), settings, DateTimeOffset.UtcNow));

        Assert.Contains("expired", ex.Message);
        Assert.Contains("2021-03-04", ex.Message);
        Assert.Contains(settings.Thumbprint!, ex.Message);
    }

    [Fact]
    public void NotYetValidCertificate_ThrowsWithTheStartDate()
    {
        using var certificate = CreateCertificate(
            DateTimeOffset.UtcNow.AddDays(10), DateTimeOffset.UtcNow.AddDays(40));
        var settings = SettingsFor(certificate);
        // Select disposes rejected certificates, so read the date first.
        var startDate = certificate.NotBefore.ToUniversalTime().ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture);

        var ex =Assert.Throws<InvalidOperationException>(() =>
            CertificateStoreLoader.Select(new X509Certificate2Collection(certificate), settings, DateTimeOffset.UtcNow));

        Assert.Contains("not valid before", ex.Message);
        Assert.Contains(startDate, ex.Message);
        Assert.Contains(settings.Thumbprint!, ex.Message);
    }

    [Fact]
    public void CertificateStartingWithinClockSkew_IsAccepted()
    {
        using var certificate = CreateCertificate(
            DateTimeOffset.UtcNow.AddMinutes(1), DateTimeOffset.UtcNow.AddDays(30));

        using var selected = CertificateStoreLoader.Select(
            new X509Certificate2Collection(certificate), SettingsFor(certificate), DateTimeOffset.UtcNow);

        Assert.NotNull(selected);
    }

    [Fact]
    public void ErrorMessages_NeverContainKeyMaterial()
    {
        using var certificate = CreateCertificate(
            DateTimeOffset.UtcNow.AddYears(-2), DateTimeOffset.UtcNow.AddYears(-1));
        var settings = SettingsFor(certificate);
        var privateKey = Convert.ToBase64String(certificate.GetRSAPrivateKey()!.ExportPkcs8PrivateKey());

        var ex = Assert.Throws<InvalidOperationException>(() =>
            CertificateStoreLoader.Select(new X509Certificate2Collection(certificate), settings, DateTimeOffset.UtcNow));

        Assert.DoesNotContain(privateKey.Substring(0, 40), ex.Message);
    }

    // ---- wiring into the resolver ----

    [Fact]
    public void ClientCertificate_NotInStore_FailsWhenTheResolverIsCreated()
    {
        // Random thumbprint: cannot be in any store. Fails at construction, before any vault call.
        var options = new KeyVaultReferenceResolverOptions
        {
            ClientCertificate = new CertificateStoreCredentialOptions(Tenant, Client, Guid.NewGuid().ToString("N") + "ABCDEF01")
        };

        var ex = Assert.Throws<InvalidOperationException>(() => new KeyVaultSecretResolver(options));
        Assert.Contains(options.ClientCertificate.Thumbprint!, ex.Message);

        var builder = new ConfigurationBuilder();
        Assert.Throws<InvalidOperationException>(() => builder.AddKeyVaultReferenceResolver(options, logger: null));
    }

    [Fact]
    public void ExplicitCredential_WinsOverClientCertificate()
    {
        var credential = new ClientSecretCredential(Tenant, Client, "not-used");
        var options = new KeyVaultReferenceResolverOptions
        {
            Credential = credential,
            // Would throw if it were consulted.
            ClientCertificate = new CertificateStoreCredentialOptions(Tenant, Client, Guid.NewGuid().ToString("N") + "ABCDEF01")
        };

        using var resolver = new KeyVaultSecretResolver(options);
    }

    [Fact]
    public void WithoutClientCertificate_BehaviourIsUnchanged()
    {
        var options = new KeyVaultReferenceResolverOptions();
        Assert.Null(options.ClientCertificate);

        // Same default-chain construction as before, and no Azure call without a reference.
        using var resolver = new KeyVaultSecretResolver(options);
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new[] { new KeyValuePair<string, string?>("Plain", "value") })
            .AddKeyVaultReferenceResolver(options, logger: null)
            .Build();

        Assert.Equal("value", configuration["Plain"]);

        var chain = KeyVaultSecretResolver.BuildCredentialOptions(new KeyVaultReferenceResolverOptions { AllowDeveloperCredentials = true });
        Assert.False(chain.ExcludeAzureCliCredential);
    }

    /// <summary>
    /// The one test that goes through the real store. The certificate carries a persisted,
    /// non-exportable-style key, is added to CurrentUser\My, found by a messy thumbprint, and then
    /// removed along with its key container.
    /// </summary>
    [Fact]
    public void ClientCertificate_InCurrentUserStore_IsFoundAndUsed()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Skip("Persisting a private key in the user store is exercised on Windows only.");
            return;
        }

        using var generated = CreateValidCertificate();
        var pfx = generated.Export(X509ContentType.Pfx, "temp");
        using var persisted = new X509Certificate2(
            pfx, "temp", X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.UserKeySet);

        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadWrite);
        try
        {
            store.Add(persisted);

            var messy = "‎" + string.Join(" ", persisted.Thumbprint.ToLowerInvariant().Chunk(4).Select(c => new string(c)));
            var options = new KeyVaultReferenceResolverOptions
            {
                ClientCertificate = new CertificateStoreCredentialOptions(Tenant, Client, messy)
            };

            using var resolver = new KeyVaultSecretResolver(options);
        }
        finally
        {
            store.Remove(persisted);
            if (persisted.GetRSAPrivateKey() is RSACng cng)
                cng.Key.Delete();
        }
    }
}
