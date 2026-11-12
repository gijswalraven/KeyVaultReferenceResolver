using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Xunit;

namespace CertificateStoreCredentials.Tests;

/// <summary>
/// The explicit route without a thumbprint: <c>new CertificateStoreCredentialOptions(tenant, client)</c>
/// finds the certificate that names the client ID, and, unlike the environment convention, fails
/// when there is none.
/// </summary>
public class CertificateByClientIdTests
{
    private const string Tenant = "00000000-0000-0000-0000-000000000001";

    private static X509Certificate2 Cert(string subject, TimeSpan notBefore, TimeSpan notAfter)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var now = DateTimeOffset.UtcNow;
        return request.CreateSelfSigned(now + notBefore, now + notAfter);
    }

    private static X509Certificate2 ValidCert(string subject) =>
        Cert(subject, TimeSpan.FromDays(-1), TimeSpan.FromDays(30));

    private static Func<StoreLocation, X509Certificate2Collection> Only(StoreLocation location, X509Certificate2 certificate) =>
        asked => asked == location
            ? new X509Certificate2Collection(certificate)
            : throw new InvalidOperationException($"{asked} must not be searched.");

    [Fact]
    public void Constructors_ExposeWhatWasGiven()
    {
        var byClient = new CertificateStoreCredentialOptions(Tenant, "client-1");
        Assert.Null(byClient.Thumbprint);
        Assert.Null(byClient.StoreLocation);

        var oneStore = new CertificateStoreCredentialOptions(Tenant, "client-1", StoreLocation.LocalMachine);
        Assert.Null(oneStore.Thumbprint);
        Assert.Equal(StoreLocation.LocalMachine, oneStore.StoreLocation);

        var byThumbprint = new CertificateStoreCredentialOptions(Tenant, "client-1", "ab cd");
        Assert.Equal("ABCD", byThumbprint.Thumbprint);
        Assert.Equal(StoreLocation.CurrentUser, byThumbprint.StoreLocation);
    }

    [Theory]
    [InlineData("", "client")]
    [InlineData(Tenant, " ")]
    public void ByClientId_RejectsEmptyIds(string tenant, string client)
    {
        Assert.Throws<ArgumentException>(() => new CertificateStoreCredentialOptions(tenant, client));
    }

    [Fact]
    public void WithAThumbprint_ResolveReturnsTheSameSettings_WithoutSearching()
    {
        var settings = new CertificateStoreCredentialOptions(Tenant, "client-1", "ABCD");

        var resolved = CertificateStoreLoader.Resolve(
            settings, _ => throw new InvalidOperationException("The store must not be read."), DateTimeOffset.UtcNow);

        Assert.Same(settings, resolved);
    }

    [Fact]
    public void WithoutAThumbprint_ResolveFindsTheCertificateNamingTheClient()
    {
        var clientId = Guid.NewGuid().ToString();
        using var certificate = ValidCert("CN=" + clientId);
        var thumbprint = certificate.Thumbprint;

        var resolved = CertificateStoreLoader.Resolve(
            new CertificateStoreCredentialOptions(Tenant, clientId),
            location => location == StoreLocation.LocalMachine
                ? new X509Certificate2Collection(certificate)
                : new X509Certificate2Collection(),
            DateTimeOffset.UtcNow);

        Assert.Equal(thumbprint, resolved.Thumbprint);
        Assert.Equal(StoreLocation.LocalMachine, resolved.StoreLocation);
        Assert.Equal(Tenant, resolved.TenantId);
        Assert.Equal(clientId, resolved.ClientId);
    }

    [Fact]
    public void WithOneStoreLocationGiven_OnlyThatStoreIsSearched()
    {
        var clientId = Guid.NewGuid().ToString();
        using var certificate = ValidCert("CN=" + clientId);

        var resolved = CertificateStoreLoader.Resolve(
            new CertificateStoreCredentialOptions(Tenant, clientId, StoreLocation.CurrentUser),
            Only(StoreLocation.CurrentUser, certificate), DateTimeOffset.UtcNow);

        Assert.Equal(StoreLocation.CurrentUser, resolved.StoreLocation);
    }

    [Fact]
    public void NoCertificateNamesTheClient_Throws_NamingTheClientAndTheStores()
    {
        var clientId = Guid.NewGuid().ToString();
        using var other = ValidCert("CN=somebody-else");

        var ex = Assert.Throws<InvalidOperationException>(() => CertificateStoreLoader.Resolve(
            new CertificateStoreCredentialOptions(Tenant, clientId),
            _ => new X509Certificate2Collection(new X509Certificate2(other.RawData)), DateTimeOffset.UtcNow));

        Assert.Contains(clientId, ex.Message);
        Assert.Contains("CurrentUser or LocalMachine", ex.Message);
        Assert.Contains(Environment.UserName, ex.Message);
    }

    [Fact]
    public void Create_WithoutAMatchingCertificate_FailsAtSetup()
    {
        var clientId = Guid.NewGuid().ToString();

        var ex = Assert.Throws<InvalidOperationException>(
            () => CertificateStoreCredential.Create(new CertificateStoreCredentialOptions(Tenant, clientId)));

        Assert.Contains(clientId, ex.Message);
    }

    /// <summary>
    /// Through the real store: a persisted certificate named after the client ID is found with no
    /// thumbprint (an expired one proves it, by failing with the specific reason). Everything added
    /// is removed in a <c>finally</c>.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Create_FindsTheCertificateInTheCurrentUserStore(bool expired)
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Skip("Persisting a private key in the user store is exercised on Windows only.");
            return;
        }

        var clientId = Guid.NewGuid().ToString();
        using var generated = expired
            ? Cert("CN=" + clientId, TimeSpan.FromDays(-400), TimeSpan.FromDays(-35))
            : ValidCert("CN=" + clientId);
        var pfx = generated.Export(X509ContentType.Pfx, "temp");
        using var persisted = new X509Certificate2(
            pfx, "temp", X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.UserKeySet);

        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadWrite);
        try
        {
            store.Add(persisted);

            var settings = new CertificateStoreCredentialOptions(Tenant, clientId);

            if (expired)
            {
                var ex = Assert.Throws<InvalidOperationException>(() => CertificateStoreCredential.Create(settings));
                Assert.Contains("expired", ex.Message);
            }
            else
            {
                using var credential = CertificateStoreCredential.Create(settings);
                Assert.Equal(persisted.Thumbprint, credential.Thumbprint);
            }
        }
        finally
        {
            store.Remove(persisted);
            if (persisted.GetRSAPrivateKey() is RSACng cng)
                cng.Key.Delete();
        }
    }
}
