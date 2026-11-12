using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Azure.Core;
using Azure.Identity;
using Xunit;

namespace CertificateStoreCredentials.Tests;

/// <summary>
/// The public <see cref="CertificateStoreCredential"/>: the same certificate logic as the resolver,
/// usable for any token. Certificates are in memory and supplied through the store seam; the
/// tests that go through the real store are Windows-only and clean up in a <c>finally</c>.
/// </summary>
public class CertificateStoreCredentialClassTests
{
    private const string Tenant = "00000000-0000-0000-0000-000000000001";
    private static readonly string[] SqlScope = { "https://database.windows.net/.default" };

    private static X509Certificate2 Cert(string subject, TimeSpan notBefore, TimeSpan notAfter)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var now = DateTimeOffset.UtcNow;
        return request.CreateSelfSigned(now + notBefore, now + notAfter);
    }

    private static X509Certificate2 ValidCert(string subject) =>
        Cert(subject, TimeSpan.FromDays(-1), TimeSpan.FromDays(30));

    /// <summary>A store whose every location holds a fresh copy of the certificate, as the real store does.</summary>
    private static Func<StoreLocation, X509Certificate2Collection> StoreHolding(X509Certificate2 certificate) =>
        _ => new X509Certificate2Collection(new X509Certificate2(certificate.Export(X509ContentType.Pfx, "t"), "t"));

    private static Func<StoreLocation, X509Certificate2Collection> PublicOnlyStoreHolding(X509Certificate2 certificate) =>
        _ => new X509Certificate2Collection(new X509Certificate2(certificate.RawData));

    private static Func<StoreLocation, X509Certificate2Collection> EmptyStore =>
        _ => new X509Certificate2Collection();

    /// <summary>The credential for the certificate named after the client ID, read from the supplied store.</summary>
    private static CertificateStoreCredential FromStore(
        string clientId,
        Func<StoreLocation, X509Certificate2Collection> store,
        ClientCertificateCredentialOptions? credentialOptions = null) =>
        CertificateStoreCredential.CreateFrom(
            new CertificateStoreCredentialOptions(Tenant, clientId), credentialOptions, store, DateTimeOffset.UtcNow);

    // ---- a usable certificate yields a credential ----

    [Fact]
    public void FromStoreCertificate_ReturnsACredentialForIt()
    {
        var clientId = Guid.NewGuid().ToString();
        using var certificate = ValidCert("CN=" + clientId);

        using var credential = FromStore(clientId, StoreHolding(certificate));

        Assert.NotNull(credential);
        Assert.IsAssignableFrom<TokenCredential>(credential);
        Assert.Equal(certificate.Thumbprint, credential!.Thumbprint);
        Assert.True(credential.Certificate.HasPrivateKey);
    }

    // ---- an unusable certificate throws ----

    [Fact]
    public void ExpiredCertificate_Throws()
    {
        var clientId = Guid.NewGuid().ToString();
        using var expired = Cert("CN=" + clientId, TimeSpan.FromDays(-400), TimeSpan.FromDays(-35));

        var ex = Assert.Throws<InvalidOperationException>(() => FromStore(clientId, StoreHolding(expired)));

        Assert.Contains("expired", ex.Message);
    }

    [Fact]
    public void CertificateWithoutPrivateKey_Throws()
    {
        var clientId = Guid.NewGuid().ToString();
        using var full = ValidCert("CN=" + clientId);

        var ex = Assert.Throws<InvalidOperationException>(() => FromStore(clientId, PublicOnlyStoreHolding(full)));

        Assert.Contains("private key", ex.Message);
    }

    // ---- Create: the certificate is required ----

    [Fact]
    public void Create_WithoutAMatchingCertificate_Throws()
    {
        var clientId = Guid.NewGuid().ToString();

        var byClient = Assert.Throws<InvalidOperationException>(
            () => CertificateStoreCredential.Create(new CertificateStoreCredentialOptions(Tenant, clientId)));
        Assert.Contains(clientId, byClient.Message);

        var byThumbprint = new CertificateStoreCredentialOptions(Tenant, clientId, new string('C', 40));
        var missing = Assert.Throws<InvalidOperationException>(() => CertificateStoreCredential.Create(byThumbprint));
        Assert.Contains(byThumbprint.Thumbprint!, missing.Message);
    }

    [Fact]
    public void Create_NullOptions_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => CertificateStoreCredential.Create(null!));
    }

    // ---- ownership ----

    [Fact]
    public void Dispose_ReleasesTheCertificate_AndIsIdempotent()
    {
        var clientId = Guid.NewGuid().ToString();
        using var certificate = ValidCert("CN=" + clientId);

        var credential = FromStore(clientId, StoreHolding(certificate))!;
        var loaded = credential.Certificate;
        Assert.NotEqual(IntPtr.Zero, loaded.Handle);

        credential.Dispose();
        credential.Dispose();

        Assert.Equal(IntPtr.Zero, loaded.Handle);
        Assert.Equal(certificate.Thumbprint, credential.Thumbprint);
    }

    [Fact]
    public void Dispose_DuringATokenRequest_ReleasesTheCertificateOnlyWhenItEnds()
    {
        var clientId = Guid.NewGuid().ToString();
        using var certificate = ValidCert("CN=" + clientId);

        var credential = FromStore(clientId, StoreHolding(certificate))!;
        var loaded = credential.Certificate;

        credential.Enter();
        credential.Dispose();

        // The request in flight can still sign; new ones are refused.
        Assert.NotEqual(IntPtr.Zero, loaded.Handle);
        Assert.Throws<ObjectDisposedException>(() => credential.Enter());

        credential.Exit();

        Assert.Equal(IntPtr.Zero, loaded.Handle);
    }

    [Fact]
    public void BlankThumbprint_MeansSearchByClientId_AndKeepsTheLocationUnset()
    {
        foreach (var blank in new string?[] { null, "", "  " })
        {
            var settings = new CertificateStoreCredentialOptions(Tenant, "client-1", blank);
            Assert.Null(settings.Thumbprint);
            Assert.Null(settings.StoreLocation);
        }

        var oneStore = new CertificateStoreCredentialOptions(Tenant, "client-1", (string?)null, StoreLocation.LocalMachine);
        Assert.Null(oneStore.Thumbprint);
        Assert.Equal(StoreLocation.LocalMachine, oneStore.StoreLocation);
    }

    [Fact]
    public void NotYetValidCertificate_IsReported_EvenBesideAnExpiredOne()
    {
        var clientId = Guid.NewGuid().ToString();
        using var expired = Cert("CN=" + clientId, TimeSpan.FromDays(-60), TimeSpan.FromDays(-30));
        using var future = Cert("CN=" + clientId, TimeSpan.FromDays(10), TimeSpan.FromDays(40));
        var both = new X509Certificate2Collection();
        both.Add(new X509Certificate2(expired.Export(X509ContentType.Pfx, "t"), "t"));
        both.Add(new X509Certificate2(future.Export(X509ContentType.Pfx, "t"), "t"));

        var settings = new CertificateStoreCredentialOptions(Tenant, clientId, "AB");
        var ex = Assert.Throws<InvalidOperationException>(
            () => CertificateStoreLoader.Select(both, settings, DateTimeOffset.UtcNow));

        Assert.Contains("not valid before", ex.Message);
        Assert.Contains(future.NotBefore.ToUniversalTime().ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture), ex.Message);
    }

    [Fact]
    public void LiteralNullThumbprint_Compiles_AndMeansSearchByClientId()
    {
        var settings = new CertificateStoreCredentialOptions(Tenant, "client-1", null);
        Assert.Null(settings.Thumbprint);
    }

    [Fact]
    public void KeyThatCannotBeOpened_IsNotUsable_AndTheSearchReportsTheMissingKey()
    {
        var clientId = Guid.NewGuid().ToString();
        using var certificate = ValidCert("CN=" + clientId);

        // A certificate carrying only its public part has no usable key; with the key check the
        // search fails with the specific reason instead of returning a credential.
        var ex = Assert.Throws<InvalidOperationException>(() => FromStore(clientId, PublicOnlyStoreHolding(certificate)));
        Assert.Contains("private key", ex.Message);
    }

    [Fact]
    public async Task AfterDispose_TokenRequestsThrowObjectDisposed()
    {
        var clientId = Guid.NewGuid().ToString();
        using var certificate = ValidCert("CN=" + clientId);
        var credential = FromStore(clientId, StoreHolding(certificate))!;
        credential.Dispose();

        var context = new TokenRequestContext(SqlScope);
        var cancellation = TestContext.Current.CancellationToken;

        Assert.Throws<ObjectDisposedException>(() => credential.GetToken(context, cancellation));
        await Assert.ThrowsAsync<ObjectDisposedException>(async () => await credential.GetTokenAsync(context, cancellation));
    }

    [Fact]
    public void Options_ForTheWrappedCredential_AreAccepted()
    {
        var clientId = Guid.NewGuid().ToString();
        using var certificate = ValidCert("CN=" + clientId);
        var credentialOptions = new ClientCertificateCredentialOptions
        {
            AuthorityHost = new Uri("https://login.microsoftonline.us/")
        };
        credentialOptions.AdditionallyAllowedTenants.Add("*");

        using var credential = FromStore(clientId, StoreHolding(certificate), credentialOptions);

        Assert.NotNull(credential);
    }
}
