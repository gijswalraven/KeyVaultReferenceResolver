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
/// Tests that change the process-wide AZURE_* variables. A collection of its own, with
/// parallelization disabled, so they cannot race with anything that reads the environment.
/// </summary>
[CollectionDefinition("AzureEnvironment", DisableParallelization = true)]
public class AzureEnvironmentCollection
{
}

/// <summary>
/// The public <see cref="CertificateStoreCredential"/>: the same certificate logic as the resolver,
/// usable for any token. Certificates are in memory and supplied through the store seam; the
/// tests that go through the real store are Windows-only and clean up in a <c>finally</c>.
/// </summary>
[Collection("AzureEnvironment")]
public class CertificateStoreCredentialClassTests
{
    private const string Tenant = "00000000-0000-0000-0000-000000000001";
    private static readonly string[] SqlScope = { "https://database.windows.net/.default" };

    private static readonly string[] Variables =
    {
        "AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET",
        "AZURE_CLIENT_CERTIFICATE_PATH", "AZURE_FEDERATED_TOKEN_FILE"
    };

    private static X509Certificate2 Cert(string subject, TimeSpan notBefore, TimeSpan notAfter)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var now = DateTimeOffset.UtcNow;
        return request.CreateSelfSigned(now + notBefore, now + notAfter);
    }

    private static X509Certificate2 ValidCert(string subject) =>
        Cert(subject, TimeSpan.FromDays(-1), TimeSpan.FromDays(30));

    private static Func<string, string?> Env(params (string Key, string Value)[] values)
    {
        var data = values.ToDictionary(v => v.Key, v => v.Value);
        return name => data.TryGetValue(name, out var v) ? v : null;
    }

    /// <summary>A store whose every location holds a fresh copy of the certificate, as the real store does.</summary>
    private static Func<StoreLocation, X509Certificate2Collection> StoreHolding(X509Certificate2 certificate) =>
        _ => new X509Certificate2Collection(new X509Certificate2(certificate.Export(X509ContentType.Pfx, "t"), "t"));

    private static Func<StoreLocation, X509Certificate2Collection> PublicOnlyStoreHolding(X509Certificate2 certificate) =>
        _ => new X509Certificate2Collection(new X509Certificate2(certificate.RawData));

    private static Func<StoreLocation, X509Certificate2Collection> EmptyStore =>
        _ => new X509Certificate2Collection();

    private static void WithEnvironment((string Key, string Value)[] values, Action body)
    {
        var saved = Variables.ToDictionary(name => name, Environment.GetEnvironmentVariable);
        foreach (var name in Variables)
            Environment.SetEnvironmentVariable(name, null);

        try
        {
            foreach (var (key, value) in values)
                Environment.SetEnvironmentVariable(key, value);
            body();
        }
        finally
        {
            foreach (var pair in saved)
                Environment.SetEnvironmentVariable(pair.Key, pair.Value);
        }
    }

    // ---- TryCreateFromEnvironment: null when the convention does not apply ----

    [Fact]
    public void TryCreateFromEnvironment_NoVariables_ReturnsNull()
    {
        Assert.Null(CertificateStoreCredential.TryCreateFromEnvironment(
            Env(), EmptyStore, DateTimeOffset.UtcNow));
    }

    [Fact]
    public void TryCreateFromEnvironment_NoMatchingCertificate_ReturnsNull()
    {
        var clientId = Guid.NewGuid().ToString();
        using var other = ValidCert("CN=somebody-else");

        Assert.Null(CertificateStoreCredential.TryCreateFromEnvironment(
            Env(("AZURE_TENANT_ID", Tenant), ("AZURE_CLIENT_ID", clientId)),
            StoreHolding(other), DateTimeOffset.UtcNow));
    }

    [Theory]
    [InlineData("AZURE_CLIENT_SECRET")]
    [InlineData("AZURE_CLIENT_CERTIFICATE_PATH")]
    [InlineData("AZURE_FEDERATED_TOKEN_FILE")]
    public void TryCreateFromEnvironment_AnotherMechanismConfigured_ReturnsNull(string variable)
    {
        var clientId = Guid.NewGuid().ToString();
        using var certificate = ValidCert("CN=" + clientId);

        Assert.Null(CertificateStoreCredential.TryCreateFromEnvironment(
            Env(("AZURE_TENANT_ID", Tenant), ("AZURE_CLIENT_ID", clientId), (variable, "x")),
            StoreHolding(certificate), DateTimeOffset.UtcNow));
    }

    [Fact]
    public void TryCreateFromEnvironment_PublicOverload_ReturnsNull_WithoutVariables()
    {
        WithEnvironment(Array.Empty<(string, string)>(), () =>
            Assert.Null(CertificateStoreCredential.TryCreateFromEnvironment()));
    }

    // ---- a usable certificate yields a credential ----

    [Fact]
    public void TryCreateFromEnvironment_ValidCertificate_ReturnsACredentialForIt()
    {
        var clientId = Guid.NewGuid().ToString();
        using var certificate = ValidCert("CN=" + clientId);

        using var credential = CertificateStoreCredential.TryCreateFromEnvironment(
            Env(("AZURE_TENANT_ID", Tenant), ("AZURE_CLIENT_ID", clientId)),
            StoreHolding(certificate), DateTimeOffset.UtcNow);

        Assert.NotNull(credential);
        Assert.IsAssignableFrom<TokenCredential>(credential);
        Assert.Equal(certificate.Thumbprint, credential!.Thumbprint);
        Assert.True(credential.Certificate.HasPrivateKey);
    }

    // ---- an unusable certificate throws, it is not "convention does not apply" ----

    [Fact]
    public void TryCreateFromEnvironment_ExpiredCertificate_Throws()
    {
        var clientId = Guid.NewGuid().ToString();
        using var expired = Cert("CN=" + clientId, TimeSpan.FromDays(-400), TimeSpan.FromDays(-35));

        var ex = Assert.Throws<InvalidOperationException>(() => CertificateStoreCredential.TryCreateFromEnvironment(
            Env(("AZURE_TENANT_ID", Tenant), ("AZURE_CLIENT_ID", clientId)),
            StoreHolding(expired), DateTimeOffset.UtcNow));

        Assert.Contains("expired", ex.Message);
    }

    [Fact]
    public void TryCreateFromEnvironment_CertificateWithoutPrivateKey_Throws()
    {
        var clientId = Guid.NewGuid().ToString();
        using var full = ValidCert("CN=" + clientId);

        var ex = Assert.Throws<InvalidOperationException>(() => CertificateStoreCredential.TryCreateFromEnvironment(
            Env(("AZURE_TENANT_ID", Tenant), ("AZURE_CLIENT_ID", clientId)),
            PublicOnlyStoreHolding(full), DateTimeOffset.UtcNow));

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

        var credential = CertificateStoreCredential.TryCreateFromEnvironment(
            Env(("AZURE_TENANT_ID", Tenant), ("AZURE_CLIENT_ID", clientId)),
            StoreHolding(certificate), DateTimeOffset.UtcNow)!;
        var loaded = credential.Certificate;
        Assert.NotEqual(IntPtr.Zero, loaded.Handle);

        credential.Dispose();
        credential.Dispose();

        Assert.Equal(IntPtr.Zero, loaded.Handle);
        Assert.Equal(certificate.Thumbprint, credential.Thumbprint);
    }

    [Fact]
    public async Task AfterDispose_TokenRequestsThrowObjectDisposed()
    {
        var clientId = Guid.NewGuid().ToString();
        using var certificate = ValidCert("CN=" + clientId);
        var credential = CertificateStoreCredential.TryCreateFromEnvironment(
            Env(("AZURE_TENANT_ID", Tenant), ("AZURE_CLIENT_ID", clientId)),
            StoreHolding(certificate), DateTimeOffset.UtcNow)!;
        credential.Dispose();

        var context = new TokenRequestContext(SqlScope);
        var cancellation = TestContext.Current.CancellationToken;

        Assert.Throws<ObjectDisposedException>(() => credential.GetToken(context, cancellation));
        await Assert.ThrowsAsync<ObjectDisposedException>(async () => await credential.GetTokenAsync(context, cancellation));
    }

    // ---- through the real store ----

    /// <summary>
    /// Through the real store, same input to both factories: the explicit one and the convention
    /// pick the same certificate. Everything added is removed in a <c>finally</c>.
    /// </summary>
    [Fact]
    public void CreateAndTryCreateFromEnvironment_UseTheSameStoreCertificate()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Skip("Persisting a private key in the user store is exercised on Windows only.");
            return;
        }

        var clientId = Guid.NewGuid().ToString();
        using var generated = ValidCert("CN=" + clientId);
        var pfx = generated.Export(X509ContentType.Pfx, "temp");
        using var persisted = new X509Certificate2(
            pfx, "temp", X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.UserKeySet);

        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadWrite);
        try
        {
            store.Add(persisted);

            using var explicitCredential = CertificateStoreCredential.Create(new CertificateStoreCredentialOptions(Tenant, clientId));
            Assert.Equal(persisted.Thumbprint, explicitCredential.Thumbprint);

            WithEnvironment(new[] { ("AZURE_TENANT_ID", Tenant), ("AZURE_CLIENT_ID", clientId) }, () =>
            {
                using var byConvention = CertificateStoreCredential.TryCreateFromEnvironment();
                Assert.NotNull(byConvention);
                Assert.Equal(persisted.Thumbprint, byConvention!.Thumbprint);
            });
        }
        finally
        {
            store.Remove(persisted);
            if (persisted.GetRSAPrivateKey() is RSACng cng)
                cng.Key.Delete();
        }
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

        using var credential = CertificateStoreCredential.TryCreateFromEnvironment(
            Env(("AZURE_TENANT_ID", Tenant), ("AZURE_CLIENT_ID", clientId)),
            StoreHolding(certificate), DateTimeOffset.UtcNow, credentialOptions);

        Assert.NotNull(credential);
    }
}
