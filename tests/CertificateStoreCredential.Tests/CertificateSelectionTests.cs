using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Xunit;

namespace CertificateStoreCredentials.Tests;

/// <summary>
/// Which store certificate is picked when settings name only the client ID: the stores are fed in
/// through the seam, so no machine store is touched.
/// </summary>
public class CertificateSelectionTests
{
    private const string Tenant = "00000000-0000-0000-0000-000000000001";
    private static readonly string Client = "5f1c2a90-7d3e-4b8a-9c11-0a2b3c4d5e6f";

    private static X509Certificate2 Cert(string subject, TimeSpan notBefore, TimeSpan notAfter)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var now = DateTimeOffset.UtcNow;
        return request.CreateSelfSigned(now + notBefore, now + notAfter);
    }

    private static X509Certificate2 ValidCert(string subject) =>
        Cert(subject, TimeSpan.FromDays(-1), TimeSpan.FromDays(30));

    private static CertificateStoreCredentialOptions Find(
        Func<StoreLocation, X509Certificate2Collection> stores) =>
        CertificateStoreLoader.Resolve(new CertificateStoreCredentialOptions(Tenant, Client), stores, DateTimeOffset.UtcNow);

    private static Func<StoreLocation, X509Certificate2Collection> Stores(
        X509Certificate2[]? currentUser = null, X509Certificate2[]? localMachine = null) =>
        location => new X509Certificate2Collection(
            (location == StoreLocation.CurrentUser ? currentUser : localMachine) ?? Array.Empty<X509Certificate2>());

    // ---- discovery ----

    [Fact]
    public void CertificateWhoseSubjectIsTheClientId_IsFound()
    {
        using var certificate = ValidCert("CN=" + Client);
        var thumbprint = certificate.Thumbprint;

        var settings = Find(Stores(new[] { certificate }));

        Assert.Equal(Tenant, settings.TenantId);
        Assert.Equal(Client, settings.ClientId);
        Assert.Equal(thumbprint, settings.Thumbprint);
        Assert.Equal(StoreLocation.CurrentUser, settings.StoreLocation);
    }

    [Fact]
    public void SubjectContainingTheClientId_MatchesCaseInsensitively()
    {
        using var certificate = ValidCert("CN=kv-" + Client.ToUpperInvariant() + ", O=Contoso");

        var settings = Find(Stores(new[] { certificate }));

        Assert.NotNull(settings);
    }

    [Fact]
    public void ValidCertificate_BeatsAnExpiredOne()
    {
        using var expired = Cert("CN=" + Client, TimeSpan.FromDays(-400), TimeSpan.FromDays(-35));
        using var valid = ValidCert("CN=" + Client);
        var validThumbprint = valid.Thumbprint;

        var settings = Find(Stores(new[] { expired, valid }));

        Assert.Equal(validThumbprint, settings.Thumbprint);
    }

    [Fact]
    public void AmongValidCertificates_TheOneExpiringLastWins()
    {
        using var older = Cert("CN=" + Client, TimeSpan.FromDays(-60), TimeSpan.FromDays(5));
        using var renewed = Cert("CN=" + Client, TimeSpan.FromDays(-1), TimeSpan.FromDays(300));
        var renewedThumbprint = renewed.Thumbprint;

        var settings = Find(Stores(new[] { older, renewed }));

        Assert.Equal(renewedThumbprint, settings.Thumbprint);
    }

    /// <summary>
    /// When the only match is unusable it is still returned, so loading it fails with the
    /// specific reason instead of silently falling back to the default chain.
    /// </summary>
    [Fact]
    public void OnlyAnExpiredMatch_IsStillReturned_SoTheFailureIsSpecific()
    {
        using var expired = Cert("CN=" + Client, TimeSpan.FromDays(-400), TimeSpan.FromDays(-35));
        var thumbprint = expired.Thumbprint;

        var settings = Find(Stores(new[] { expired }));

        Assert.Equal(thumbprint, settings.Thumbprint);
    }

    [Fact]
    public void FallsThroughToLocalMachine_WhenCurrentUserHasNoMatch()
    {
        using var certificate = ValidCert("CN=" + Client);

        var settings = Find(Stores(localMachine: new[] { certificate }));

        Assert.Equal(StoreLocation.LocalMachine, settings.StoreLocation);
    }

    /// <summary>
    /// A stale certificate in CurrentUser must not mask a valid one in LocalMachine: that is what
    /// rotation leaves behind when the renewed certificate lands in the machine store.
    /// </summary>
    [Fact]
    public void ValidCertificateInLocalMachine_BeatsAnExpiredOneInCurrentUser()
    {
        using var expired = Cert("CN=" + Client, TimeSpan.FromDays(-400), TimeSpan.FromDays(-35));
        using var valid = ValidCert("CN=" + Client);
        var validThumbprint = valid.Thumbprint;

        var settings = Find(Stores(currentUser: new[] { expired }, localMachine: new[] { valid }));

        Assert.Equal(validThumbprint, settings.Thumbprint);
        Assert.Equal(StoreLocation.LocalMachine, settings.StoreLocation);
    }
}
