using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Azure.Identity;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace KeyVaultReferenceResolver.Tests;

/// <summary>
/// Tests that change the process-wide AZURE_* variables. A collection of its own, with
/// parallelization disabled, so they cannot race with anything that reads the environment.
/// </summary>
[CollectionDefinition("AzureEnvironment", DisableParallelization = true)]
public class AzureEnvironmentCollection
{
}

/// <summary>
/// The environment convention: with AZURE_TENANT_ID and AZURE_CLIENT_ID set, a store certificate
/// whose subject contains the client ID is used, without any option set in code.
/// </summary>
[Collection("AzureEnvironment")]
public class CertificateConventionTests
{
    private const string Tenant = "00000000-0000-0000-0000-000000000001";
    private static readonly string Client = "5f1c2a90-7d3e-4b8a-9c11-0a2b3c4d5e6f";

    private static readonly string[] Variables =
    {
        "AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET",
        "AZURE_CLIENT_CERTIFICATE_PATH", "AZURE_FEDERATED_TOKEN_FILE"
    };

    private static readonly (string, string)[] ConventionEnvironment =
    {
        ("AZURE_TENANT_ID", Tenant),
        ("AZURE_CLIENT_ID", "5f1c2a90-7d3e-4b8a-9c11-0a2b3c4d5e6f")
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

    private static Func<StoreLocation, X509Certificate2Collection> Stores(
        X509Certificate2[]? currentUser = null, X509Certificate2[]? localMachine = null) =>
        location => new X509Certificate2Collection(
            (location == StoreLocation.CurrentUser ? currentUser : localMachine) ?? Array.Empty<X509Certificate2>());

    private static Func<StoreLocation, X509Certificate2Collection> NoStoreAccess =>
        _ => throw new InvalidOperationException("The store must not be read.");

    /// <summary>Sets the AZURE_* variables for the duration of <paramref name="body"/>, then restores them.</summary>
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

    // ---- discovery ----

    [Fact]
    public void CertificateWhoseSubjectIsTheClientId_IsFound()
    {
        using var certificate = ValidCert("CN=" + Client);
        var thumbprint = certificate.Thumbprint;

        var settings = CertificateStoreLoader.FromEnvironment(
            Env(("AZURE_TENANT_ID", Tenant), ("AZURE_CLIENT_ID", Client)),
            Stores(new[] { certificate }), DateTimeOffset.UtcNow);

        Assert.NotNull(settings);
        Assert.Equal(Tenant, settings!.TenantId);
        Assert.Equal(Client, settings.ClientId);
        Assert.Equal(thumbprint, settings.Thumbprint);
        Assert.Equal(StoreLocation.CurrentUser, settings.StoreLocation);
    }

    [Fact]
    public void SubjectContainingTheClientId_MatchesCaseInsensitively()
    {
        using var certificate = ValidCert("CN=kv-" + Client.ToUpperInvariant() + ", O=Contoso");

        var settings = CertificateStoreLoader.FromEnvironment(
            Env(("AZURE_TENANT_ID", Tenant), ("AZURE_CLIENT_ID", Client)),
            Stores(new[] { certificate }), DateTimeOffset.UtcNow);

        Assert.NotNull(settings);
    }

    [Fact]
    public void NoCertificateNamesTheClient_MeansNoConvention()
    {
        using var other = ValidCert("CN=somebody-else");

        Assert.Null(CertificateStoreLoader.FromEnvironment(
            Env(("AZURE_TENANT_ID", Tenant), ("AZURE_CLIENT_ID", Client)),
            Stores(new[] { other }), DateTimeOffset.UtcNow));
    }

    [Theory]
    [InlineData("AZURE_TENANT_ID")]
    [InlineData("AZURE_CLIENT_ID")]
    public void MissingTenantOrClient_MeansNoConvention_WithoutReadingTheStore(string present)
    {
        Assert.Null(CertificateStoreLoader.FromEnvironment(
            Env((present, "x")), NoStoreAccess, DateTimeOffset.UtcNow));
    }

    [Theory]
    [InlineData("AZURE_CLIENT_SECRET")]
    [InlineData("AZURE_CLIENT_CERTIFICATE_PATH")]
    [InlineData("AZURE_FEDERATED_TOKEN_FILE")]
    public void AnotherConfiguredMechanism_KeepsTheConventionOut(string variable)
    {
        Assert.Null(CertificateStoreLoader.FromEnvironment(
            Env(("AZURE_TENANT_ID", Tenant), ("AZURE_CLIENT_ID", Client), (variable, "x")),
            NoStoreAccess, DateTimeOffset.UtcNow));
    }

    [Fact]
    public void ValidCertificate_BeatsAnExpiredOne()
    {
        using var expired = Cert("CN=" + Client, TimeSpan.FromDays(-400), TimeSpan.FromDays(-35));
        using var valid = ValidCert("CN=" + Client);
        var validThumbprint = valid.Thumbprint;

        var settings = CertificateStoreLoader.FromEnvironment(
            Env(("AZURE_TENANT_ID", Tenant), ("AZURE_CLIENT_ID", Client)),
            Stores(new[] { expired, valid }), DateTimeOffset.UtcNow);

        Assert.Equal(validThumbprint, settings!.Thumbprint);
    }

    [Fact]
    public void AmongValidCertificates_TheOneExpiringLastWins()
    {
        using var older = Cert("CN=" + Client, TimeSpan.FromDays(-60), TimeSpan.FromDays(5));
        using var renewed = Cert("CN=" + Client, TimeSpan.FromDays(-1), TimeSpan.FromDays(300));
        var renewedThumbprint = renewed.Thumbprint;

        var settings = CertificateStoreLoader.FromEnvironment(
            Env(("AZURE_TENANT_ID", Tenant), ("AZURE_CLIENT_ID", Client)),
            Stores(new[] { older, renewed }), DateTimeOffset.UtcNow);

        Assert.Equal(renewedThumbprint, settings!.Thumbprint);
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

        var settings = CertificateStoreLoader.FromEnvironment(
            Env(("AZURE_TENANT_ID", Tenant), ("AZURE_CLIENT_ID", Client)),
            Stores(new[] { expired }), DateTimeOffset.UtcNow);

        Assert.Equal(thumbprint, settings!.Thumbprint);
    }

    [Fact]
    public void FallsThroughToLocalMachine_WhenCurrentUserHasNoMatch()
    {
        using var certificate = ValidCert("CN=" + Client);

        var settings = CertificateStoreLoader.FromEnvironment(
            Env(("AZURE_TENANT_ID", Tenant), ("AZURE_CLIENT_ID", Client)),
            Stores(localMachine: new[] { certificate }), DateTimeOffset.UtcNow);

        Assert.Equal(StoreLocation.LocalMachine, settings!.StoreLocation);
    }

    // ---- wiring through AddKeyVaultReferenceResolver ----

    [Fact]
    public void TenantAndClientSetButNoCertificate_FallsBackToTheDefaultChain()
    {
        // e.g. a user-assigned managed identity: AZURE_CLIENT_ID is set for another reason.
        WithEnvironment(new[] { ("AZURE_TENANT_ID", Tenant), ("AZURE_CLIENT_ID", Guid.NewGuid().ToString()) }, () =>
        {
            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?> { ["Plain"] = "value" })
                .AddKeyVaultReferenceResolver()
                .Build();

            Assert.Equal("value", configuration["Plain"]);
        });
    }

    [Fact]
    public void ExplicitCredential_BypassesTheConvention_AndExcludeEnvironmentSwitchesItOff()
    {
        WithEnvironment(ConventionEnvironment, () =>
        {
            new ConfigurationBuilder().AddKeyVaultReferenceResolver(new ClientSecretCredential(Tenant, Client, "not-used"));
            new ConfigurationBuilder().AddKeyVaultReferenceResolver(
                new KeyVaultReferenceResolverOptions { ExcludeEnvironmentCredential = true }, logger: null);
        });
    }

    /// <summary>
    /// Through the real store: a persisted certificate named after the client ID is found by the
    /// convention (an expired one proves it, by failing with the specific reason), and everything
    /// added is removed again in a <c>finally</c>.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void CertificateInCurrentUserStore_IsFoundByTheConvention(bool expired)
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

            WithEnvironment(new[] { ("AZURE_TENANT_ID", Tenant), ("AZURE_CLIENT_ID", clientId) }, () =>
            {
                if (expired)
                {
                    var ex = Assert.Throws<InvalidOperationException>(
                        () => new ConfigurationBuilder().AddKeyVaultReferenceResolver());
                    Assert.Contains("expired", ex.Message);
                }
                else
                {
                    new ConfigurationBuilder().AddKeyVaultReferenceResolver();
                }
            });
        }
        finally
        {
            store.Remove(persisted);
            if (persisted.GetRSAPrivateKey() is RSACng cng)
                cng.Key.Delete();
        }
    }
}
