using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Azure.Core;
using Azure.Identity;
using CertificateStoreCredentials;
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
/// How the resolver uses the CertificateStoreCredential package: which credential wins, and that
/// the environment is never consulted for a certificate. The certificate lookup and validation
/// rules themselves are tested in CertificateStoreCredential.Tests.
/// </summary>
/// <remarks>
/// Tests that need a certificate in a store go through the real <c>CurrentUser\My</c> store on
/// Windows and remove everything they add in a <c>finally</c>.
/// </remarks>
[Collection("AzureEnvironment")]
public class CertificateIntegrationTests
{
    private const string Tenant = "00000000-0000-0000-0000-000000000001";
    private static readonly string[] ExpectedTenants = { "tenant-a", "tenant-b" };

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

    /// <summary>
    /// Puts a persisted certificate named after <paramref name="clientId"/> into CurrentUser\My for
    /// the duration of <paramref name="body"/> and removes it, and its key container, afterwards.
    /// </summary>
    private static void WithStoreCertificate(string clientId, bool expired, Action<string> body)
    {
        using var generated = expired
            ? Cert("CN=" + clientId, TimeSpan.FromDays(-400), TimeSpan.FromDays(-35))
            : Cert("CN=" + clientId, TimeSpan.FromDays(-1), TimeSpan.FromDays(30));
        var pfx = generated.Export(X509ContentType.Pfx, "temp");
        using var persisted = new X509Certificate2(
            pfx, "temp", X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.UserKeySet);

        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadWrite);
        try
        {
            store.Add(persisted);
            body(persisted.Thumbprint);
        }
        finally
        {
            store.Remove(persisted);
            if (OperatingSystem.IsWindows() && persisted.GetRSAPrivateKey() is RSACng cng)
                cng.Key.Delete();
        }
    }

    // ---- precedence ----

    [Fact]
    public void ExplicitCredential_WinsOverClientCertificate()
    {
        var credential = new ClientSecretCredential(Tenant, "client", "not-used");
        using var resolver = new KeyVaultSecretResolver(new KeyVaultReferenceResolverOptions
        {
            Credential = credential,
            // Would throw if it were consulted.
            ClientCertificate = new CertificateStoreCredentialOptions(Tenant, Guid.NewGuid().ToString())
        });

        Assert.Same(credential, resolver.Credential);
    }

    [Fact]
    public void ClientCertificate_NotInStore_FailsWhenTheResolverIsCreated()
    {
        var settings = new CertificateStoreCredentialOptions(Tenant, "client", Guid.NewGuid().ToString("N") + "ABCDEF01");
        var options = new KeyVaultReferenceResolverOptions { ClientCertificate = settings };

        var ex = Assert.Throws<InvalidOperationException>(() => new KeyVaultSecretResolver(options));
        Assert.Contains(settings.Thumbprint!, ex.Message);

        Assert.Throws<InvalidOperationException>(
            () => WithReference(new ConfigurationBuilder()).AddKeyVaultReferenceResolver(options, logger: null));
    }

    [Fact]
    public void ClientCertificate_NotInStore_DoesNotFailWhenNothingReferencesAVault()
    {
        var settings = new CertificateStoreCredentialOptions(Tenant, "client", Guid.NewGuid().ToString("N") + "ABCDEF01");
        var options = new KeyVaultReferenceResolverOptions { ClientCertificate = settings };

        // The resolver, and with it the certificate, is only built once there is a reference to resolve.
        new ConfigurationBuilder().AddKeyVaultReferenceResolver(options, logger: null);
    }

    private static ConfigurationBuilder WithReference(ConfigurationBuilder builder)
    {
        builder.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Key"] = "@Microsoft.KeyVault(SecretUri=https://vault.vault.azure.net/secrets/name)"
        });
        return builder;
    }

    /// <summary>
    /// AZURE_TENANT_ID and AZURE_CLIENT_ID no longer select a store certificate: with a matching
    /// certificate in the store, the resolver, built directly or by the extension, still uses the
    /// default chain.
    /// </summary>
    [Fact]
    public void EnvironmentVariables_NeverSelectAStoreCertificate()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Skip("Persisting a private key in the user store is exercised on Windows only.");
            return;
        }

        var clientId = Guid.NewGuid().ToString();
        WithStoreCertificate(clientId, expired: false, _ =>
            WithEnvironment(new[] { ("AZURE_TENANT_ID", Tenant), ("AZURE_CLIENT_ID", clientId) }, () =>
            {
                using var resolver = new KeyVaultSecretResolver(new KeyVaultReferenceResolverOptions());
                Assert.IsType<DefaultAzureCredential>(resolver.Credential);

                // The extension resolves nothing here, but must not load the certificate either.
                new ConfigurationBuilder().AddKeyVaultReferenceResolver();
            }));
    }

    [Fact]
    public void ClientCertificate_UsesThePackageCredential_AndPicksTheSameCertificateAsAStandaloneOne()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Skip("Persisting a private key in the user store is exercised on Windows only.");
            return;
        }

        var clientId = Guid.NewGuid().ToString();
        WithStoreCertificate(clientId, expired: false, thumbprint =>
        {
            var settings = new CertificateStoreCredentialOptions(Tenant, clientId);

            using var resolver = new KeyVaultSecretResolver(
                new KeyVaultReferenceResolverOptions { ClientCertificate = settings });
            using var standalone = CertificateStoreCredential.Create(settings);

            var fromResolver = Assert.IsType<CertificateStoreCredential>(resolver.Credential);
            Assert.Equal(thumbprint, fromResolver.Thumbprint);
            Assert.Equal(thumbprint, standalone.Thumbprint);
        });
    }

    // ---- options passed to the wrapped credential ----

    [Fact]
    public void ResolverOptions_AreCarriedIntoTheStoreCertificateCredentialOptions()
    {
        var options = new KeyVaultReferenceResolverOptions
        {
            AuthorityHost = new Uri("https://login.microsoftonline.us/"),
            AdditionallyAllowedTenants = new List<string> { "tenant-a", "tenant-b" },
            ClientOptions = new Azure.Security.KeyVault.Secrets.SecretClientOptions
            {
                Retry = { MaxRetries = 7, Delay = TimeSpan.FromSeconds(3), MaxDelay = TimeSpan.FromSeconds(40), Mode = RetryMode.Fixed, NetworkTimeout = TimeSpan.FromSeconds(11) }
            }
        };

        var credentialOptions = KeyVaultSecretResolver.BuildClientCertificateCredentialOptions(options);

        Assert.Equal(options.AuthorityHost, credentialOptions.AuthorityHost);
        Assert.Equal(ExpectedTenants, credentialOptions.AdditionallyAllowedTenants);
        Assert.Equal(7, credentialOptions.Retry.MaxRetries);
        Assert.Equal(TimeSpan.FromSeconds(3), credentialOptions.Retry.Delay);
        Assert.Equal(TimeSpan.FromSeconds(40), credentialOptions.Retry.MaxDelay);
        Assert.Equal(RetryMode.Fixed, credentialOptions.Retry.Mode);
        Assert.Equal(TimeSpan.FromSeconds(11), credentialOptions.Retry.NetworkTimeout);
    }

    [Fact]
    public void WithoutResolverOptions_TheAzureIdentityDefaultsRemain()
    {
        var credentialOptions = KeyVaultSecretResolver.BuildClientCertificateCredentialOptions(new KeyVaultReferenceResolverOptions());

        Assert.Empty(credentialOptions.AdditionallyAllowedTenants);
        Assert.Equal(new ClientCertificateCredentialOptions().Retry.MaxRetries, credentialOptions.Retry.MaxRetries);
    }
}
