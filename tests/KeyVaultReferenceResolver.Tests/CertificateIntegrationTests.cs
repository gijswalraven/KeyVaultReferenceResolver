using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Azure.Core;
using Azure.Identity;
using CertificateStoreCredentials;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
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
/// How the resolver uses the CertificateStoreCredential package: which credential wins, what
/// switches the environment convention off, and that the convention is logged. The certificate
/// lookup and validation rules themselves are tested in CertificateStoreCredential.Tests.
/// </summary>
/// <remarks>
/// The convention needs a certificate in a store, so those tests go through the real
/// <c>CurrentUser\My</c> store on Windows and remove everything they add in a <c>finally</c>.
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
    public void ExplicitCredential_BypassesTheConvention_ThroughTheExtension()
    {
        WithEnvironment(new[] { ("AZURE_TENANT_ID", Tenant), ("AZURE_CLIENT_ID", Guid.NewGuid().ToString()) }, () =>
        {
            // No certificate matches this client, so this only proves nothing throws and nothing is
            // looked up in a way that could; the Windows tests below prove the convention itself.
            new ConfigurationBuilder().AddKeyVaultReferenceResolver(new ClientSecretCredential(Tenant, "client", "not-used"));
        });
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

    [Fact]
    public void Convention_StaysOutOfTheWay_ForADeliberateManagedIdentityOrTenant()
    {
        WithEnvironment(new[] { ("AZURE_TENANT_ID", Tenant), ("AZURE_CLIENT_ID", "client") }, () =>
        {
            Assert.True(KeyVaultSecretResolver.ConventionApplies(new KeyVaultReferenceResolverOptions()));
            Assert.True(KeyVaultSecretResolver.ConventionApplies(new KeyVaultReferenceResolverOptions { TenantId = Tenant.ToUpperInvariant() }));
            Assert.False(KeyVaultSecretResolver.ConventionApplies(new KeyVaultReferenceResolverOptions { ManagedIdentityClientId = "mi-client" }));
            Assert.False(KeyVaultSecretResolver.ConventionApplies(new KeyVaultReferenceResolverOptions { TenantId = "another-tenant" }));
            Assert.False(KeyVaultSecretResolver.ConventionApplies(new KeyVaultReferenceResolverOptions { ExcludeEnvironmentCredential = true }));
        });
    }

    private static ConfigurationBuilder WithReference(ConfigurationBuilder builder)
    {
        builder.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Key"] = "@Microsoft.KeyVault(SecretUri=https://vault.vault.azure.net/secrets/name)"
        });
        return builder;
    }

    [Fact]
    public void ExcludeEnvironmentCredential_SwitchesTheConventionOff()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Skip("Persisting a private key in the user store is exercised on Windows only.");
            return;
        }

        var clientId = Guid.NewGuid().ToString();
        WithStoreCertificate(clientId, expired: true, _ =>
            WithEnvironment(new[] { ("AZURE_TENANT_ID", Tenant), ("AZURE_CLIENT_ID", clientId) }, () =>
            {
                // An expired certificate names the client, so the convention would throw if consulted.
                using var resolver = new KeyVaultSecretResolver(
                    new KeyVaultReferenceResolverOptions { ExcludeEnvironmentCredential = true }, logger: null, applyEnvironmentConvention: true);

                Assert.IsNotType<CertificateStoreCredential>(resolver.Credential);
            }));
    }

    [Fact]
    public void WithoutAMatchingCertificate_NothingChanges()
    {
        // e.g. a user-assigned managed identity: AZURE_CLIENT_ID is set for another reason.
        WithEnvironment(new[] { ("AZURE_TENANT_ID", Tenant), ("AZURE_CLIENT_ID", Guid.NewGuid().ToString()) }, () =>
        {
            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?> { ["Plain"] = "value" })
                .AddKeyVaultReferenceResolver()
                .Build();

            Assert.Equal("value", configuration["Plain"]);

            using var resolver = new KeyVaultSecretResolver(null, null, applyEnvironmentConvention: true);
            Assert.IsType<DefaultAzureCredential>(resolver.Credential);
        });
    }

    [Fact]
    public void WithoutAnyVariables_BehaviourIsUnchanged()
    {
        WithEnvironment(Array.Empty<(string, string)>(), () =>
        {
            var options = new KeyVaultReferenceResolverOptions();
            Assert.Null(options.ClientCertificate);

            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new[] { new KeyValuePair<string, string?>("Plain", "value") })
                .AddKeyVaultReferenceResolver(options, logger: null)
                .Build();

            Assert.Equal("value", configuration["Plain"]);

            var chain = KeyVaultSecretResolver.BuildCredentialOptions(new KeyVaultReferenceResolverOptions { AllowDeveloperCredentials = true });
            Assert.False(chain.ExcludeAzureCliCredential);
        });
    }

    /// <summary>A resolver built directly never reads the environment for an identity.</summary>
    [Fact]
    public void DirectConstruction_NeverAppliesTheConvention()
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
            }));
    }

    // ---- the convention through the resolver ----

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Convention_IsAppliedByTheExtension_AndFailsAtSetupWhenUnusable(bool expired)
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Skip("Persisting a private key in the user store is exercised on Windows only.");
            return;
        }

        var clientId = Guid.NewGuid().ToString();
        WithStoreCertificate(clientId, expired, thumbprint =>
            WithEnvironment(new[] { ("AZURE_TENANT_ID", Tenant), ("AZURE_CLIENT_ID", clientId) }, () =>
            {
                if (expired)
                {
                    var ex = Assert.Throws<InvalidOperationException>(
                        () => WithReference(new ConfigurationBuilder()).AddKeyVaultReferenceResolver());
                    Assert.Contains("expired", ex.Message);
                }
                else
                {
                    new ConfigurationBuilder().AddKeyVaultReferenceResolver();

                    using var resolver = new KeyVaultSecretResolver(null, null, applyEnvironmentConvention: true);
                    var credential = Assert.IsType<CertificateStoreCredential>(resolver.Credential);
                    Assert.Equal(thumbprint, credential.Thumbprint);
                }
            }));
    }

    [Fact]
    public void ClientCertificate_TakesPrecedenceOverTheConvention_AndBothUseThePackageCredential()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Skip("Persisting a private key in the user store is exercised on Windows only.");
            return;
        }

        var clientId = Guid.NewGuid().ToString();
        WithStoreCertificate(clientId, expired: false, thumbprint =>
            WithEnvironment(new[] { ("AZURE_TENANT_ID", Tenant), ("AZURE_CLIENT_ID", clientId) }, () =>
            {
                var settings = new CertificateStoreCredentialOptions(Tenant, clientId);

                using var explicitResolver = new KeyVaultSecretResolver(
                    new KeyVaultReferenceResolverOptions { ClientCertificate = settings }, null, applyEnvironmentConvention: true);
                using var conventionResolver = new KeyVaultSecretResolver(null, null, applyEnvironmentConvention: true);
                using var standalone = CertificateStoreCredential.Create(settings);

                // The resolver and a standalone consumer of the package pick the same certificate.
                var fromExplicit = Assert.IsType<CertificateStoreCredential>(explicitResolver.Credential);
                var fromConvention = Assert.IsType<CertificateStoreCredential>(conventionResolver.Credential);
                Assert.Equal(thumbprint, fromExplicit.Thumbprint);
                Assert.Equal(thumbprint, fromConvention.Thumbprint);
                Assert.Equal(thumbprint, standalone.Thumbprint);
            }));
    }

    // ---- logging ----

    [Fact]
    public void Convention_IsLoggedAsEvent1007_WithoutAnIdentifier()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Skip("Persisting a private key in the user store is exercised on Windows only.");
            return;
        }

        var clientId = Guid.NewGuid().ToString();
        var logger = new RecordingLogger();
        WithStoreCertificate(clientId, expired: false, thumbprint =>
            WithEnvironment(new[] { ("AZURE_TENANT_ID", Tenant), ("AZURE_CLIENT_ID", clientId) }, () =>
            {
                using var resolver = new KeyVaultSecretResolver(null, logger, applyEnvironmentConvention: true);

                var entry = Assert.Single(logger.Entries, e => e.EventId.Id == LogEvents.ClientCertificateFromEnvironmentId);
                Assert.Equal(LogLevel.Information, entry.Level);
                Assert.DoesNotContain(clientId, entry.Text);
                Assert.DoesNotContain(thumbprint, entry.Text);
            }));
    }

    [Fact]
    public void WithoutAConvention_Event1007IsNotLogged()
    {
        var logger = new RecordingLogger();
        WithEnvironment(Array.Empty<(string, string)>(), () =>
        {
            using var resolver = new KeyVaultSecretResolver(null, logger, applyEnvironmentConvention: true);

            Assert.DoesNotContain(logger.Entries, e => e.EventId.Id == LogEvents.ClientCertificateFromEnvironmentId);
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

    private sealed class RecordingLogger : ILogger
    {
        private readonly ConcurrentQueue<Entry> _entries = new();

        public IEnumerable<Entry> Entries => _entries;

        public IDisposable BeginScope<TState>(TState state) where TState : notnull => NullScope.Instance;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            _entries.Enqueue(new Entry(logLevel, eventId, formatter(state, exception)));
        }

        internal sealed record Entry(LogLevel Level, EventId EventId, string Text);

        private sealed class NullScope : IDisposable
        {
            public static readonly NullScope Instance = new();

            public void Dispose()
            {
            }
        }
    }
}
