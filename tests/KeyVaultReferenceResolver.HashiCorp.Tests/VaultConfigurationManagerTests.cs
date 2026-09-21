using Microsoft.Extensions.Configuration;
using Xunit;
using KeyVaultReferenceResolver.Testing;

namespace KeyVaultReferenceResolver.HashiCorp.Tests
{
    /// <summary>
    /// Resolution against <see cref="ConfigurationManager"/>, the type behind
    /// <c>Host.CreateApplicationBuilder().Configuration</c>.
    /// </summary>
    /// <remarks>
    /// It is builder and root at once and its <c>Build()</c> returns itself, so disposing the
    /// temporary root the resolver builds would dispose the caller's own configuration. The
    /// Azure-side extension had this bug; this is the matching guard on the HashiCorp side.
    /// </remarks>
    public class VaultConfigurationManagerTests
    {
        private const string PasswordRef =
            "@HashiCorp.Vault(VaultAddress=https://vault.example.com;SecretPath=secret/data/myapp;SecretKey=password)";

        private static FakeSecretResolver Resolver() =>
            new FakeSecretResolver().AddSecret(PasswordRef, "p@ssw0rd");

        private static ConfigurationManager ManagerWith(params (string Key, string Value)[] values)
        {
            var manager = new ConfigurationManager();
            var pairs = new Dictionary<string, string?>();
            foreach (var (key, value) in values)
                pairs[key] = value;

            ((IConfigurationBuilder)manager).AddInMemoryCollection(pairs);
            return manager;
        }

        [Fact]
        public void AddHashiCorpVaultResolver_OnConfigurationManager_DoesNotThrow()
        {
            var manager = ManagerWith(("Db:Password", PasswordRef));

            ((IConfigurationBuilder)manager).AddHashiCorpVaultResolver(Resolver());

            Assert.Equal("p@ssw0rd", manager["Db:Password"]);
        }

        [Fact]
        public void AddHashiCorpVaultResolver_OnConfigurationManager_LeavesItUsable()
        {
            var manager = ManagerWith(("Db:Password", PasswordRef), ("Plain", "literal"));

            ((IConfigurationBuilder)manager).AddHashiCorpVaultResolver(Resolver());

            Assert.Equal("literal", manager["Plain"]);

            ((IConfigurationBuilder)manager).AddInMemoryCollection(
                new Dictionary<string, string?> { ["Added:Later"] = "value" });

            Assert.Equal("value", manager["Added:Later"]);
            Assert.Equal("p@ssw0rd", manager["Db:Password"]);
        }

        [Fact]
        public void AddHashiCorpVaultResolver_OnConfigurationManager_WithNoReferences_LeavesItUsable()
        {
            var manager = ManagerWith(("Plain", "literal"));

            ((IConfigurationBuilder)manager).AddHashiCorpVaultResolver(Resolver());

            Assert.Equal("literal", manager["Plain"]);
        }
    }
}
