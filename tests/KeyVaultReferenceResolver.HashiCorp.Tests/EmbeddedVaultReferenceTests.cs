using KeyVaultReferenceResolver.Testing;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace KeyVaultReferenceResolver.HashiCorp.Tests
{
    /// <summary>
    /// Covers a Vault reference embedded in a larger value, such as a connection string.
    /// </summary>
    /// <remarks>
    /// The whole configuration value used to be replaced by the secret, so
    /// <c>Server=db;Password=@HashiCorp.Vault(...)</c> resolved to the bare password and the
    /// connection string was destroyed. The Azure package already substituted in place; this makes
    /// the two behave the same.
    /// </remarks>
    public class EmbeddedVaultReferenceTests
    {
        private const string PasswordRef =
            "@HashiCorp.Vault(VaultAddress=https://vault.example.com;SecretPath=secret/data/myapp;SecretKey=password)";

        private const string UserRef =
            "@HashiCorp.Vault(VaultAddress=https://vault.example.com;SecretPath=secret/data/myapp;SecretKey=username)";

        [Fact]
        public void ReferenceInsideAConnectionString_KeepsTheSurroundingText()
        {
            var config = Build($"Server=db.example.com;User=app;Password={PasswordRef};Encrypt=true");

            Assert.Equal("Server=db.example.com;User=app;Password=p@ssw0rd;Encrypt=true", config["Db:Connection"]);
        }

        [Fact]
        public void TwoReferencesInOneValue_AreBothSubstituted()
        {
            var config = Build($"User={UserRef};Password={PasswordRef}");

            Assert.Equal("User=appuser;Password=p@ssw0rd", config["Db:Connection"]);
        }

        [Fact]
        public void WholeValueReference_ResolvesToTheSecretAlone()
        {
            var config = Build(PasswordRef);

            Assert.Equal("p@ssw0rd", config["Db:Connection"]);
        }

        [Fact]
        public void WholeValueUriFormReference_StillResolves()
        {
            const string uriRef = "hashicorp://vault.example.com/secret/data/myapp#password";

            var resolver = new FakeSecretResolver().AddSecret(uriRef, "p@ssw0rd");

            var builder = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?> { ["Db:Connection"] = uriRef });
            builder.AddHashiCorpVaultResolver(resolver);

            Assert.Equal("p@ssw0rd", builder.Build()["Db:Connection"]);
        }

        /// <summary>
        /// One unresolvable reference nulls the whole value: half a substituted connection string
        /// is worse than none, because it would be used.
        /// </summary>
        [Fact]
        public void OneUnresolvableReference_NullsTheWholeValue()
        {
            var resolver = new FakeSecretResolver().AddSecret(UserRef, "appuser");

            var builder = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Db:Connection"] = $"User={UserRef};Password={PasswordRef}"
                });

            builder.AddHashiCorpVaultResolver(
                resolver,
                new HashiCorpVaultResolverOptions { ThrowOnResolveFailure = false });

            var config = builder.Build();

            Assert.Null(config["Db:Connection"]);
            Assert.Empty(config.FindUnresolvedVaultReferences());
        }

        [Fact]
        public void TheSameReferenceOnTwoKeys_IsFetchedOnce()
        {
            var resolver = new CountingResolver().AddSecret(PasswordRef, "p@ssw0rd");

            var builder = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["First"] = PasswordRef,
                    ["Second"] = $"prefix-{PasswordRef}"
                });

            builder.AddHashiCorpVaultResolver(resolver);
            var config = builder.Build();

            Assert.Equal(1, resolver.Calls);
            Assert.Equal("p@ssw0rd", config["First"]);
            Assert.Equal("prefix-p@ssw0rd", config["Second"]);
        }

        private static IConfiguration Build(string value)
        {
            var resolver = new FakeSecretResolver()
                .AddSecret(PasswordRef, "p@ssw0rd")
                .AddSecret(UserRef, "appuser");

            var builder = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?> { ["Db:Connection"] = value });

            builder.AddHashiCorpVaultResolver(resolver);
            return builder.Build();
        }

        private sealed class CountingResolver : ISecretResolver
        {
            private readonly Dictionary<string, string> _secrets = new(StringComparer.Ordinal);
            private int _calls;

            public int Calls => _calls;

            public CountingResolver AddSecret(string reference, string value)
            {
                _secrets[reference] = value;
                return this;
            }

            public string ResolveSecret(string secretUri)
            {
                Interlocked.Increment(ref _calls);
                return _secrets[secretUri];
            }

            public Task<string> ResolveSecretAsync(string secretUri, CancellationToken cancellationToken = default) =>
                Task.FromResult(ResolveSecret(secretUri));
        }
    }
}
