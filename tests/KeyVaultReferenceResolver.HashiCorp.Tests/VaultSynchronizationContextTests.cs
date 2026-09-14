using KeyVaultReferenceResolver.Testing;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace KeyVaultReferenceResolver.HashiCorp.Tests
{
    /// <summary>
    /// Covers registration from a thread that has a <see cref="SynchronizationContext"/>.
    /// </summary>
    /// <remarks>
    /// The same exposure as on the Azure side: the resolution is awaited synchronously while the
    /// ISecretResolver belongs to the caller, so one that yields without ConfigureAwait(false)
    /// posts its continuation to the very thread that is blocked waiting for it, and startup hangs
    /// with no error. This package has its own copy of the guard, so it needs its own test.
    /// </remarks>
    public class VaultSynchronizationContextTests
    {
        private const string Reference =
            "@HashiCorp.Vault(VaultAddress=https://vault.example.com;SecretPath=secret/data/myapp;SecretKey=password)";

        [Fact]
        public void RegistrationCompletesUnderASingleThreadedSynchronizationContext()
        {
            using var context = new SingleThreadedSynchronizationContext();

            var resolved = context.Run(() =>
            {
                var builder = new ConfigurationBuilder()
                    .AddInMemoryCollection(new Dictionary<string, string?> { ["Db:Password"] = Reference });

                builder.AddHashiCorpVaultResolver(new ContextCapturingResolver());
                return builder.Build()["Db:Password"];
            });

            Assert.Equal("p@ssw0rd", resolved);
        }

        private sealed class ContextCapturingResolver : ISecretResolver
        {
            public async Task<string> ResolveSecretAsync(string secretUri, CancellationToken cancellationToken = default)
            {
                await Task.Yield();
                return "p@ssw0rd";
            }

            public string ResolveSecret(string secretUri) => "p@ssw0rd";
        }
    }
}
