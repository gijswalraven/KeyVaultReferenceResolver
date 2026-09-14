using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using KeyVaultReferenceResolver.Testing;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace KeyVaultReferenceResolver.Tests;

/// <summary>
/// Covers registration from a thread that has a <see cref="SynchronizationContext"/>.
/// </summary>
/// <remarks>
/// Configuration is built synchronously, so the asynchronous resolution has to be waited on.
/// The library's own awaits all use ConfigureAwait(false), so its continuations never need the
/// calling thread - but the ISecretResolver it awaits is supplied by the caller, and a resolver
/// that yields without ConfigureAwait(false) posts its continuation straight back to a thread
/// that is blocked waiting for it. Startup then hangs with no error at all, which is the worst
/// way for a credential-loading library to fail. Running the resolution on the thread pool means
/// there is no context to post back to in the first place.
/// </remarks>
public class SynchronizationContextTests
{
    private const string Reference = "@Microsoft.KeyVault(SecretUri=https://myvault.vault.azure.net/secrets/db-password)";

    [Fact]
    public void RegistrationCompletesUnderASingleThreadedSynchronizationContext()
    {
        using var context = new SingleThreadedSynchronizationContext();

        var completed = context.Run(() =>
        {
            var builder = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?> { ["Db:Password"] = Reference });

            builder.AddKeyVaultReferenceResolver(new ContextCapturingResolver());
            return builder.Build()["Db:Password"];
        });

        Assert.Equal("p@ssw0rd", completed);
    }

    [Fact]
    public void RegistrationStillWorksWithNoSynchronizationContext()
    {
        Assert.Null(SynchronizationContext.Current);

        var builder = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Db:Password"] = Reference });

        builder.AddKeyVaultReferenceResolver(new ContextCapturingResolver());

        Assert.Equal("p@ssw0rd", builder.Build()["Db:Password"]);
    }

    /// <summary>
    /// A caller-supplied resolver that yields without ConfigureAwait(false), so its continuation
    /// is posted to whatever SynchronizationContext was current when it was invoked. This is
    /// ordinary application code - most people do not write ConfigureAwait(false) in their own
    /// resolver - and it is what turns a blocking wait into a deadlock.
    /// </summary>
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
