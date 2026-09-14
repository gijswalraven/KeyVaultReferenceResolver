using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace KeyVaultReferenceResolver.Testing
{
    /// <summary>
    /// An in-memory <see cref="ISecretResolver"/> for tests.
    /// </summary>
    /// <remarks>
    /// This lives in a test-only project rather than in the shipped package. Its predecessor,
    /// <c>KeyVaultReferenceResolver.MockSecretResolver</c>, shipped inside the library, where a
    /// dependency-injection or configuration mistake could wire it into a real application with no
    /// compile-time signal - and with <c>throwOnMissing: false</c> that application would start
    /// with empty passwords and API keys rather than failing. Nothing that can do that belongs in
    /// a production assembly, however well documented.
    /// </remarks>
    public class FakeSecretResolver : ISecretResolver
    {
        private readonly ConcurrentDictionary<string, string> _secrets;
        private readonly bool _throwOnMissing;

        /// <summary>
        /// Creates a new instance.
        /// </summary>
        /// <param name="secrets">Dictionary mapping secret URIs to their values.</param>
        /// <param name="throwOnMissing">
        /// If true, throws <see cref="KeyNotFoundException"/> when a secret is not found. Default
        /// is true. Setting it to false returns an empty string instead, which hides a missing
        /// secret - use it only in a test that is specifically about that behaviour.
        /// </param>
        public FakeSecretResolver(Dictionary<string, string> secrets, bool throwOnMissing = true)
        {
            ArgumentNullException.ThrowIfNull(secrets);

            // Concurrent, because reference resolution fetches secrets in parallel and a test may
            // add to the resolver while a resolution is in flight.
            _secrets = new ConcurrentDictionary<string, string>(secrets);
            _throwOnMissing = throwOnMissing;
        }

        /// <summary>
        /// Creates an empty resolver.
        /// </summary>
        public FakeSecretResolver() : this(new Dictionary<string, string>())
        {
        }

        /// <summary>
        /// Gets the number of secrets in the resolver.
        /// </summary>
        public int Count => _secrets.Count;

        /// <summary>
        /// Adds a secret to the resolver.
        /// </summary>
        /// <param name="secretUri">The secret URI.</param>
        /// <param name="value">The secret value.</param>
        /// <returns>This instance for chaining.</returns>
        public FakeSecretResolver AddSecret(string secretUri, string value)
        {
            _secrets[secretUri] = value;
            return this;
        }

        /// <summary>
        /// Adds multiple secrets to the resolver.
        /// </summary>
        /// <param name="secrets">Dictionary of secrets to add.</param>
        /// <returns>This instance for chaining.</returns>
        public FakeSecretResolver AddSecrets(Dictionary<string, string> secrets)
        {
            ArgumentNullException.ThrowIfNull(secrets);

            foreach (var kvp in secrets)
                _secrets[kvp.Key] = kvp.Value;

            return this;
        }

        /// <inheritdoc />
        public string ResolveSecret(string secretUri)
        {
            if (_secrets.TryGetValue(secretUri, out var value))
                return value;

            if (_throwOnMissing)
            {
                // Masked: this exception becomes the InnerException of the resolution failure that
                // the configuration extension logs, so an unmasked URI here would put the secret
                // name into the log by the back door.
                throw new KeyNotFoundException(
                    $"Secret not found: {KeyVaultReferenceResolutionException.MaskSecretUri(secretUri)}");
            }

            return string.Empty;
        }

        /// <inheritdoc />
        public Task<string> ResolveSecretAsync(string secretUri, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(ResolveSecret(secretUri));
        }

        /// <summary>
        /// Clears all secrets from the resolver.
        /// </summary>
        public void Clear() => _secrets.Clear();

        /// <summary>
        /// Checks if a secret URI exists in the resolver.
        /// </summary>
        /// <param name="secretUri">The secret URI to check.</param>
        /// <returns>True if the secret exists.</returns>
        public bool ContainsSecret(string secretUri) => _secrets.ContainsKey(secretUri);
    }
}
