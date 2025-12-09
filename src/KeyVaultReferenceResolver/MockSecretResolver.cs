using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace KeyVaultReferenceResolver
{
    /// <summary>
    /// A mock implementation of <see cref="ISecretResolver"/> for testing purposes.
    /// </summary>
    public class MockSecretResolver : ISecretResolver
    {
        private readonly Dictionary<string, string> _secrets;
        private readonly bool _throwOnMissing;

        /// <summary>
        /// Creates a new instance of <see cref="MockSecretResolver"/>.
        /// </summary>
        /// <param name="secrets">Dictionary mapping secret URIs to their values.</param>
        /// <param name="throwOnMissing">If true, throws KeyNotFoundException when a secret is not found. Default is true.</param>
        public MockSecretResolver(Dictionary<string, string> secrets, bool throwOnMissing = true)
        {
            _secrets = secrets ?? throw new ArgumentNullException(nameof(secrets));
            _throwOnMissing = throwOnMissing;
        }

        /// <summary>
        /// Creates an empty MockSecretResolver.
        /// </summary>
        public MockSecretResolver() : this(new Dictionary<string, string>())
        {
        }

        /// <summary>
        /// Adds a secret to the resolver.
        /// </summary>
        /// <param name="secretUri">The secret URI.</param>
        /// <param name="value">The secret value.</param>
        /// <returns>This instance for chaining.</returns>
        public MockSecretResolver AddSecret(string secretUri, string value)
        {
            _secrets[secretUri] = value;
            return this;
        }

        /// <summary>
        /// Adds multiple secrets to the resolver.
        /// </summary>
        /// <param name="secrets">Dictionary of secrets to add.</param>
        /// <returns>This instance for chaining.</returns>
        public MockSecretResolver AddSecrets(Dictionary<string, string> secrets)
        {
            foreach (var kvp in secrets)
            {
                _secrets[kvp.Key] = kvp.Value;
            }
            return this;
        }

        /// <inheritdoc />
        public string ResolveSecret(string secretUri)
        {
            if (_secrets.TryGetValue(secretUri, out var value))
            {
                return value;
            }

            if (_throwOnMissing)
            {
                throw new KeyNotFoundException($"Secret not found: {secretUri}");
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
        /// Gets the number of secrets in the resolver.
        /// </summary>
        public int Count => _secrets.Count;

        /// <summary>
        /// Checks if a secret URI exists in the resolver.
        /// </summary>
        /// <param name="secretUri">The secret URI to check.</param>
        /// <returns>True if the secret exists.</returns>
        public bool ContainsSecret(string secretUri) => _secrets.ContainsKey(secretUri);
    }
}
