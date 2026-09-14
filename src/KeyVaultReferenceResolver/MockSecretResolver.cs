using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.Threading;
using System.Threading.Tasks;

namespace KeyVaultReferenceResolver
{
    /// <summary>
    /// A mock implementation of <see cref="ISecretResolver"/> for testing purposes.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Test use only. Never register this in an application that runs in production.</b>
    /// </para>
    /// <para>
    /// It ships inside the main package for convenience, so a dependency-injection or
    /// configuration mistake can wire it into a real application with no compile-time signal.
    /// With <c>throwOnMissing: false</c> it returns an empty string for every secret it does not
    /// know, which means an application would start with empty passwords and API keys rather than
    /// failing - so guard the registration with an environment check, and prefer
    /// <c>throwOnMissing: true</c> (the default) so a missing secret is loud.
    /// </para>
    /// <para>
    /// Hidden from IntelliSense to reduce the chance of it being reached for by accident.
    /// </para>
    /// <para>
    /// Deprecated. Hiding it from IntelliSense never stopped a dependency-injection registration,
    /// and no amount of documentation makes a type that can hand an application empty passwords
    /// safe to ship inside the library. Use <c>KeyVaultReferenceResolver.Testing.FakeSecretResolver</c>,
    /// which is identical but lives in a test-only assembly. This type is removed in 2.0.
    /// </para>
    /// </remarks>
    [EditorBrowsable(EditorBrowsableState.Never)]
    [Obsolete("Use KeyVaultReferenceResolver.Testing.FakeSecretResolver from the TestSupport project instead. " +
              "A test double that returns empty secrets should not ship inside the library; this type is removed in 2.0.")]
    public class MockSecretResolver : ISecretResolver
    {
        private readonly ConcurrentDictionary<string, string> _secrets;
        private readonly bool _throwOnMissing;

        /// <summary>
        /// Creates a new instance of <see cref="MockSecretResolver"/>.
        /// </summary>
        /// <param name="secrets">Dictionary mapping secret URIs to their values.</param>
        /// <param name="throwOnMissing">
        /// If true, throws KeyNotFoundException when a secret is not found. Default is true.
        /// Setting it to false returns an empty string instead, which hides missing secrets.
        /// </param>
        public MockSecretResolver(Dictionary<string, string> secrets, bool throwOnMissing = true)
        {
            if (secrets == null)
                throw new ArgumentNullException(nameof(secrets));

            // Concurrent, because reference resolution now fetches secrets in parallel and a
            // test may add to the resolver while a resolution is in flight.
            _secrets = new ConcurrentDictionary<string, string>(secrets);
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
                // Masked: this exception becomes the InnerException of the resolution failure
                // that the configuration extension logs, so an unmasked URI here puts the
                // secret name into the log by the back door.
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
