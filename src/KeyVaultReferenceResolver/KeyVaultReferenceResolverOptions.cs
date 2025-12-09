using System;
using Azure.Core;

namespace KeyVaultReferenceResolver
{
    /// <summary>
    /// Options for configuring Key Vault reference resolution.
    /// </summary>
    public class KeyVaultReferenceResolverOptions
    {
        /// <summary>
        /// Gets or sets the Azure credential to use for authentication.
        /// If null, DefaultAzureCredential will be used.
        /// </summary>
        public TokenCredential? Credential { get; set; }

        /// <summary>
        /// Gets or sets whether to throw an exception when a secret cannot be resolved.
        /// Default is false (logs a warning and continues).
        /// </summary>
        public bool ThrowOnResolveFailure { get; set; } = false;

        /// <summary>
        /// Gets or sets the timeout for secret retrieval operations.
        /// Default is 30 seconds.
        /// </summary>
        public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);

        /// <summary>
        /// Gets or sets whether to cache resolved secrets in memory.
        /// Default is true.
        /// </summary>
        public bool EnableCaching { get; set; } = true;
    }
}
