using Xunit;

namespace KeyVaultReferenceResolver.HashiCorp.Tests
{
    /// <summary>
    /// Serializes the test classes that mutate the process-wide VAULT_* environment
    /// variables. Without this they race: one class clears VAULT_TOKEN while another
    /// is asserting on it.
    /// </summary>
    [CollectionDefinition("VaultEnvironment", DisableParallelization = true)]
    public class VaultEnvironmentCollection
    {
    }
}
