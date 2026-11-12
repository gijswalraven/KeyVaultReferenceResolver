# HOWTO: Migrate from App Service Key Vault References or AddAzureKeyVault

## Overview and Purpose

This guide moves an application that gets its secrets from Azure Key Vault in one of two other ways onto KeyVaultReferenceResolver:

- **App Service Key Vault references**: `@Microsoft.KeyVault(...)` strings in application settings, resolved by the App Service platform.
- **`AddAzureKeyVault`**: the configuration provider (from the `Azure.Extensions.AspNetCore.Configuration.Secrets` package) that loads vault secrets into `IConfiguration`.

The two sources work differently, so the migration differs. The App Service syntax is the one this library reads, so that route is mostly a matter of registering the resolver. `AddAzureKeyVault` maps secret *names* to configuration keys, and this library maps configuration *values* (references) to secrets, so each key needs a reference written for it.

Statements about Microsoft's own behaviour in this guide are limited to what is certain; anything that depends on the exact version or platform is marked **verify**.

## What Changes

| | App Service references | `AddAzureKeyVault` | This library |
| --- | --- | --- | --- |
| Where the secret is named | In the setting value, as a reference | In the vault: the secret name becomes the configuration key | In the configuration value, as a reference |
| Who resolves it | The App Service platform, before the process starts | A configuration provider, at build time | `AddKeyVaultReferenceResolver`, at build time |
| Works outside App Service | No | Yes | Yes (local, Docker, Kubernetes, Scheduled Task) |
| Secrets loaded | Only those referenced | All enabled secrets in the vault, unless filtered | Only those referenced |
| Rotation | Platform-managed (verify the refresh behaviour for your plan) | Optional periodic reload (`ReloadInterval`; verify) | Not reloaded; see [Pick-Up-Rotated-Secrets-HOWTO.md](../Operations/Pick-Up-Rotated-Secrets-HOWTO.md) |

## Reference Formats Supported

Both App Service formats are supported unchanged, so a value that works under App Service works as is:

```text
@Microsoft.KeyVault(SecretUri=https://myvault.vault.azure.net/secrets/db-connection)
@Microsoft.KeyVault(SecretUri=https://myvault.vault.azure.net/secrets/api-key/abc123def456)
@Microsoft.KeyVault(VaultName=myvault;SecretName=db-connection)
@Microsoft.KeyVault(VaultName=myvault;SecretName=api-key;SecretVersion=abc123def456)
```

- A version pins the secret; without one, the current version is read at startup.
- The `VaultName` groups follow Azure's naming rules and nothing else: vault 3 to 24 letters, digits or hyphens; secret up to 127; version up to 64 letters or digits. A value outside these is not treated as a reference: it is left exactly as written, and `AssertNoUnresolvedReferences()` does not flag it either, because it uses the same patterns.
- A reference may be embedded in a longer value (`Server=db;Password=@Microsoft.KeyVault(...)`) and a value may hold several. If any reference in a value fails to resolve, the whole value becomes `null`.
- Keywords are case-insensitive; secret names are case-sensitive.

Details and the HashiCorp formats are in [Reference-Formats.md](../Features/Reference-Formats.md).

## Prerequisites

- The application already authenticates to the vault with an identity that has `Key Vault Secrets User` (or `Get` on secrets).
- KeyVaultReferenceResolver 2.0.1 or later if the application uses `Host.CreateApplicationBuilder()` or `WebApplication.CreateBuilder()` (earlier versions threw `ObjectDisposedException` on those builders).
- The set of secrets the application reads, with the configuration key that holds each.

## Step 1: Register the resolver, last

```csharp
var builder = Host.CreateApplicationBuilder(args);
// ... every other configuration source first ...
builder.Configuration.AddKeyVaultReferenceResolver();
```

Register it **after every source that might carry a reference**. A source added later overrides the resolved values and is never itself resolved, so the application would read the literal `@Microsoft.KeyVault(...)` string and use it as a credential. The resolver detects this and throws `KeyVaultReferenceResolutionException` when the configuration is built.

## Step 2a: From App Service references

The reference strings already exist in your app settings. Move them to wherever the new environment keeps settings.

1. Copy each setting that holds a reference into the new environment: `appsettings.json`, environment variables (`ConnectionStrings__Db` for the key `ConnectionStrings:Db`), or a mounted file.
2. Leave the value exactly as it is, the reference string.
3. Deploy. On App Service the platform replaces the reference with the secret before the process starts, so the library sees a plain value and does nothing there (**verify** on your plan). That makes an incremental migration safe: the same build runs on App Service and elsewhere.

If the app uses a user-assigned managed identity, set `ManagedIdentityClientId` (see Step 3). App Service chooses the identity for references with its own site setting (**verify**), and this library does not read that setting.

## Step 2b: From AddAzureKeyVault

`AddAzureKeyVault` turns the secret name into the key, normally by replacing `--` with `:` (**verify** for the version in use). For each secret the application actually reads, write the reference under that key:

```csharp
// Before
builder.Configuration.AddAzureKeyVault(new Uri("https://myvault.vault.azure.net/"), new DefaultAzureCredential());
```

```json
{
  "ConnectionStrings": {
    "Db": "@Microsoft.KeyVault(VaultName=myvault;SecretName=ConnectionStrings--Db)"
  },
  "Payments": {
    "ApiKey": "@Microsoft.KeyVault(VaultName=myvault;SecretName=Payments--ApiKey)"
  }
}
```

```csharp
// After
builder.Configuration.AddKeyVaultReferenceResolver();
```

1. List the keys the application reads from the vault. A provider that loads everything hides this; search the code for the configuration keys, or list the vault's secrets and match them.
2. Add a reference per key, as above. Use `SecretUri=` instead if a name does not fit the `VaultName` rules.
3. Replace the `AddAzureKeyVault` call with `AddKeyVaultReferenceResolver()`, still registered last.
4. Secrets nobody references are no longer loaded. Anything that read one through `IConfiguration` without you noticing now gets `null`.
5. If the application relied on `ReloadInterval`, there is no equivalent here. Use the patterns in [Pick-Up-Rotated-Secrets-HOWTO.md](../Operations/Pick-Up-Rotated-Secrets-HOWTO.md).
6. `AddAzureKeyVault` needs permission to list secrets; this library only reads the named ones. With access policies you can narrow to `Get`.

## Step 3: Set the identity options explicitly

The default is `DefaultAzureCredential`, narrowed:

| Option | Set it to | Why |
| --- | --- | --- |
| `ManagedIdentityClientId` | The user-assigned identity's client ID | A host with more than one managed identity cannot choose on its own |
| `ExcludeEnvironmentCredential` | `true` where the app uses a managed or workload identity | The environment credential (`AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_CLIENT_SECRET`) sits ahead of managed identity, so anyone who can set those variables could redirect vault access. Defaults to `false` for backwards compatibility |
| `AllowDeveloperCredentials` | `true` for local development only | Azure CLI, Visual Studio and similar credentials are off by default |
| `VaultDnsSuffix` and `AuthorityHost` | The sovereign cloud values | `VaultName` references compose the host from the suffix |

```csharp
builder.Configuration.AddKeyVaultReferenceResolver(options =>
{
    options.ManagedIdentityClientId = "<client id>";
    options.ExcludeEnvironmentCredential = true;
    options.AllowDeveloperCredentials = builder.Environment.IsDevelopment();
    options.AllowedVaultHosts = new List<string> { "myvault.vault.azure.net" };
});
```

## Step 4: Restrict which vaults may be contacted

`AllowedVaultHosts` is the setting that pins resolution to **your** vaults. Without it, any `*.vault.azure.net` host passes the default suffix check, and a reference pointing at someone else's vault would send this application's token to it. When `AllowedVaultHosts` is populated it is authoritative and the suffix list is not consulted. Set it in production.

## Step 5: Know the behaviour that is different

| Behaviour | What happens |
| --- | --- |
| A reference cannot be resolved | Fail closed. By default (`ThrowOnResolveFailure = true`) building the configuration throws `KeyVaultReferenceResolutionException` naming the configuration key. With `false`, the value is set to `null`; the literal reference string is never handed to the application as if it were the secret. |
| A value holds several references and one fails | The whole value is `null`; a partly substituted connection string is never produced. |
| Identical references | Distinct secret URIs are fetched once, however many keys use them. |
| Logging | Information-level records name the vault, not the secret or the configuration key. The secret name appears only at Debug. |
| Timeouts | `Timeout` (default 30 seconds) bounds one read; `OverallTimeout` (default 2 minutes) bounds all references together, so unreachable references cannot stall startup indefinitely. |
| Unreferenced vault secrets | Never read. |
| Rotation | Resolved once; a restart picks up a new value. |

## Step 6: Verify

Run this checklist before you cut over:

1. Build the configuration and call `configuration.AssertNoUnresolvedReferences()` right after `Build()`. It throws if any value still holds a literal reference, which means a source was registered after the resolver or the resolver never ran.
2. For each migrated key, check the value is the secret and not the reference, and not `null`.
3. In the logs, find `ResolutionSummary` (1004): `Count` of `Total` resolved. A `Count` below `Total` with `ThrowOnResolveFailure = false` means some values are `null`.
4. Break one reference on purpose (a wrong secret name) in a non-production environment and confirm startup fails naming the configuration key.
5. Confirm `AllowedVaultHosts` rejects a reference to a vault that is not yours.
6. Confirm the identity used is the intended one (managed identity, not a developer or environment credential), and that `ExcludeEnvironmentCredential` is `true` where it should be.
7. If you also read references with `ExtractSecretUri` or `IsKeyVaultReference`, remember `ExtractSecretUri` uses the public-cloud suffix for `VaultName` references.

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| The application reads `@Microsoft.KeyVault(...)` as a value | The resolver ran before the source that holds it, or never ran | Register it last; call `AssertNoUnresolvedReferences()` |
| `KeyVaultReferenceResolutionException` at startup naming a key | The secret does not exist, is disabled, or the identity lacks access | Check the secret name and the role assignment |
| HTTP 403 in the inner exception | The identity has no `Key Vault Secrets User` role, or the vault firewall blocks the caller | Fix the assignment or the network rule |
| `ArgumentException` about an allowed vault host | The reference's host is not in `AllowedVaultHosts` or the suffix list | Add the vault, or correct the reference |
| The application reads a reference-looking string, and `AssertNoUnresolvedReferences()` passes | The reference is malformed or outside the `VaultName` rules (for example an underscore, or a vault name over 24 characters), so it is not recognised and left as is | Correct it, or use the `SecretUri=` form |
| A sovereign-cloud `VaultName` reference resolves to the wrong host | `VaultDnsSuffix` was not set | Set `VaultDnsSuffix` (and `AuthorityHost`) |
| A secret that `AddAzureKeyVault` used to load is now `null` | No reference was written for its key | Add the reference (Step 2b) |
| A configuration value is `null` and nothing was thrown | `ThrowOnResolveFailure` is `false` and the reference failed | Look for `ResolutionFailed` (1003) in the logs |

## Security Considerations

- **Fail closed is the default.** Leave `ThrowOnResolveFailure = true` unless the application can run with a missing secret. With `false`, an application that starts with an empty password fails later and less clearly.
- **Pin the vault with `AllowedVaultHosts`**, and set `ExcludeEnvironmentCredential = true` where a managed identity is in use.
- **References are not secrets**, but they name the vault and the secret. Treat them like any infrastructure identifier: fine in source control, not something to print in logs.
- **Do not mix mechanisms silently.** Keeping `AddAzureKeyVault` alongside the resolver loads every secret into configuration again and defeats the point of naming only what is needed.

## Limitations

- The configuration is resolved once at startup; there is no reload, unlike an `AddAzureKeyVault` configured with a reload interval.
- References inside a source registered after the resolver are not resolved.
- Azure only here: HashiCorp references have their own formats and rules; see [Reference-Formats.md](../Features/Reference-Formats.md).
- This guide does not cover Key Vault certificates or keys; the library reads secrets.

## Related Documents

- [Reference-Formats.md](../Features/Reference-Formats.md): the reference syntax in detail
- [Vault-Authentication-Methods.md](../Features/Vault-Authentication-Methods.md): how the credential is chosen
- [Configuration-Reference.md](Configuration-Reference.md): every option
- [Environment-Deployment-Guide.md](Environment-Deployment-Guide.md): deployment targets outside App Service
- [Pick-Up-Rotated-Secrets-HOWTO.md](../Operations/Pick-Up-Rotated-Secrets-HOWTO.md): rotation after the migration
- [Security-Model.md](../Architecture/Security-Model.md): why the host allow-list and fail-closed defaults exist
