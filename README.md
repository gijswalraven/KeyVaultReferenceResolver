# 🔐 KeyVaultReferenceResolver

[![NuGet](https://img.shields.io/badge/nuget-v1.3.0-blue.svg)](https://www.nuget.org/packages/KeyVaultReferenceResolver)
[![.NET](https://img.shields.io/badge/.NET%20Standard-2.0-512BD4.svg)](https://dotnet.microsoft.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Seamlessly resolve Azure Key Vault secrets in your .NET configuration — using the same format as Azure App Service.**

---

## ✨ Why KeyVaultReferenceResolver?

When deploying to Azure App Service, you can reference Key Vault secrets directly in your configuration using the `@Microsoft.KeyVault(SecretUri=...)` syntax. But what about local development? What about running in Docker, Kubernetes, or other environments?

**KeyVaultReferenceResolver bridges that gap.** Use the exact same configuration files everywhere — no environment-specific transforms, no code changes, no friction.

```
┌─────────────────────────────────────────────────────────────────┐
│  appsettings.json                                               │
│  ─────────────────                                              │
│  "ConnectionString": "@Microsoft.KeyVault(SecretUri=https://    │
│                       myvault.vault.azure.net/secrets/db-conn)" │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
          ┌───────────────────────────────────────┐
          │   KeyVaultReferenceResolver           │
          │   ─────────────────────────           │
          │   • Detects Key Vault references      │
          │   • Authenticates via Azure Identity  │
          │   • Resolves secrets automatically    │
          │   • Caches for performance            │
          └───────────────────────────────────────┘
                              │
                              ▼
          ┌───────────────────────────────────────┐
          │  Your Application                     │
          │  ────────────────                     │
          │  config["ConnectionString"]           │
          │  → "Server=prod.db;Password=..."      │
          └───────────────────────────────────────┘
```

---

## 🚀 Quick Start

### Installation

```bash
dotnet add package KeyVaultReferenceResolver
```

### Basic Usage

```csharp
using KeyVaultReferenceResolver;

var configuration = new ConfigurationBuilder()
    .AddJsonFile("appsettings.json")
    .AddKeyVaultReferenceResolver()  // ← Just add this line
    .Build();

// That's it! Secrets are resolved automatically.
var connectionString = configuration["ConnectionStrings:Database"];
```

### ASP.NET Core

```csharp
var builder = WebApplication.CreateBuilder(args);

builder.Configuration.AddKeyVaultReferenceResolver(options =>
{
    // Keep fail-fast on in every environment. For offline development, use
    // MockSecretResolver or a local-only configuration source rather than
    // disabling it — see Testing below.
    options.AllowDeveloperCredentials = builder.Environment.IsDevelopment();
});

var app = builder.Build();
```

> **Note**
> `AllowDeveloperCredentials` is `false` by default, so locally cached Azure CLI,
> Azure Developer CLI, Visual Studio and Azure PowerShell credentials are not
> used unless you opt in. This stops a process running in Azure from silently
> falling back to a developer's personal identity.

---

## 📝 Configuration Format

Use the standard Azure App Service Key Vault reference format:

```json
{
  "ConnectionStrings": {
    "Database": "@Microsoft.KeyVault(SecretUri=https://myvault.vault.azure.net/secrets/db-connection)",
    "Redis": "@Microsoft.KeyVault(SecretUri=https://myvault.vault.azure.net/secrets/redis-conn)"
  },
  "ExternalServices": {
    "ApiKey": "@Microsoft.KeyVault(SecretUri=https://myvault.vault.azure.net/secrets/api-key/v1)"
  },
  "RegularSetting": "This stays as-is"
}
```

| Format | Example |
|--------|---------|
| Latest version | `https://vault.vault.azure.net/secrets/my-secret` |
| Specific version | `https://vault.vault.azure.net/secrets/my-secret/abc123def456` |

---

## 🔑 Authentication

KeyVaultReferenceResolver uses **DefaultAzureCredential** by default, which automatically works with:

| Environment | Recommended | Notes |
|-------------|-------------|-------|
| **Azure App Service / Functions** | Managed Identity | Recommended. Set `ManagedIdentityClientId` if more than one identity is assigned, otherwise the credential cannot choose. |
| **Azure VMs** | Managed Identity | As above. |
| **Azure Kubernetes** | Workload Identity | Recommended. Prefer this over a service principal in environment variables. |
| **Local Development** | Azure CLI / Visual Studio / PowerShell | Requires `AllowDeveloperCredentials = true`. Scope the developer identity to a **dev** vault, not production. |
| **CI/CD Pipelines** | Federated credential (OIDC) | If you must use a client secret, mount it as a file rather than an environment variable and rotate it. |
| **Docker (outside Azure)** | Service Principal | Least preferred. Consider `ExcludeEnvironmentCredential` elsewhere so this path cannot be used accidentally. |

> **Warning**
> The environment credential (`AZURE_CLIENT_ID` / `AZURE_TENANT_ID` /
> `AZURE_CLIENT_SECRET`) sits **ahead of** managed identity in the default
> chain. Anything able to set those variables in the process environment can
> redirect vault access to an identity of its choosing. Set
> `ExcludeEnvironmentCredential = true` when the workload authenticates with a
> managed or workload identity.

### Custom Credentials

```csharp
// Managed Identity (User-Assigned)
builder.AddKeyVaultReferenceResolver(
    new ManagedIdentityCredential("client-id-here"));

// Service Principal
builder.AddKeyVaultReferenceResolver(options =>
{
    options.Credential = new ClientSecretCredential(
        tenantId: "...",
        clientId: "...",
        clientSecret: "...");
});

// Chained credentials (try multiple in order)
builder.AddKeyVaultReferenceResolver(
    new ChainedTokenCredential(
        new ManagedIdentityCredential(),
        new AzureCliCredential()));
```

---

## ⚙️ Configuration Options

```csharp
builder.AddKeyVaultReferenceResolver(options =>
{
    // 🚨 Throw on failure (default: true)
    // When false, an unresolvable key is set to null — never to the literal
    // "@Microsoft.KeyVault(...)" reference string.
    options.ThrowOnResolveFailure = true;

    // ⏱️ Timeout per secret (default: 30 seconds)
    options.Timeout = TimeSpan.FromSeconds(60);

    // ⏱️ Total budget for resolving all references (default: 2 minutes)
    options.OverallTimeout = TimeSpan.FromMinutes(2);

    // 🔀 How many secrets are fetched concurrently (default: 8)
    options.MaxConcurrency = 8;

    // 💾 Cache resolved secrets (default: true)
    options.EnableCaching = true;

    // ⏳ How long a cached secret stays valid (default: infinite)
    // Refresh on demand instead of polling — see Secret rotation below.
    options.CacheTtl = Timeout.InfiniteTimeSpan;

    // 🆔 Pin the identity (required when the host has several managed identities)
    options.ManagedIdentityClientId = "00000000-0000-0000-0000-000000000000";

    // 💻 Allow Azure CLI / Visual Studio / PowerShell credentials (default: false)
    options.AllowDeveloperCredentials = false;

    // 🚫 Exclude AZURE_CLIENT_ID/SECRET env-var credentials (default: false)
    // Recommended when the workload uses a managed or workload identity: the
    // environment credential otherwise sits ahead of managed identity in the chain.
    options.ExcludeEnvironmentCredential = true;

    // ⏰ Reject a secret that has expired or is not yet valid (default: false)
    options.RejectSecretsOutsideValidityPeriod = true;

    // ⏰ Warn this far ahead of a secret's expiry (default: 7 days)
    options.ExpiryWarningThreshold = TimeSpan.FromDays(14);

    // 🏷️ Restrict resolution to your own vaults (default: empty)
    // The suffix list below establishes that a host is a Key Vault, not whose.
    // This is the setting that pins resolution to the vaults you own.
    options.AllowedVaultHosts = new List<string> { "contoso-prod.vault.azure.net" };

    // 🏢 Pin the credential to one tenant (default: null, leaving the SDK default)
    // An empty list also overrides AZURE_ADDITIONALLY_ALLOWED_TENANTS.
    options.AdditionallyAllowedTenants = new List<string>();

    // 📦 Largest number of secrets held in the cache (default: 1024, 0 = unlimited)
    options.MaxCacheEntries = 1024;

    // 🌍 Sovereign clouds
    options.AuthorityHost = AzureAuthorityHosts.AzureGovernment;
    options.VaultDnsSuffix = "vault.usgovcloudapi.net";
    options.AllowedVaultHostSuffixes = new List<string> { ".vault.usgovcloudapi.net" };

    // 🎛️ Full control over the Key Vault client (retries, proxy, API version)
    options.ClientOptions = new SecretClientOptions { Retry = { MaxRetries = 5 } };

    // 🔐 Custom credential (overrides all credential options above)
    options.Credential = new DefaultAzureCredential();
});
```

### Allowed vault hosts

A secret URI must use `https` and match one of `AllowedVaultHostSuffixes`, which
defaults to the Key Vault and Managed HSM suffixes of all four Azure clouds.
This stops a configuration value — an environment variable, a mounted
`appsettings.json`, a remote config service — from pointing a reference at an
arbitrary host and making your process authenticate to it during startup. Clear
the list to disable the check.

**The suffix list is not enough on its own.** It establishes that a host is a
Key Vault, not whose Key Vault. `https://someone-elses.vault.azure.net` matches
the default list perfectly well, and resolving against it presents a token for
your application's identity to a vault under someone else's control — who can
then replay that token against the vaults your identity legitimately reaches.

Set `AllowedVaultHosts` to the exact hosts you own:

```csharp
options.AllowedVaultHosts = new List<string>
{
    "contoso-prod.vault.azure.net",
    "contoso-shared.vault.azure.net"
};
```

When `AllowedVaultHosts` is non-empty it is authoritative and the suffix list is
not consulted, so a suffix entry cannot widen it. Suffix entries match on a
label boundary, so `contoso.vault.azure.net` does not admit
`evilcontoso.vault.azure.net`.

### Register the resolver last

References are resolved **once**, in a single sweep, when
`AddKeyVaultReferenceResolver` is called. A configuration source registered
*after* it overrides the resolved secrets and is never itself resolved — so a
reference in that source reaches your application as the literal
`@Microsoft.KeyVault(...)` string and gets used as a credential. The same
applies to a `reloadOnChange` source that gains a reference after startup.

The library logs `ResolverNotLastSource` (event 1005) at `Error` when it detects
a later source. To fail startup instead, check the built configuration:

```csharp
var configuration = builder.Build();
configuration.AssertNoUnresolvedReferences(logger); // throws, naming the keys

// or, to inspect without throwing:
foreach (var key in configuration.FindUnresolvedReferences())
    Console.WriteLine($"unresolved: {key}");
```

The HashiCorp package has the same pair as `AssertNoUnresolvedVaultReferences`
and `FindUnresolvedVaultReferences`.

### Secret rotation

Secrets are resolved **once**, while the configuration is being built, and the
result is written into an in-memory configuration source. A rotated secret is
therefore **not** picked up until the application restarts — wire your rotation
process to a restart or a rolling deployment.

`CacheTtl` defaults to `Timeout.InfiniteTimeSpan`: the resolver does not poll
Key Vault on a timer, which would mostly buy traffic and throttling risk. When
code resolves secrets through `ISecretResolver` directly rather than through
`IConfiguration`, refresh on demand at the point you detect staleness:

```csharp
catch (SqlException ex) when (ex.Number == 18456) // Login failed
{
    var fresh = await resolver.ResolveSecretAsync(secretUri, forceRefresh: true, ct);
    // or: resolver.InvalidateCache(secretUri);
}
```

`KeyVaultSecretResolver` implements `IDisposable`; disposing it clears cached
secret values.

---

## 📊 Logging

Get visibility into what's happening:

```csharp
var loggerFactory = LoggerFactory.Create(builder => 
    builder.AddConsole().SetMinimumLevel(LogLevel.Debug));

builder.AddKeyVaultReferenceResolver(
    options: new KeyVaultReferenceResolverOptions(),
    logger: loggerFactory.CreateLogger("KeyVault"));
```

**Sample output:**

```text
dbug: KeyVault[1001] Resolved Key Vault reference: https://myvault.vault.azure.net/secrets/***
info: KeyVault[1002] Successfully resolved secret from https://myvault.vault.azure.net
info: KeyVault[1004] Resolved 2 of 2 configuration value(s) containing Key Vault reference(s)
```

### What each level emits

**Secret values are never logged, at any level.**

| Level | Emitted |
|-------|---------|
| `Information` | Per-secret success (vault host only), the aggregate count, the selected Vault auth method |
| `Warning` | A secret is expired, not yet valid, or expiring within `ExpiryWarningThreshold` |
| `Error` | A reference failed to resolve, including the configuration key and the exception |
| `Debug` | Secret **names**, configuration **keys**, cache hits, and the KV engine version probe |

Secret names and configuration key names appear only at `Debug`. They are not
secrets, but together they inventory which keys hold credentials and what exists
in the vault, so they are kept out of the levels that ship to an aggregated log
store by default. Treat `Debug` records from this library as sensitive and
restrict their retention accordingly.

### Event IDs

Every record carries a stable `EventId`, so alerts and audit queries can key on
an identifier rather than message text — see `LogEvents` (1000s resolution,
1100s secret validity, 1200s caching) and `HashiCorpLogEvents` (2000s
resolution, 2100s authentication, 2200s caching). Ones worth alerting on:

| ID | Meaning |
|----|---------|
| `1003` | A reference failed to resolve and its value was set to `null` |
| `1101` | A secret past its expiry was used anyway |
| `1102` | A secret expires soon |
| `2101` | Which Vault auth method was auto-selected — a change here is worth noticing |
| `2102` | Vault rejected the login token and the client re-authenticated |

### Note on inner exceptions

A resolution failure is logged with the underlying exception from
`Azure.Identity`, `Azure.Security.KeyVault.Secrets` or `VaultSharp` attached.
Those messages carry response status and body, which is where the diagnostic
value is. Secret values do not appear there — a secret payload only comes back
on a successful response, which raises no exception — but if you forward
exceptions to a third-party sink, that is the text being forwarded.

---

## 🧪 Testing

Use the built-in `MockSecretResolver` for unit tests:

```csharp
[Fact]
public void Configuration_ResolvesSecrets_FromMock()
{
    // Arrange
    var mockResolver = new MockSecretResolver()
        .AddSecret(
            "https://myvault.vault.azure.net/secrets/db-conn",
            "Server=localhost;Database=TestDb")
        .AddSecret(
            "https://myvault.vault.azure.net/secrets/api-key",
            "test-api-key-12345");

    var configuration = new ConfigurationBuilder()
        .AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Database"] = "@Microsoft.KeyVault(SecretUri=https://myvault.vault.azure.net/secrets/db-conn)",
            ["ApiKey"] = "@Microsoft.KeyVault(SecretUri=https://myvault.vault.azure.net/secrets/api-key)"
        })
        .AddKeyVaultReferenceResolver(mockResolver)
        .Build();

    // Act & Assert
    Assert.Equal("Server=localhost;Database=TestDb", configuration["Database"]);
    Assert.Equal("test-api-key-12345", configuration["ApiKey"]);
}
```

### MockSecretResolver Features

```csharp
// Fluent API
var mock = new MockSecretResolver()
    .AddSecret("uri1", "value1")
    .AddSecret("uri2", "value2");

// Bulk add
mock.AddSecrets(new Dictionary<string, string>
{
    ["uri3"] = "value3",
    ["uri4"] = "value4"
});

// Silent mode (returns empty string instead of throwing)
var silentMock = new MockSecretResolver(secrets, throwOnMissing: false);

// Inspection
bool exists = mock.ContainsSecret("uri1");
int count = mock.Count;
mock.Clear();
```

---

## 🛠️ Utility Methods

```csharp
using KeyVaultReferenceResolver;

// Check if a value is a Key Vault reference
string value = "@Microsoft.KeyVault(SecretUri=https://...)";
bool isRef = KeyVaultReferenceResolverExtensions.IsKeyVaultReference(value);
// → true

// Extract the secret URI
string? uri = KeyVaultReferenceResolverExtensions.ExtractSecretUri(value);
// → "https://..."
```

---

## 🔒 Security Best Practices

1. **Use Managed Identity or Workload Identity in Azure** — no secrets to manage, and set `ExcludeEnvironmentCredential = true` so the chain cannot be redirected
2. **Keep `ThrowOnResolveFailure` enabled (default)** — fail fast if secrets can't be loaded
3. **Use specific secret versions for critical configs** — prevents unexpected changes
4. **Grant the minimum role** — `Key Vault Secrets User`, scoped as narrowly as possible
5. **Audit access** — enable Key Vault diagnostic logging and alert on unexpected callers

### Required Key Vault permissions

With **Azure RBAC** (recommended), assign the built-in
**Key Vault Secrets User** role — it grants exactly the `Get`/`List` data
actions this library needs. `Key Vault Secrets Officer`, `Contributor` and
`Owner` are all over-privileged for a consuming application.

```bash
# Scope to a single secret where possible, not the whole vault
az role assignment create \
  --role "Key Vault Secrets User" \
  --assignee-object-id "<managed-identity-principal-id>" \
  --assignee-principal-type ServicePrincipal \
  --scope "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.KeyVault/vaults/<vault>/secrets/<secret>"
```

With **legacy access policies**, grant only the `Get` secret permission:

| Permission | Required |
|------------|----------|
| `secrets/get` | ✅ Yes |
| `secrets/list` | ❌ No |
| `secrets/set` | ❌ No |

### Vault configuration prerequisites

The library cannot compensate for a weakly configured vault. Confirm that:

- **Azure RBAC** is enabled rather than legacy access policies
- **Soft delete** and **purge protection** are on
- **Expiration dates** are set on secrets (note: Key Vault does not block reads of an expired secret — expiry is advisory)
- **Public network access** is disabled, with a private endpoint or firewall rules where the network topology allows
- **Diagnostic logging** (`AuditEvent`) is sent to a Log Analytics workspace

### What the library does and does not protect

Resolved secrets become ordinary `string` values in `IConfiguration`. They
cannot be zeroed, they appear in a full process dump, and
`IConfigurationRoot.GetDebugView()` — which the ASP.NET Core developer exception
page renders — prints them in clear text. **Do not enable the developer
exception page, or any endpoint that dumps configuration, outside local
development.**

---

## 🔷 HashiCorp Vault Support

KeyVaultReferenceResolver also supports **HashiCorp Vault** via a separate package:

```bash
dotnet add package KeyVaultReferenceResolver.HashiCorp
```

### Basic Usage

```csharp
using KeyVaultReferenceResolver.HashiCorp;

var configuration = new ConfigurationBuilder()
    .AddJsonFile("appsettings.json")
    .AddHashiCorpVaultResolver()  // Auto-detects from environment
    .Build();
```

### Configuration Formats

HashiCorp Vault supports two reference formats:

**Attribute Format (Azure-style):**
```json
{
  "ConnectionStrings": {
    "Database": "@HashiCorp.Vault(VaultAddress=https://vault.example.com;SecretPath=secret/data/myapp;SecretKey=db-password)"
  }
}
```

**URI Format:**
```json
{
  "ConnectionStrings": {
    "Database": "hashicorp://vault.example.com/secret/data/myapp#db-password"
  }
}
```

### Authentication Methods

HashiCorp Vault supports multiple authentication methods:

```csharp
// Token authentication (from VAULT_TOKEN env var)
builder.AddHashiCorpVaultResolver();

// Explicit token — never hard-code it; read it from the environment or a
// mounted file so it does not end up committed in Program.cs
builder.AddHashiCorpVaultResolver(options =>
{
    options.VaultAddress = "https://vault.example.com";
    options.AuthMethod = new TokenAuthMethod(
        Environment.GetEnvironmentVariable("VAULT_TOKEN")!);
});

// AppRole authentication
builder.AddHashiCorpVaultResolver(options =>
{
    options.VaultAddress = "https://vault.example.com";
    options.AuthMethod = new AppRoleAuthMethod(
        Environment.GetEnvironmentVariable("VAULT_ROLE_ID")!,
        Environment.GetEnvironmentVariable("VAULT_SECRET_ID")!);
});

// Kubernetes authentication — FromFile re-reads the service account token on
// each login, so a rotated projected token keeps working
builder.AddHashiCorpVaultResolver(options =>
{
    options.VaultAddress = "https://vault.vault.svc:8200";
    options.AuthMethod = KubernetesAuthMethod.FromFile("my-app-role");
});
```

> **Warning**
> Vault addresses must use `https`. Over plaintext HTTP the Vault token and the
> returned secret both travel in the clear — including between pods inside a
> cluster. If the in-cluster Vault presents a private CA certificate, trust that
> CA rather than downgrading to HTTP. `AllowInsecureTransport = true` exists for
> a local dev-mode Vault only.

### Strict vault address validation

A `@HashiCorp.Vault(VaultAddress=...)` reference carries its own address, and
that address comes from configuration. Set `VaultAddress` in options to pin the
resolver: a reference naming a different vault is then rejected rather than
being sent your Vault credential. If you genuinely need several vaults, list
them in `AllowedVaultAddresses`.

### Minimum Vault policy

```hcl
# KV v2 — read one application's secrets and nothing else
path "secret/data/myapp" {
  capabilities = ["read"]
}

# Only if you also need secret metadata (versions, timestamps)
path "secret/metadata/myapp" {
  capabilities = ["read"]
}
```

Prefer short-TTL, renewable tokens, and bound AppRole secret IDs
(`secret_id_num_uses`, `secret_id_ttl`) over long-lived credentials in
environment variables.

### Environment Variables

| Variable | Description |
|----------|-------------|
| `VAULT_ADDR` | Vault server address (e.g., `https://vault.example.com`) |
| `VAULT_TOKEN` | Token for token authentication |
| `VAULT_ROLE_ID` | Role ID for AppRole authentication |
| `VAULT_SECRET_ID` | Secret ID for AppRole authentication |

### Configuration Options

```csharp
builder.AddHashiCorpVaultResolver(options =>
{
    options.VaultAddress = "https://vault.example.com";
    options.MountPath = "secret";           // KV secrets engine mount path
    options.KvVersion = 2;                  // KV v1 or v2 (null = auto-detect)
    options.Namespace = "my-namespace";     // Enterprise namespace (optional)
    options.ThrowOnResolveFailure = true;   // Fail fast (default: true)
    options.Timeout = TimeSpan.FromSeconds(30);
    options.EnableCaching = true;
});
```

### Authentication Auto-Detection

When no explicit authentication method is configured, the resolver auto-detects in order:
1. `VAULT_TOKEN` environment variable → Token auth
2. `VAULT_ROLE_ID` + `VAULT_SECRET_ID` → AppRole auth
3. Kubernetes service account token (if running in K8s) → Kubernetes auth

---

## 🏗️ Architecture

```
KeyVaultReferenceResolver/
├── ISecretResolver.cs                      # Interface for DI/testing
├── KeyVaultSecretResolver.cs               # Default Azure implementation
├── MockSecretResolver.cs                   # Testing mock
├── KeyVaultReferenceResolverExtensions.cs  # IConfigurationBuilder extensions
├── KeyVaultReferenceResolverOptions.cs     # Configuration options
└── KeyVaultReferenceResolutionException.cs # Custom exception
```

---

## 📋 Requirements

| Dependency | Version |
|------------|---------|
| Target framework | .NET Standard 2.0 |
| .NET | 8.0+ (tested), .NET Core 2.0+ |
| .NET Framework | 4.6.2+ |
| Azure.Identity | 1.21.0+ |
| Azure.Security.KeyVault.Secrets | 4.11.1+ |
| Microsoft.Extensions.Configuration | 10.0.12+ |

> **Note for .NET Framework consumers**
> Key Vault requires TLS 1.2 or better. On .NET Framework, the TLS version is
> chosen by the host process, not by this library: target 4.7.2+, or set
> `AppContext.SetSwitch("Switch.System.Net.DontEnableSystemDefaultTlsVersions", false)`
> at startup. Otherwise the handshake fails with an opaque connection error.

---

## 🤝 Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for the branch and
review flow, and for what a change to the resolution path additionally needs. Changes to
this repository are also subject to [CODEOWNERS](.github/CODEOWNERS) review.

Found a security problem? Do **not** open an issue — follow [SECURITY.md](SECURITY.md).

### Verifying a release

Each release is published via NuGet Trusted Publishing (OIDC, no long-lived API key) and
carries a build provenance attestation plus a CycloneDX SBOM. To confirm a package was
built from this repository rather than uploaded from elsewhere:

```bash
gh attestation verify KeyVaultReferenceResolver.1.3.0.nupkg \
  --repo gijswalraven/KeyVaultReferenceResolver
```

The SBOM (`KeyVaultReferenceResolver-sbom.cdx.json`) is attached to the GitHub release
and lists the full transitive closure.

### Building from source

Building and testing this repo requires the **.NET 10 SDK** (pinned in `global.json`).
This is a contributor requirement only — the published packages target
`netstandard2.0` and consumers still only need .NET 8.0+, as listed under
[Requirements](#-requirements).

```bash
dotnet build
dotnet test
```

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  <b>Stop juggling configuration transforms. Start shipping.</b>
</p>
