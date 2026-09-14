# 🔐 KeyVaultReferenceResolver

[![NuGet](https://img.shields.io/badge/nuget-v1.2.0-blue.svg)](https://www.nuget.org/packages/KeyVaultReferenceResolver)
[![.NET](https://img.shields.io/badge/.NET-8.0-512BD4.svg)](https://dotnet.microsoft.com/)
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
    // Default is fail-fast (true); be lenient in development if needed
    options.ThrowOnResolveFailure = !builder.Environment.IsDevelopment();
});

var app = builder.Build();
```

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

| Environment | Authentication Method |
|-------------|----------------------|
| **Local Development** | Azure CLI, Visual Studio, VS Code, PowerShell |
| **Azure App Service** | Managed Identity |
| **Azure VMs** | Managed Identity |
| **Azure Kubernetes** | Workload Identity |
| **CI/CD Pipelines** | Service Principal (env vars) |
| **Docker/Kubernetes** | Service Principal or Managed Identity |

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
    // Fail fast is enabled by default; set to false for lenient mode
    options.ThrowOnResolveFailure = true;

    // ⏱️ Timeout per secret (default: 30 seconds)
    options.Timeout = TimeSpan.FromSeconds(60);

    // 💾 Cache resolved secrets (default: true)
    // Improves performance, secrets resolved once at startup
    options.EnableCaching = true;

    // 🔐 Custom credential (default: DefaultAzureCredential)
    options.Credential = new DefaultAzureCredential();
});
```

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
```
info: KeyVault[0] Resolved Key Vault reference: ConnectionStrings:Database
info: KeyVault[0] Resolved Key Vault reference: ExternalServices:ApiKey
info: KeyVault[0] Resolved 2 Key Vault reference(s)
```

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

1. **Use Managed Identity in Azure** — No secrets to manage
2. **Keep `ThrowOnResolveFailure` enabled (default)** — Fail fast if secrets can't be loaded
3. **Use specific secret versions for critical configs** — Prevents unexpected changes
4. **Grant minimal permissions** — Only `Get` permission on secrets is required
5. **Audit access** — Enable Key Vault logging in Azure

### Required Key Vault Permissions

| Permission | Required |
|------------|----------|
| `secrets/get` | ✅ Yes |
| `secrets/list` | ❌ No |
| `secrets/set` | ❌ No |

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

// Explicit token
builder.AddHashiCorpVaultResolver(options =>
{
    options.VaultAddress = "https://vault.example.com";
    options.AuthMethod = new TokenAuthMethod("my-token");
});

// AppRole authentication
builder.AddHashiCorpVaultResolver(options =>
{
    options.VaultAddress = "https://vault.example.com";
    options.AuthMethod = new AppRoleAuthMethod("role-id", "secret-id");
});

// Kubernetes authentication
builder.AddHashiCorpVaultResolver(options =>
{
    options.VaultAddress = "http://vault.vault.svc:8200";
    options.AuthMethod = KubernetesAuthMethod.FromFile("my-app-role");
});
```

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
| .NET | 8.0+ |
| Azure.Identity | 1.21.0+ |
| Azure.Security.KeyVault.Secrets | 4.11.1+ |
| Microsoft.Extensions.Configuration | 10.0.12+ |

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

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
