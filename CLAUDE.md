# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

```bash
# Build the solution
dotnet build

# Build in release mode
dotnet build -c Release

# Create NuGet package
dotnet pack -c Release
```

## Project Overview

KeyVaultReferenceResolver is a .NET library that resolves Azure Key Vault secrets in `Microsoft.Extensions.Configuration`. It enables using the same `@Microsoft.KeyVault(SecretUri=...)` format that Azure App Service uses, but in any environment (local dev, Docker, Kubernetes, etc.).

**Target Framework:** .NET Standard 2.0 (compatible with .NET Framework 4.6.1+ and .NET Core 2.0+)

## Architecture

The library follows a simple provider pattern:

- **ISecretResolver** - Interface for secret resolution, enables DI and testing
- **KeyVaultSecretResolver** - Default implementation using Azure SDK (`Azure.Identity`, `Azure.Security.KeyVault.Secrets`)
- **MockSecretResolver** - Test double for unit testing without Azure dependencies
- **KeyVaultReferenceResolverExtensions** - `IConfigurationBuilder` extension methods; contains the regex pattern matching and orchestrates resolution
- **KeyVaultReferenceResolverOptions** - Configuration: `ThrowOnResolveFailure`, `Timeout`, `EnableCaching`, `Credential`

### Resolution Flow

1. Extension method builds a temp config from existing sources
2. Iterates all config values, matching against `@Microsoft\.KeyVault\(SecretUri=(?<uri>https://[^)]+)\)`
3. Resolved secrets are added via `AddInMemoryCollection()`, overriding the original references
4. `KeyVaultSecretResolver` caches both `SecretClient` instances (per vault) and resolved values

## Key Vault Reference Format

```
@Microsoft.KeyVault(SecretUri=https://{vault}.vault.azure.net/secrets/{secret-name}[/{version}])
```

## Testing Notes

No test project exists yet. When adding tests:
- Use `MockSecretResolver` for unit tests to avoid Azure dependencies
- `MockSecretResolver` supports fluent API: `.AddSecret(uri, value)` chaining
- Set `throwOnMissing: false` for silent mode (returns empty string instead of throwing)
