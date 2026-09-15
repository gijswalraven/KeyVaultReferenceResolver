# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

Requires the **.NET 10 SDK** (see `global.json`). The libraries still target
netstandard2.0; the SDK floor exists because the test projects run on
Microsoft.Testing.Platform.

```bash
# Build the solution
dotnet build

# Build in release mode
dotnet build -c Release

# Run the tests
dotnet test

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
- **FakeSecretResolver** - Test double for unit testing without Azure dependencies. Lives in
  `tests/KeyVaultReferenceResolver.TestSupport`, which is never packed; it is deliberately not
  part of either shipped package.
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

Two test projects live under `tests/`, one per library, both on **xunit.v3**
running under Microsoft.Testing.Platform. `dotnet test` works via the
`test.runner` key in `global.json`; the projects are also self-executing
(`OutputType=Exe`), so you can run a test assembly directly.

When adding tests:

- Use plain XUnit assertions (`Assert.Equal`, `Assert.Throws<T>`, ...).
  FluentAssertions is deliberately not referenced.
- Note `Assert.Throws<T>` matches the exception type *exactly* — use
  `Assert.ThrowsAny<T>` when a derived type is acceptable.
- Use `FakeSecretResolver` (from `KeyVaultReferenceResolver.TestSupport`) for unit tests to
  avoid Azure dependencies
- `FakeSecretResolver` supports fluent API: `.AddSecret(uri, value)` chaining
- Set `throwOnMissing: false` for silent mode (returns empty string instead of throwing)
- Pass `TestContext.Current.CancellationToken` to async calls that accept one
  (enforced by analyzer xUnit1051).
- Anything that mutates the process-wide `VAULT_*` environment variables must
  join the `"VaultEnvironment"` collection, which disables parallelization —
  otherwise it races with the other env-var tests.
