# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Security fixes are listed under a `Security` heading so they can be found
without reading the whole entry. Reporting process: [SECURITY.md](SECURITY.md).

## [Unreleased]

## [2.0.0]

Security release. Every item under `Security` was found by a review of the
resolution path in both packages; several change behaviour, so this is a major
version.

### Security

- **Fail closed on an unresolved reference.** With `ThrowOnResolveFailure =
  false`, a reference that could not be resolved was skipped, leaving the
  literal `@Microsoft.KeyVault(SecretUri=...)` / `@HashiCorp.Vault(...)` string
  as the configuration value. The application would then use the reference
  string itself as a password or connection string — failing late, or silently
  succeeding against something that accepted it. The key is now set to `null`.
- **Reject vault hosts outside Key Vault.** A secret URI was accepted with any
  host and a `SecretClient` was built for it immediately, so a configuration
  value an attacker could influence made the process issue an authenticated
  request to a host of their choosing during startup. URIs must now use `https`
  and match `AllowedVaultHostSuffixes`.
- **Constrain `VaultName` and `SecretName`.** Both were captured as `[^;)]+` and
  interpolated into a URI, so `/`, `@`, `?` and `#` could relocate the authority
  — `VaultName=evil.example/x` produced a URI whose authority was
  `evil.example`. Both are now restricted to Azure's naming rules.
- **Do not trust the vault address inside a HashiCorp reference.** The address
  used to build the Vault client came from the configuration value itself, so a
  tampered value could redirect the ambient Vault credential (`VAULT_TOKEN`, an
  AppRole login, or the Kubernetes service account JWT) to an attacker's host in
  one step. A reference address must now match the configured `VaultAddress`, or
  appear in `AllowedVaultAddresses`.
- **Require HTTPS for Vault addresses.** `VaultAddress` / `VAULT_ADDR` were used
  verbatim, so an `http://` address sent the token and the secret in the clear.
  Opt out with `AllowInsecureTransport` for a local dev Vault only.
- **Harden the default Azure credential chain.** `DefaultAzureCredential` was
  constructed with no options, leaving Azure CLI, Azure Developer CLI, Visual
  Studio and Azure PowerShell credentials live in production. Developer
  credentials are now excluded unless `AllowDeveloperCredentials` is set, and
  interactive browser authentication is always excluded.
- **Never log secret payloads via the Azure SDK.**
  `Diagnostics.IsLoggingContentEnabled` is forced to `false` on the
  `SecretClientOptions` used to build each client, so enabling `AZURE_LOG_LEVEL`
  cannot dump secret response bodies.
- **Re-read the Kubernetes service account token.** The JWT was read once and
  reused for the lifetime of the process. Kubernetes rotates projected tokens at
  roughly 80% of their lifetime, so every login after the first rotation failed.
- **Restore resolver logging.** Both resolvers took `ILogger<T>` while the public
  API accepts `ILogger`, bridged by a cast that is `null` for every logger a
  caller can pass. Every log call inside the resolvers was dead code, leaving no
  record of which vault or secret was read.
- **Bound startup resolution.** References were resolved sequentially, each with
  its own `Timeout`, so N unreachable references stalled startup for up to
  N × 30 s and outlived container liveness probes. Resolution now runs with
  bounded concurrency under a single `OverallTimeout`.
- **Enforce the HashiCorp timeout.** `CancellationTokenSource.CancelAfter` could
  never fire because VaultSharp does not observe a `CancellationToken`, so an
  unreachable Vault hung startup indefinitely despite a comment claiming the
  timeout was enforced. The timeout is now applied as
  `VaultClientSettings.VaultServiceTimeout`.
- Added a regex match timeout to the Azure reference patterns, matching the
  HashiCorp package (CWE-1333).
- Masked the secret URI in `ParseSecretUri`'s exception message instead of
  echoing the value back (CWE-209).

### Added

- `KeyVaultReferenceResolverOptions`: `ManagedIdentityClientId`, `TenantId`,
  `AuthorityHost`, `AllowDeveloperCredentials`, `ExcludeEnvironmentCredential`,
  `ClientOptions`, `AllowedVaultHostSuffixes`, `OverallTimeout`,
  `MaxConcurrency`, `CacheTtl`, `Validate()`.
- `HashiCorpVaultResolverOptions`: `AllowInsecureTransport`,
  `AllowedVaultAddresses`, `OverallTimeout`, `MaxConcurrency`, `CacheTtl`,
  `Validate()`, `EnsureTransportAllowed()`.
- On-demand cache refresh on both resolvers: `InvalidateCache(uri?)` and
  `ResolveSecret[Async](uri, forceRefresh: true)`.
- Both resolvers implement `IDisposable`, clearing cached secret values.
- `SECURITY.md` with a private vulnerability-reporting path, triage targets and
  an explicit scope section.
- README sections covering secret rotation, allowed vault hosts, least-privilege
  RBAC (`Key Vault Secrets User`), minimum Vault policy, vault configuration
  prerequisites, and the `GetDebugView()` exposure.

### Changed

- `CacheTtl` defaults to `Timeout.InfiniteTimeSpan`. The resolver does not poll
  Key Vault on a timer; refresh explicitly when a secret is observed to be
  stale. Configuration references are still resolved once at startup and still
  require an application restart to pick up a rotated secret.
- `KeyVaultSecretResolver` and `HashiCorpVaultSecretResolver` accept `ILogger`
  instead of `ILogger<T>`. `ILogger<T>` still binds, so calling code compiles
  unchanged.
- `ParseSecretUri` throws `ArgumentException` rather than `UriFormatException`
  for a malformed URI.
- Resolution failures log at `Error` rather than `Warning`.

### CI

- All GitHub Actions pinned to commit SHAs; `permissions: contents: read` on
  CI; `persist-credentials: false` on checkouts that do not push.
- `claude.yml` gated on `author_association`; `id-token: write` removed from
  both Claude workflows.
- CI fails on vulnerable direct or transitive packages.
- Added CodeQL (`security-extended`) and Dependabot for `nuget` and
  `github-actions`.

### Upgrading from 1.x

1. If you set `ThrowOnResolveFailure = false`, handle `null` where you
   previously received the literal reference string.
2. If you rely on Azure CLI or Visual Studio credentials at runtime, set
   `AllowDeveloperCredentials = true` — in development only.
3. If the host has more than one managed identity, set
   `ManagedIdentityClientId`.
4. If you use a sovereign cloud, set `AuthorityHost` and adjust
   `AllowedVaultHostSuffixes`.
5. If a HashiCorp `VAULT_ADDR` uses `http://`, move to `https://` or set
   `AllowInsecureTransport = true` for local development.

## [1.2.0]

- Dependency modernisation: Azure SDK and `Microsoft.Extensions.*` updates,
  `System.Text.Json` pinned to clear advisories.
- Test suite migrated to xunit.v3 on Microsoft.Testing.Platform;
  FluentAssertions removed.
- Release publishes to NuGet.org via Trusted Publishing (OIDC) instead of a
  long-lived API key, with a tag/version consistency check.

## [1.1.0]

- Added `@Microsoft.KeyVault(VaultName=...;SecretName=...)` reference format.
- Added the `KeyVaultReferenceResolver.HashiCorp` package with Token, AppRole
  and Kubernetes authentication.

## [1.0.0]

- Initial release: resolve `@Microsoft.KeyVault(SecretUri=...)` references in
  `Microsoft.Extensions.Configuration` anywhere, not just Azure App Service.

[Unreleased]: https://github.com/gijswalraven/KeyVaultReferenceResolver/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/gijswalraven/KeyVaultReferenceResolver/compare/v1.2.0...v2.0.0
[1.2.0]: https://github.com/gijswalraven/KeyVaultReferenceResolver/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/gijswalraven/KeyVaultReferenceResolver/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/gijswalraven/KeyVaultReferenceResolver/releases/tag/v1.0.0
