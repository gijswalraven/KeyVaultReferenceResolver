# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Security fixes are listed under a `Security` heading so they can be found
without reading the whole entry. Reporting process: [SECURITY.md](SECURITY.md).

## [Unreleased]

Repository and CI only.

### Changed

- `actions/upload-artifact` and `actions/download-artifact` 4 → 5. The v4 pins
  target Node 20, which the runners now force onto Node 24 and will stop
  supporting. Both move together: an upload and a download of different majors
  are not guaranteed to interoperate.
- The release workflow hands over two named artifacts with explicit download
  paths instead of one artifact with several path patterns. A multi-path upload
  reconstructs directory structure relative to the least common ancestor of its
  paths, and the publish job was silently relying on that rule to find
  `./artifacts` and `./sbom`.
- CI gained a job that downloads the packages it just uploaded and checks they
  arrive where the release expects. The release workflow's artifact hand-off runs
  only during a release, so this is the one part of it a pull request can
  exercise.


## [2.0.0]

The tightenings 1.4.0 introduced as opt-in are now the default, and the test
double is gone from the shipped packages. That is the whole release: no new
capability, three defaults and one deletion.

> **Read Migrating from 1.4.x before upgrading.** Two of these changes can stop
> an application that currently starts.

### Breaking

- **`StrictVaultAddressValidation` defaults to `true`.** An address inside a
  `@HashiCorp.Vault(...)` reference must now match `VaultAddress`, an entry in
  `AllowedVaultAddresses`, or `VAULT_ADDR`. If none of the three is configured,
  resolution fails rather than contacting a host named by a configuration value.
  In 1.4.x this logged `VaultAddressUnverified` (2103) at `Warning` and proceeded.
- **A later configuration source carrying a reference fails the build.**
  `builder.Build()` throws `KeyVaultReferenceResolutionException` naming the
  offending keys. In 1.4.x this logged `ResolverNotLastSource` (1005 / 2006) at
  `Error` and let the literal reference string through to be used as a
  credential.
- **`MockSecretResolver` is removed.** It shipped inside the production package,
  where `[EditorBrowsable(Never)]` did not stop a dependency-injection
  registration, and with `throwOnMissing: false` it started applications with
  empty passwords. Implement `ISecretResolver` yourself — it has two members, and
  the README shows a stub.

### Fixed

- **A reference arriving only in a later source is now detected.** With no
  references present at registration the resolver returned early and registered
  nothing, so there was nothing left to notice a reference that appeared in a
  source added afterwards. It registers unconditionally now.

### Changed

- A later source with no references is no longer reported at all. Registering
  `AddCommandLine` or `AddEnvironmentVariables` last is common and correct, and
  overriding a resolved secret with a literal value is legitimate; only an
  unresolvable reference is an error. `ResolverNotLastSource` is now emitted only
  when the later sources cannot be inspected.

### Migrating from 1.4.x

**If you use the HashiCorp package.** Set one of `VaultAddress`,
`AllowedVaultAddresses`, or `VAULT_ADDR`. If you were relying on none of them,
1.4.x has been logging `VaultAddressUnverified` at `Warning` on every resolution
— search for it before upgrading and you will find every affected deployment.
Setting `StrictVaultAddressValidation = false` restores the old behaviour, but
that means a configuration value decides where your Vault credential is sent.

**If you register configuration sources after the resolver.** Move
`AddKeyVaultReferenceResolver` / `AddHashiCorpVaultResolver` last. You only need
to act if a later source actually contains a reference; a later source holding
ordinary values is unaffected and still overrides as before. 1.4.x logged
`ResolverNotLastSource` at `Error` for any later source, so that event over-reports
relative to what 2.0 rejects.

**If you use `MockSecretResolver` in tests.** Replace it with your own
`ISecretResolver`. The README has a stub that is a direct substitute; have it
throw on an unknown secret rather than returning an empty string.

Nothing else changed. No public signature outside those three areas was touched,
and the resolution behaviour for a correctly ordered, correctly pinned
configuration is identical to 1.4.0.


Repository and CI only. No change to either shipped package, so there is nothing
here that affects a consumer.

### Security

- **Restrict the release environment to release tags.** `nuget-production` had
  required reviewers but no deployment branch policy, so the environment could be
  targeted from any branch — the reviewer gate was the only thing between an
  arbitrary branch and nuget.org. A tag rule (`v*`) now applies. Tag rather than
  branch because a release deployment's ref is the tag, which the deployment
  records confirm. The comment in `release.yml` had asserted this rule existed
  since 1.3.0; it now records the configuration that is actually in place, with
  the commands to read it back.

### Changed

- `github/codeql-action` 3.38.0 → 4.38.0 (`init`, `analyze`, `upload-sarif`
  together — the halves cannot be bumped separately).
- `actions/checkout` 4.4.0 → 7.0.1, `actions/setup-dotnet` 4.3.1 → 6.0.0,
  `actions/attest-build-provenance` 2.4.0 → 4.2.2.
- The Claude review is skipped on Dependabot pull requests. They run without
  access to repository secrets, so the action could never authenticate and every
  dependency bump carried a permanently red check.
- `.gitattributes` normalises line endings, and the last five CRLF files are
  renormalised. Editing one of them previously rendered as a whole-file rewrite.
- `actions/attest-build-provenance` v4 verified against both subject shapes the
  release uses, by hand-dispatched workflow, since `release.yml` never runs on a
  pull request. Attestations were produced for the packages and the SBOM.


## [1.4.0]

Security release. Follow-up to 1.3.0, from a second review of the same paths.
Nothing here changes behaviour on upgrade: every tightening that would have is
behind a new opt-in, and becomes the default in 2.0.

### Security

- **Pin a HashiCorp vault address supplied by a reference against `VAULT_ADDR`.**
  `ResolveTrustedAddress` only pinned when the `VaultAddress` option was set in
  process. The documented and most common deployment — address from
  `VAULT_ADDR`, `AllowedVaultAddresses` left empty — matched neither gate and
  accepted any HTTPS host a reference named, sending it `VAULT_TOKEN`, an
  AppRole secret ID or a Kubernetes service account token. `VAULT_ADDR` now
  counts as a pin. A mismatch is rejected when the new
  `StrictVaultAddressValidation` is set, and otherwise logged as
  `VaultAddressUnverified` (2103) at `Warning`.
- **Allow-list Key Vault hosts exactly.** `AllowedVaultHostSuffixes` establishes
  that a host is a Key Vault, not whose: `https://attacker.vault.azure.net`
  satisfies the default list, and resolving against it presents a token for the
  application's identity to a vault its owner controls, who can replay it. The
  new `AllowedVaultHosts` matches whole hosts and, when populated, is
  authoritative.
- **Match host suffixes at a label boundary.** `EndsWith` matched inside a
  label, so narrowing the list to `contoso.vault.azure.net` also admitted
  `evilcontoso.vault.azure.net` — the configuration that looked safest was the
  one that silently failed.
- **Force challenge resource verification on.** A caller-supplied
  `SecretClientOptions` could set `DisableChallengeResourceVerification`, letting
  a vault name a different resource in its authentication challenge and have the
  SDK fetch a token for it. It is now overridden, as `IsLoggingContentEnabled`
  already was. `AdditionallyAllowedTenants` is exposed so the credential can be
  pinned to one tenant.
- **Detect references the resolver never saw.** Resolution is a single sweep at
  registration, so a source registered afterwards — or a reloading source that
  gains a reference later — overrode the resolved values and was never resolved,
  handing the application the literal reference string to use as a credential.
  A later source is now reported as `ResolverNotLastSource` (1005 / 2006) at
  `Error`, and `AssertNoUnresolvedReferences` / `FindUnresolvedReferences` (plus
  the `...VaultReferences` pair) let a caller fail startup instead.
- **Stop double-decoding the secret name.** Parsing called
  `Uri.UnescapeDataString` on an already partially decoded path, so
  `%252e%252e%252f` reached the SDK as `../`. Azure.Core re-escapes the segment,
  so nothing was exploitable, but the decode is gone and names are now validated
  against Key Vault's own rules.

### Added

- `KeyVaultReferenceResolverOptions.AllowedVaultHosts`,
  `AdditionallyAllowedTenants` and `MaxCacheEntries`.
- `HashiCorpVaultResolverOptions.StrictVaultAddressValidation` and
  `MaxCacheEntries`.
- `IConfiguration.FindUnresolvedReferences()` /
  `AssertNoUnresolvedReferences()`, and the HashiCorp equivalents.
- Log events `ResolverNotLastSource`, `UnresolvedReference`, `CacheFull` and
  `VaultAddressUnverified`.

### Fixed

- **HashiCorp references embedded in a larger value.** The whole configuration
  value was replaced by the secret, so
  `Server=db;Password=@HashiCorp.Vault(...);Encrypt=true` resolved to the bare
  password. References are now substituted in place, matching the Azure package.
  If any reference in a value fails, the whole value becomes `null`.
- **Deadlock when registering under a `SynchronizationContext`.** The resolution
  is awaited synchronously while the `ISecretResolver` belongs to the caller, so
  a resolver that yields without `ConfigureAwait(false)` posted its continuation
  to the very thread blocked waiting for it — under classic ASP.NET, WPF or
  WinForms, startup hung with no error. Resolution now runs on the thread pool
  when a context is present.
- **Cache entries keyed on the raw reference.** The same secret spelled two ways
  occupied two entries, so `InvalidateCache` could evict one while the other kept
  serving the pre-rotation value. Both resolvers now key on the parsed,
  canonical form.
- **Unbounded secret cache.** Nothing removed an entry, so a caller resolving
  references chosen at runtime held every secret it had ever seen for the life of
  the process. Capped by `MaxCacheEntries` (default 1024).

### Deprecated

- `MockSecretResolver`. A test double that can hand an application empty
  passwords should not ship inside the library; `EditorBrowsable(Never)` never
  stopped a dependency-injection registration. Use
  `KeyVaultReferenceResolver.Testing.FakeSecretResolver` from the test-support
  project. Removed in 2.0.

### Changed

- The release workflow is split into an unprivileged `build` job and a `publish`
  job that runs no project code, so the OIDC and write permissions are never in
  scope while compiling or testing. Its checkout now sets
  `persist-credentials: false`, as every other workflow already did.

### Planned for 2.0

Delivered in 2.0.0; see that entry.

## [1.3.0]

Security release. Every item under `Security` was found by a review of the
resolution path in both packages.

> **Read the Breaking behaviour changes section before upgrading.** Three changes
> alter runtime behaviour for existing consumers. No public signature changed, so
> the upgrade recompiles cleanly and the differences surface at run time.

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

- **Substitute references in place.** The patterns are unanchored, so a value
  only had to *contain* a reference to match — but the resolved secret then
  replaced the *entire* value. `"Server=db;Password=@Microsoft.KeyVault(...)"`
  collapsed to just the password, and a value embedding two references resolved
  only the first, silently discarding the rest. If any reference within a value
  now fails, the whole value becomes `null`: a connection string with an empty
  password in it is worse than a missing one.
- **Mask the reference stored on resolution exceptions.** Both exception types
  kept the unmasked reference on a public property, and both are thrown out of
  `Build()` during startup — so crash dumps, developer error pages and APM sinks
  that serialize exception properties recorded the vault and secret name. The
  HashiCorp side held the *raw configuration value*, so a compound value such as
  a connection string with an inline password was captured whole.
- **Keep secret names out of logs at Information and above.** `MaskUri` was
  applied only on the cache-hit and timeout paths; the success path logged the
  name verbatim at the level that ships to an aggregated log store by default.
  The per-key "Resolved reference" record moved to Debug, since one record per
  key maps exactly which keys hold credentials.
- **Validate HashiCorp secret paths.** The path pattern accepted anything but
  `;` and `)`, and went straight into the Vault request URL, so
  `SecretPath=secret/data/../../sys/mounts` was dot-segment-normalised into a
  different API endpoint and `?`/`#` spliced on a query or fragment.
- **Re-authenticate to Vault on 401/403.** VaultSharp logs in once and caches
  the result, so once the login token's TTL elapsed every read failed for the
  life of the process, and the cached client was never evicted.
- **Honour secret validity periods.** Key Vault does not block reads of an
  expired secret — expiry is advisory — so the library handed applications
  expired credentials and the failure surfaced later at the downstream service.
- **Log which Vault auth method was auto-selected.** A leftover `VAULT_TOKEN` in
  a production container silently overrode the intended workload identity, since
  token auth is tried before AppRole and Kubernetes, with nothing recording it.
- Dispose the temporary `IConfigurationRoot` built during resolution, which
  leaked a `FileSystemWatcher` per `reloadOnChange` source.
- `MockSecretResolver` marked `[EditorBrowsable(Never)]` with an explicit
  test-only warning, and its backing store made concurrent.

### Added

- `KeyVaultReferenceResolverOptions`: `ManagedIdentityClientId`, `TenantId`,
  `AuthorityHost`, `AllowDeveloperCredentials`, `ExcludeEnvironmentCredential`,
  `ClientOptions`, `AllowedVaultHostSuffixes`, `VaultDnsSuffix`,
  `RejectSecretsOutsideValidityPeriod`, `ExpiryWarningThreshold`,
  `OverallTimeout`, `MaxConcurrency`, `CacheTtl`, `Validate()`.
- `VaultDnsSuffix`, so the `VaultName=` format works in Azure Government and
  Azure China — it previously hard-coded `.vault.azure.net`.
- Public `LogEvents` and `HashiCorpLogEvents`, giving every record a stable
  EventId so log-based controls can be keyed on an identifier rather than
  message text.
- Actionable messages for Key Vault request failures: 401/403 names the
  `Key Vault Secrets User` role and the vault firewall, 404 mentions
  soft-delete, 429 points at `MaxConcurrency`.
- KV engine version probing: with `KvVersion` unset, a read is attempted as v2
  and retried as v1. Reading `sys/mounts` to detect it properly needs
  permissions a least-privileged token does not have.
- `(message)` and `(message, innerException)` constructors on both exception
  types (CA1032).
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
- `KeyVaultReferenceResolutionException.SecretUri` and
  `HashiCorpVaultReferenceResolutionException.VaultReference` now return the
  masked form. Code reading them to reconstruct a URI must use the
  configuration value instead.
- A value embedding a reference alongside literal text now keeps that text. Any
  code that relied on the whole value being replaced by the secret will see
  different output — though that behaviour produced malformed connection
  strings, so it is unlikely to have been depended on deliberately.

### CI and supply chain

- All GitHub Actions pinned to commit SHAs; `permissions: contents: read` on
  CI; `persist-credentials: false` on checkouts that do not push.
- `claude.yml` gated on `author_association`, so untrusted input can no longer
  start a job holding repository secrets. `id-token: write` is retained on both
  Claude workflows because the action requires it to authenticate; the author
  gate is the control, not withholding the permission.
- CI fails on vulnerable direct or transitive packages.
- Added CodeQL (`security-extended`), Dependabot for `nuget` and
  `github-actions`, and an OpenSSF Scorecard workflow.
- **Build provenance attestation** over the packages and the SBOM. Verify with
  `gh attestation verify <file> --repo gijswalraven/KeyVaultReferenceResolver`.
- **CycloneDX SBOM** (spec 1.7) attached to each release, generated from a
  version-pinned tool manifest, with the component version taken from the
  release tag.
- The publish job runs in a protected `nuget-production` environment. **This
  still needs configuring in repository settings** with required reviewers.
- `NuGet.config` clears inherited restore sources and pins them to nuget.org
  with package source mapping, so a private feed cannot enter the resolution
  path. CI and release restore with `--locked-mode` against committed
  `packages.lock.json` files.
- Analyzers enabled repo-wide via `Directory.Build.props` with
  warnings-as-errors in Release, `NuGetAuditMode=all`, and
  `ContinuousIntegrationBuild` on CI for path-normalised PDBs.
- Both packages now declare a real supplier in `Authors`/`Company` rather than
  a placeholder, so generated SBOMs carry an identifying supplier name.
- Added `CONTRIBUTING.md` and `CODEOWNERS`.

### Known gaps

- **NuGet author signing** is not configured; it needs a code-signing
  certificate. Trusted Publishing plus provenance attestation are the integrity
  controls in the meantime.
- **Branch protection on `main`** is repository configuration rather than a
  file. `CONTRIBUTING.md` documents the ruleset the project expects.
- `MockSecretResolver` still ships inside the main package rather than a
  separate `.Testing` package, which would need its own nuget.org Trusted
  Publishing policy. It is hidden from IntelliSense and documented as test-only.

### Breaking behaviour changes, and how to upgrade

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
[2.0.0]: https://github.com/gijswalraven/KeyVaultReferenceResolver/compare/v1.4.0...v2.0.0
[1.4.0]: https://github.com/gijswalraven/KeyVaultReferenceResolver/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/gijswalraven/KeyVaultReferenceResolver/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/gijswalraven/KeyVaultReferenceResolver/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/gijswalraven/KeyVaultReferenceResolver/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/gijswalraven/KeyVaultReferenceResolver/releases/tag/v1.0.0
