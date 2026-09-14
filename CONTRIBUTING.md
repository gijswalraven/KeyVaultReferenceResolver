# Contributing

Thanks for considering a contribution. This library moves credentials from a vault
into application configuration, so the bar for changes is a little higher than for an
average utility package — an ordinary bug here becomes a credential exposure.

Found a security problem? **Do not open an issue.** Follow [SECURITY.md](SECURITY.md).

## Getting set up

```bash
git clone https://github.com/gijswalraven/KeyVaultReferenceResolver.git
cd KeyVaultReferenceResolver
dotnet restore --locked-mode
dotnet build -c Release
dotnet test -c Release
```

You need the .NET SDK pinned in [global.json](global.json). Restore sources are pinned in
[NuGet.config](NuGet.config) to nuget.org only — do not add a private feed.

A few things are deliberate and will bite you if you do not know them:

- **Release builds treat warnings as errors.** Debug builds do not, so iterate in Debug
  and check `-c Release` before pushing.
- **Lock files are committed.** If you change a `PackageReference`, run `dotnet restore`
  and commit the updated `packages.lock.json`. CI restores in locked mode and will fail
  if you don't.
- **Test projects relax three analyzer rules** (see `tests/Directory.Build.props`).
  Production code does not; don't add suppressions there without a reason in the file.

## Branch and pull request flow

1. Branch from `main`. Use a prefix that says what the change is:
   `fix/`, `feat/`, `security/`, `docs/`, `chore/`, `ci/`.
2. Keep one logical change per commit, and make each commit build and pass tests on its
   own. A reviewer should be able to read the series, and a bisect should never land on a
   broken commit.
3. Write the commit message to explain *why*, not what the diff already shows. For a
   security fix, say what the previous behaviour allowed.
4. Open a pull request against `main`. CI must be green: build, tests, the vulnerable
   package check, and CodeQL.

`main` is expected to be protected: pull request required, at least one approving review
from a code owner, required status checks, linear history, no force pushes. If you have
admin rights and it is not configured, that is worth fixing before anything else.

## What a change to the resolution path needs

Anything touching credential selection, vault host or address validation, reference
parsing, caching, logging or exception content also needs:

- **A test that fails without the fix.** For security changes, a test that demonstrates
  the old behaviour was exploitable is worth more than one that asserts the new
  behaviour is correct.
- **No new secret in a log or an exception.** `SecretLeakageTests` enforces this with a
  sentinel value; if you add a log or exception that carries a reference, extend it.
- **Fail closed.** A new option must not make it possible for an unresolved reference to
  reach the application as though it were a secret. Options that default to the less safe
  behaviour will be asked to flip.
- **A CHANGELOG entry.** Security-relevant changes go under a `### Security` heading.
- **Updated XML docs and README** if the change is observable to a consumer. Documentation
  that describes behaviour the code no longer has is treated as a defect.

## Testing

xUnit v3, no FluentAssertions — plain `Assert`. Name tests
`Method_Scenario_ExpectedResult`, so a failure in CI output reads as a sentence.

Use `MockSecretResolver` rather than reaching for a live vault. It is test-only and
marked as such; never register it in application code.

If `dotnet test` reports "Zero tests ran" on your machine, run the test executables
directly (`tests/<project>/bin/Release/net8.0/<project>.exe`) — that is a local
toolchain quirk, not a broken suite.

## Releasing

Maintainers only:

1. Bump `<Version>` in both `src/**/*.csproj` and add the CHANGELOG section.
2. Tag `vX.Y.Z` and publish a GitHub release. The release workflow verifies that the tag
   matches the csproj version and fails before publishing if it does not.
3. The workflow packs, attests build provenance, generates and attaches an SBOM, and
   publishes to nuget.org via Trusted Publishing (OIDC — there is no long-lived API key).
   It runs in the protected `nuget-production` environment, so it waits for approval.

Follow [Semantic Versioning](https://semver.org/). Note that a behaviour change can break
a consumer at runtime even when every public signature is unchanged and the upgrade
recompiles cleanly — 1.3.0 is the example, since it changed what happens when a reference
cannot be resolved. Where such a change ships in a minor version, the breaking behaviour
must be called out at the top of its CHANGELOG entry.

## Never commit

- A real secret, token, connection string or certificate — not even redacted-looking
  ones, and not in a test fixture.
- A private feed in `NuGet.config`.
- A new `.nupkg`; build output is gitignored on purpose.
