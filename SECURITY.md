# Security Policy

KeyVaultReferenceResolver resolves secrets into application configuration, so a
defect here can expose credentials. Reports are taken seriously and triaged
promptly.

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Report privately through GitHub's
[private vulnerability reporting](https://github.com/gijswalraven/KeyVaultReferenceResolver/security/advisories/new)
on this repository. That creates a private advisory visible only to the
maintainers.

Please include:

- the affected package (`KeyVaultReferenceResolver` or
  `KeyVaultReferenceResolver.HashiCorp`) and version,
- the .NET target framework and host (App Service, AKS, container, local),
- a description of the impact, and
- a minimal reproduction if you have one.

Never include a live secret, token or connection string in a report. Redact
them; the shape of the value is enough.

### What to expect

| Stage | Target |
| --- | --- |
| Acknowledgement | within 3 business days |
| Initial assessment and severity | within 7 business days |
| Fix or documented mitigation for High/Critical | within 30 days |
| Public advisory | after a fix ships, coordinated with the reporter |

This is a volunteer-maintained open source project, so these are targets rather
than contractual guarantees. If you have not heard back within the
acknowledgement window, please escalate by opening a *non-descriptive* public
issue ("security report awaiting triage") without details, and a maintainer will
follow up privately.

Credit is given in the advisory unless you prefer to remain anonymous.

## Supported versions

Fixes are applied to the latest minor of the current major only. There is no
long-term support branch.

| Package | Version | Supported |
| --- | --- | --- |
| KeyVaultReferenceResolver | 1.3.x | Yes |
| KeyVaultReferenceResolver | 1.2.x and earlier | No - upgrade to 1.3.x |
| KeyVaultReferenceResolver.HashiCorp | 1.3.x | Yes |
| KeyVaultReferenceResolver.HashiCorp | 1.1.x | No - upgrade to 1.3.x |

Every fix listed in the 1.3.0 release notes is a security fix. Versions below 1.3.0
contain all of them unpatched, including the fail-open resolution path and the missing
vault host validation, so upgrading is the remediation.

## Scope

In scope:

- Secret material reaching a log, exception message, telemetry sink or crash
  dump when the documented configuration is used.
- A configuration value causing the resolver to contact a vault or host other
  than the intended one, or to send credentials to it.
- Authentication or transport weaknesses in how the library talks to Azure Key
  Vault or HashiCorp Vault.
- Failure modes where an unresolved reference is presented to the application as
  though it were a valid secret.

Out of scope:

- Misconfiguration of the vault itself (over-broad RBAC, disabled purge
  protection, public network access). The library cannot compensate for these;
  see the hardening guidance in the README.
- Secrets exposed by the *consuming* application after resolution - for example
  rendering `IConfigurationRoot.GetDebugView()` on a public endpoint. This is
  documented behaviour of `IConfiguration`, not a library defect.
- Vulnerabilities in `Azure.Identity`, `Azure.Security.KeyVault.Secrets` or
  `VaultSharp`. Report those to their maintainers; we will bump the dependency
  once a fix is available.
- Anything requiring an attacker to already have code execution in the host
  process.

## Security-relevant design notes

Documented deliberately, so they are not reported as surprises:

- Resolved secrets become ordinary `string` values in `IConfiguration`. They
  cannot be zeroed and will appear in a full process dump.
- Configuration references are resolved once while the configuration is built.
  Refreshing a resolver's cache does not change values already in
  `IConfiguration`; picking up a rotated secret requires an application restart.
- `ThrowOnResolveFailure = false` sets an unresolvable key to `null`. It never
  leaves the literal reference string in place.
