# CertificateStoreCredential

An Azure `TokenCredential` for an **Entra ID service principal that authenticates with a client certificate from the Windows certificate store**, including certificates whose private key is **non-exportable**.

It is the credential to use when there is no managed identity, no `az login`, and no secret may be written to disk: the private key stays in the store and is used in place. `EnvironmentCredential` cannot do this, because it only reads a certificate from a file (`AZURE_CLIENT_CERTIFICATE_PATH`).

- Depends only on **Azure.Identity**. No Key Vault, configuration, logging or SQL client library.
- `netstandard2.0`; the certificate store is a Windows concept (see [Limitations](#limitations)).
- One object owns the loaded certificate and wraps one `ClientCertificateCredential`: one `Dispose()`. Tokens are cached by the wrapped credential.

It is also what [KeyVaultReferenceResolver](https://github.com/gijswalraven/KeyVaultReferenceResolver) uses for certificate authentication, so the two behave identically.

```powershell
dotnet add package CertificateStoreCredential
```

## The developer experience: as close to a managed identity as it gets

1. Set the two standard variables, `AZURE_TENANT_ID` and `AZURE_CLIENT_ID`.
2. Create a certificate with the client ID in its subject (non-exportable key, in `CurrentUser\My`).
3. Write no certificate-specific code, and no thumbprint in configuration.

```csharp
using CertificateStoreCredentials;

// null when the convention does not apply (see below), so a laptop falls back to the default chain.
TokenCredential credential =
    (TokenCredential?)CertificateStoreCredential.TryCreateFromEnvironment() ?? new DefaultAzureCredential();
```

## Usage

### By convention

```csharp
using CertificateStoreCredential? credential = CertificateStoreCredential.TryCreateFromEnvironment();
```

`TryCreateFromEnvironment()` looks in `CurrentUser\My`, then `LocalMachine\My`, for a certificate whose **subject or friendly name contains `AZURE_CLIENT_ID`** (case-insensitive). Among matches it prefers one that is currently valid and has a private key, then the one that expires last, so a renewed certificate is picked up without any change.

It returns **`null`** (the convention does not apply) when:

- `AZURE_TENANT_ID` or `AZURE_CLIENT_ID` is not set, or
- no certificate names the client ID, or
- `AZURE_CLIENT_SECRET`, `AZURE_CLIENT_CERTIFICATE_PATH`, `AZURE_FEDERATED_TOKEN_FILE`, `AZURE_USERNAME` or `AZURE_PASSWORD` is set (another mechanism is configured).

It **throws `InvalidOperationException`** when a certificate does name the client ID but is unusable (expired, not yet valid, or no accessible private key). That is deliberately not "does not apply": a broken setup must not look like an unconfigured one. (The `KeyVaultReferenceResolver` package, which sets `AZURE_CLIENT_ID` aside for managed identities, catches this, logs a warning and uses its default chain; code that calls this method directly decides for itself.)

### Explicitly (certificate required)

```csharp
// By client ID: the certificate whose subject or friendly name contains it.
using var credential = CertificateStoreCredential.Create(new CertificateStoreCredentialOptions(tenantId, clientId));

// One store only, or pinned to a thumbprint (the thumbprint may be pasted from the Certificates snap-in):
// new CertificateStoreCredentialOptions(tenantId, clientId, StoreLocation.LocalMachine)
// new CertificateStoreCredentialOptions(tenantId, clientId, thumbprint)
```

`Create` throws `InvalidOperationException` if the certificate is missing, has no accessible private key, has expired or is not yet valid. The certificate is found and validated **when the credential is created**, not on the first token request.

Both factories have an overload taking a `ClientCertificateCredentialOptions` (authority host, additionally allowed tenants, retry settings) for the wrapped credential. Without it the Azure Identity defaults apply, including `AZURE_AUTHORITY_HOST`.

### Getting a token

```csharp
AccessToken token = await credential.GetTokenAsync(
    new TokenRequestContext(new[] { "https://database.windows.net/.default" }),   // Azure SQL, for example
    cancellationToken);
```

Create **one** instance and keep it for the lifetime of the application (a singleton): a new instance per call discards the token cache. `Dispose()` releases the loaded certificate, may be called more than once, and makes later token requests throw `ObjectDisposedException`. `Thumbprint` tells you which certificate was picked, for logging; it is not a secret.

## Create the certificate

On the VM, **as the account that runs the application** (the `CurrentUser` store belongs to a specific account profile):

```powershell
$clientId = "<application (client) id>"

$cert = New-SelfSignedCertificate `
    -Subject "CN=$clientId" `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -KeyExportPolicy NonExportable `
    -KeyAlgorithm RSA -KeyLength 2048 `
    -HashAlgorithm SHA256 `
    -Provider "Microsoft Software Key Storage Provider" `
    -NotAfter (Get-Date).AddYears(1)

# Only the public key goes to Entra ID.
Export-Certificate -Cert $cert -FilePath ".\$clientId.cer" -Type CERT
az ad app credential reset --id $clientId --cert "@$clientId.cer" --append
```

Notes:

- `-KeyExportPolicy NonExportable` is the point: the key cannot be exported through normal means. The certificate cannot be moved to another machine, so a new VM gets its own certificate.
- Do not add `-KeySpec` with the Key Storage Provider; it fails with `NTE_PROV_TYPE_NOT_DEF`.
- `--append` keeps certificates already registered on the app registration. Without it the command replaces them.
- For `LocalMachine\My` (several accounts, or `SYSTEM`), run elevated with `-CertStoreLocation "Cert:\LocalMachine\My"` and grant the run-as account **Read** on the private key (`certlm.msc`, **Manage Private Keys**).
- Verify: `Get-ChildItem Cert:\CurrentUser\My | Where-Object Subject -like "*$clientId*"` shows `HasPrivateKey` as `True` and a `NotAfter` in the future.

The service principal also needs whatever access the target resource requires (for Key Vault, the `Key Vault Secrets User` role; for Azure SQL, a database user for the identity).

## Rotation

With the convention, nothing changes in the application:

1. Create a new certificate with the same `CN=<client id>`, well before the old one expires.
2. Upload its public key with `--append`.
3. Restart the application. The valid certificate that expires last is picked.
4. Once every machine has switched, remove the old certificate from Entra ID and from the store.

With a thumbprint, update the thumbprint at step 3. An expired certificate stops the application at startup with a clear message, by design, so keep the expiry date in a calendar.

## Error messages

All are `InvalidOperationException`, thrown when the credential is created, and name the store and the process user; none contains key material.

| Message starts with | Cause and fix |
| --- | --- |
| `No client certificate whose subject or friendly name contains the client ID ...` | `Create` by client ID found nothing. Check the subject and that you run as the account whose store holds it. |
| `The client certificate with thumbprint ... was not found` | Wrong thumbprint, or the certificate is in another account's store. |
| `... has no private key, or this account cannot access it` | Imported without its key, or a machine-store key without Read for the run-as account. |
| `... expired on <date>` | Rotate the certificate. |
| `... is not valid before <date>` | Start date in the future or a wrong clock (5 minutes of skew are tolerated). |

Token failures from Entra ID come from Azure.Identity, for example `AADSTS700027` (the certificate in the store is not the one registered on the app) and `AADSTS700016` (wrong client or tenant ID).

## Limitations

- The certificate store is a Windows concept. On other platforms the lookup works where .NET provides a `My` store and otherwise fails with the same `InvalidOperationException`, or, for the convention, returns `null`.
- `TryCreateFromEnvironment()` takes only the standard variables. There is deliberately no thumbprint variable.
- Creating and exporting certificates is outside the package's scope; the commands above use standard Windows and Azure CLI tooling.

Step-by-step guides, including Scheduled Task deployment, rotation scripts and troubleshooting, are in the [repository documentation](https://github.com/gijswalraven/KeyVaultReferenceResolver/tree/main/docs).
