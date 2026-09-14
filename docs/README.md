# OpenZiti-CNG technical reference

## Architecture and registration

`identity.LoadKey` dispatches a parsed engine URL through the OpenZiti engine
registry to `cngengine`, then `windowscng.Open`. The returned CNG signer exposes
`crypto.Signer` and `Close() error`. Each successful load opens independent
provider/key handles. The engine itself has no mutable per-call state.

Blank-import `cngengine` even when importing `enrollcng`; registration is a
process-wide initialization step. Runtime replacement of registry entries is
not part of this module's supported lifecycle.

The module delegates token verification, CSR generation and Controller exchanges
to the SDK. An enrollment result does not establish application authorization,
tenant membership, installation state or licensing.

## Reference grammar and compatibility

Use `enrollcng.KeyReference(name)` to construct `cng:<name>?`.
The exact name grammar is `[A-Za-z0-9][A-Za-z0-9._-]{0,127}`.
Invalid names are rejected, never normalized. Creation helpers in examples,
comparison helpers and reference loading use the same name validation.

The pinned identity v1.0.140 Windows parser indexes the second element after
splitting engine addresses on `?`. Without the delimiter it can panic before
the engine runs. The trailing `?` is a version-specific workaround, not an
instruction to send query parameters. A regression test records that upstream
behavior. The load-identity example validates the entire string before dispatch.

The engine supports the Windows `Host` representation and the opaque
representation produced by `net/url`. Nonempty queries, fragments, user info,
path forms and conflicting fields are rejected. The upstream Windows parser
has already removed a leading `//` before engine dispatch; therefore this engine
cannot distinguish that spelling from the canonical form. Validate full strings
before dispatch where strict canonical spelling is required. Helpers and the
load-identity example do so. A direct engine URL also cannot prove that the
original string had the required delimiter.

With sdk-golang/v2 v2.0.0-pre4, a nonempty `KeyFile` that does not resolve to a file
is retained as the identity key reference. Canonical references do not name
ordinary Windows files; the OTT path loads the CNG signer to create the CSR.
Enroll rejects non-Windows execution before the SDK can interpret a reference as an ordinary Unix filename. Direct BuildFlags/SDK callers must enforce the same platform boundary.

## Key custody and lifecycle

The adapter calls Open, never LoadOrCreate. Missing or invalid keys fail instead
of creating replacements. Provisioning is performed by the caller/CNG provider.

CNG v0.1.2 validates export policy before returning a signer. Its public-key
export does not export private-key material. This supports the API-level
non-exportable signing boundary; it does not prove hardware protection, historical
non-export, or resistance to a compromised administrator/provider.

A directly loaded signer is caller-owned. Close it only after signing users have
stopped. CNG v0.1.2 does not synchronize Sign against Close. Do not concurrently
close a signer or reuse it after closing. Closing a handle never removes a key.

CertMatchesSigner closes the signer it opens, including on certificate errors,
and returns cleanup failures. It validates the name and rejects a nil config.
It checks public-key equality only, without certificate-chain validation.

### Residual SDK limitation

The pinned SDK's enrollOTT calls identity.LoadKey for its CSR signer but does not
call Close or expose the signer to enrollcng.Enroll. That handle cannot be closed
locally through the public API. Repeated enrollment attempts can accumulate
native resources until process exit. Identity loading failures/reloads have
similar dependency-owned lifetime limitations. Closing a separately opened
signer does not repair them. This module does not introduce a global cache or
reimplement enrollment to hide the limitation. Short-lived enrollment processes
bound its lifetime; long-running consumers should account for the limitation.

## DACL boundary

CNG v0.1.2 requests SYSTEM/Administrators full access and LOCAL SERVICE read/
execute access when provisioning. The software KSP may canonicalize generic
permission masks.

Its validator requires the expected SYSTEM, Administrators and LOCAL SERVICE
allow ACEs, rejects duplicates of those principals, checks selected generic-mask
properties and rejects allow ACEs for Everyone, Authenticated Users, Built-in
Users, Interactive Users, Service and Anonymous. It rejects missing/null/empty
DACLs. It does not reject every other SID or evaluate every ACE type or right.

Consequently validation does **not** establish an exclusive principal allow-list,
fully evaluate ownership/inheritance, or certify effective Windows access.
LOCAL SERVICE is a shared Windows account, not isolation between services.
Deployment ACL review and behavioral access testing remain caller responsibilities.

## Errors and logging

Enroll returns stage/category diagnostics and does not retain or wrap raw SDK
errors. This avoids disclosing enrollment URLs with token query parameters,
JWT material or arbitrary Controller response bodies through error formatting
or unwrapping. Network failures/timeouts retain their broad category.

The load-identity example never prints the identity key field and rejects PEM,
file and malformed references before loading. The enrollment example accepts a
JWT file path, not a raw JWT argument, and persists JSON to an exclusively created
output. Protect JWT files and output directories with OS access controls.
The output contains identity certificates and CNG references, not CNG key bytes.

BuildFlags is an SDK integration primitive: direct callers receive flags carrying
the JWT/claims and bypass Enroll's safe error boundary. Do not log those flags or
raw SDK errors. The wrapper does not reconfigure the SDK's global logging or
claim that all upstream diagnostics are sanitized.

The separately reported OpenZiti Controller v2.0.3 service-session JWT logging
issue is upstream context. This module neither fixes nor reproduces that issue.

## Validation boundaries

Default tests check name/reference round trips and rejection, engine registration,
expected dispatch/platform errors, token-source handling, error redaction,
rejection of private-key output, and configuration serialization/no-overwrite.
They use synthetic identity/token material; no live Controller is required.

A successful sign/verify test establishes that the tested signature verifies
against the returned public key. A type assertion rejecting *ecdsa.PrivateKey
only establishes the returned Go type. Neither proves that private material was
never copied elsewhere. Absence of .pem/.key files is not automatically measured.
Token reuse/consumption, actual ACL behavior and complete TLS SDK operation
require separate controlled integration validation.

### Tagged fixture tests

The pinned CNG API exposes Open/LoadOrCreate/Delete but no atomic create-exclusive
operation or created-by-this-call result. A random name plus an absence check
does not establish deletion ownership. Therefore tagged tests **never create or
delete persisted keys**. They own only the handles they open; cleanup errors fail.

The operator should provision a fresh test-only key using CNG in a protected
environment, with a unique name beginning with the required `OpenZitiCNG.Test.`
prefix, for example `OpenZitiCNG.Test.<random-guid>`. Both tagged tests fail if a
configured `CNG_TEST_KEY_NAME` is outside this namespace, even without a token.
Keep ownership records and perform any persisted-key cleanup outside these tests.
Never use production keys. The former CNG_KEY_NAME/default shared fixture is
replaced by explicit CNG_TEST_KEY_NAME.

```powershell
# Choose a unique name, then provision it separately with Keppin-OSS CNG.
$env:CNG_TEST_KEY_NAME = "OpenZitiCNG.Test." + [guid]::NewGuid().ToString("N")
# After provisioning:
go test -buildvcs=false -tags cng_smoke ./cngengine -run TestIdentityLoadKeySignVerify -count=1
# Live enrollment additionally requires a disposable identity and fresh OTT file:
$env:ZITI_OTT_JWT = "C:\secure\test-identity.jwt"
go test -buildvcs=false -tags cng_enroll ./enrollcng -run TestLiveOttEnrollmentWithCNGKey -count=1
```

Only absent explicit fixture/token configuration skips these tests. Once configured,
key-open/security-validation, signing, enrollment, verification and cleanup
failures fail the test. Opening a provisioned fixture is governed by its DACL;
tests do not infer administrator absence from an arbitrary provider failure.
The live test consumes an OTT token and does not save its disposable configuration.

Compile tags without running live tests using `go test -c -buildvcs=false -tags
cng_smoke ./cngengine` and the corresponding cng_enroll command with a selected
output location. Ordinary tests do not exercise these tagged paths.
