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

CNG v0.2.1 validates export policy and the DACL before returning a signer (the
validation logic is unchanged from v0.1.2). Its public-key export does not export
private-key material. This supports the API-level non-exportable signing
boundary; it does not prove hardware protection, historical non-export, or
resistance to a compromised administrator/provider.

A directly loaded signer is caller-owned. In CNG v0.2.1 a Windows signer is safe
for concurrent use: Sign calls may overlap each other and Close, a Sign ordered
after Close fails without calling CNG, and Close is idempotent (the first call
reports release failures, later calls return nil). Close does not drain callers;
stop and drain signing users (for example in-flight TLS handshakes) before
closing. Closing a handle never removes a key.

`windowscng.ErrKeyNotFound` means the native open reported the key as **not
found or not accessible** (`NTE_NOT_FOUND`/`NTE_BAD_KEYSET`). The software KSP
has been observed to report `NTE_BAD_KEYSET` to callers the DACL does not grant,
so the error is not proof of absence and must never by itself trigger a reset,
regeneration or overwrite of an identity key. `windowscng.Delete` deletes exactly
the named key; on "not found or not accessible" it deletes nothing and returns an
error wrapping `ErrKeyNotFound`, which does not prove the key is gone.

`windowscng.LoadOrCreate` may return `windowscng.ErrCleanupFailed`, joined with
the original failure, when it created a new key, validation failed and deleting
that new key also failed: the new key may persist and must be inspected.
Pre-existing keys are never deleted on that path. The adapter never calls
LoadOrCreate; only the enrollment example does (see Errors and logging).

**Residual risk:** `ErrCleanupFailed` identifies one known case in which a newly
created key may persist; its absence does **not** prove that no key was
persisted. Other `LoadOrCreate` failure paths in CNG v0.2.1 (for example a
failure while exporting the public key of a newly created key) can return a
generic error while the new key remains. After any `LoadOrCreate` failure,
verify whether the named key exists before retrying, and clean it up in a
controlled way if it does.

CNG v0.2.x also offers per-key access policies and service-SID access
(`OpenWithPolicy`, `LoadOrCreateWithPolicy`, `ApplyPolicy`, `OpenForService`,
`LoadOrCreateForService`, `ApplyServicePolicy`). This module does not use them:
the adapter only calls `Open`, and the enrollment example only calls
`LoadOrCreate` with the default DACL.

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

CNG v0.2.1, with its default policy (unchanged from v0.1.2), requests
SYSTEM/Administrators full access and LOCAL SERVICE read/execute access when
provisioning. The software KSP may canonicalize generic
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

CertMatchesSigner redacts certificate-parsing and signer-close failures the same
way. When it cannot open the key it wraps the `windowscng` error (key name and
HRESULT, no secrets) so callers can still test `errors.Is(err,
windowscng.ErrKeyNotFound)`. The enrollment example redacts that error with
`diagnostic.Safe` before printing it: it reports that enrollment succeeded and
the configuration was saved, and that verifying the saved certificate against
the CNG key failed, without the key name, HRESULT or native error chain.

The load-identity example never prints the identity key field and rejects PEM,
file and malformed references before loading. The enrollment example also builds
on Linux/non-Windows, where its CNG and enrollment operations are not supported
at runtime; it accepts a JWT file path, not a raw JWT argument, and persists JSON to
an exclusively created output. Protect JWT files and output directories with OS
access controls. The output contains identity certificates and CNG references,
not CNG key bytes.

When `LoadOrCreate` fails with `windowscng.ErrCleanupFailed`, the enrollment
example returns a fixed message stating that creation or validation failed and
that the newly created key may still be persisted and needs verification and
controlled manual cleanup. It carries no native message, key name, token or
path, and does not retain the native error chain. Every other `LoadOrCreate`
failure stays a generic `diagnostic.Safe` error; as described under Key custody
and lifecycle, such a generic failure does not prove that no key was persisted.

BuildFlags is an SDK integration primitive: direct callers receive flags carrying
the JWT/claims and bypass Enroll's safe error boundary. Do not log those flags or
raw SDK errors. The wrapper does not reconfigure the SDK's global logging or
claim that all upstream diagnostics are sanitized.

The separately reported OpenZiti Controller v2.0.3 service-session JWT logging
issue is upstream context. This module neither fixes nor reproduces that issue.

## Validation boundaries

Default tests check name/reference round trips and rejection, engine registration,
expected dispatch/platform errors, token-source handling, error redaction
(including both branches of the enrollment example's `LoadOrCreate` error
mapping and its `CertMatchesSigner` redaction, using synthetic errors),
rejection of private-key output, and configuration serialization/no-overwrite.
They use synthetic identity/token material, never create or delete CNG keys,
and need no live Controller.

A successful sign/verify test establishes that the tested signature verifies
against the returned public key. A type assertion rejecting *ecdsa.PrivateKey
only establishes the returned Go type. Neither proves that private material was
never copied elsewhere. Absence of .pem/.key files is not automatically measured.
Token reuse/consumption, actual ACL behavior and complete TLS SDK operation
require separate controlled integration validation.

### Tagged fixture tests

The pinned CNG v0.2.1 API used here (Open/LoadOrCreate/Delete) exposes no atomic
create-exclusive operation or created-by-this-call result. A random name plus an absence check
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
# Choose a unique name, then provision it separately with keppin-oss/cng v0.2.1.
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
