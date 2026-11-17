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

CNG v0.3.1 validates export policy and the DACL before returning a signer. Its
public-key export does not export private-key material. This supports the
API-level non-exportable signing boundary; it does not prove hardware
protection, historical non-export, or resistance to a compromised
administrator/provider.

Since CNG v0.3.1, `Open` and `LoadOrCreate` fail closed on anomalous reads: a
security descriptor read that reports 0 bytes written is an error (it could
previously cause a panic), and the Export Policy read must report exactly 4
bytes, otherwise the call fails and no signer is returned. Since CNG v0.2.2
public-key export rejects a zero size and a written length of zero or larger
than the buffer, and parses only the bytes written. The zero-size guard
prevents a panic (in v0.2.1 a zero-size query result led to indexing an empty
buffer); the length checks turn an inconsistent export result into an error.
The adapter returns these errors from `LoadKey` unchanged, without a signer.
These are defensive guards; this module does not show that the real KSP
produces such results.

A directly loaded signer is caller-owned. Since CNG v0.2.1 a Windows signer is safe
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

When `windowscng.LoadOrCreate` (CNG v0.3.1) creates a new key and a later step
fails, what happens depends on the step. If setting the export policy or the
DACL fails before finalization, it only releases the unfinalized key handle:
nothing was persisted and no delete is attempted. If finalization fails, it
deletes the unfinalized key through the handle it created. If a step after a
successful finalization fails (for example validation or, since CNG v0.2.2,
building the signer, which includes exporting the public key), it attempts a
best-effort rollback that deletes the created key through that handle, never by
name. The original failure always remains the primary error. If the delete
succeeds, there is no `windowscng.ErrCleanupFailed`. If the delete fails, the
error also wraps `ErrCleanupFailed`: the new key may persist and must be
inspected. Keys that existed before the call, and keys opened with `Open`, are
never deleted on these paths. The adapter never calls LoadOrCreate; only the
enrollment example does (see Errors and logging).

Since CNG v0.3.0, one case of a failed delete is not reported as
`ErrCleanupFailed`: finalization is denied with `NTE_PERM`, the delete of the
never finalized key reports `NTE_BAD_KEYSET`, and the privilege check succeeds
and reports the caller as not privileged. The key was not persisted. The
finalize failure remains the primary cause and the delete status is retained in
the error, without `ErrCleanupFailed`. If the privilege check itself fails, if
the caller is privileged or if the statuses differ, the error still wraps
`ErrCleanupFailed`. CNG reports having checked this natively only on Windows NT
10.0.26200 with the Microsoft Software KSP, for an Administrator with a
UAC-filtered token, a standard user and LOCAL SERVICE (see the
[CNG finalize probe](https://github.com/keppin-oss/cng/blob/v0.3.1/docs/finalize-probe.md)).
This module has not repeated that check, and it does not cover other builds or
providers, or a caller whose token holds a service SID.

**Residual risk:** the rollback is not transactional. A finalized key is
visible to other processes before it is deleted, and termination of the process
between creation and rollback can leave it in place. The tests of this module
only inject the final error of `LoadOrCreate`, in the shape of a successful or
a failed rollback, and check the message, the flow and the removal of the
reserved output file. They do not run CNG's rollback algorithm, not even
against a fake provider; CNG tests it with simulated native operations in its
own repository. The absence of `ErrCleanupFailed` is therefore not an absolute
guarantee that no key persists. After any `LoadOrCreate` failure, verify
whether the named key exists before retrying, and clean it up in a controlled
way if it does.

CNG v0.2.x and later also offer per-key access policies and service-SID access
(`OpenWithPolicy`, `LoadOrCreateWithPolicy`, `ApplyPolicy`, `OpenForService`,
`LoadOrCreateForService`, `ApplyServicePolicy`). This module does not use them:
the adapter only calls `Open`, and the enrollment example only calls
`LoadOrCreate` with the default DACL. `Open` and `LoadOrCreate` accept DACL
entries beyond the expected ones; for keys shared by LOCAL SERVICE processes,
CNG documents the `*WithPolicy` variants instead.

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

CNG v0.3.1, with its default policy, requests
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
or unwrapping. A network error that carries typed evidence keeps its broad
category (see below).

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
example returns a fixed message stating that a step after creating a new key
failed (for example finalization, validation or signer setup, including
public-key export) and that the newly created key may still be persisted and
needs verification and
controlled manual cleanup. It carries no native message, key name, token or
path, and does not retain the native error chain. Every other `LoadOrCreate`
failure stays a generic `diagnostic.Safe` error. That includes a failure whose
rollback deleted the newly created key and, since CNG v0.3.0, a denied finalize
that left no key. As described under Key custody and lifecycle, such a generic
failure does not prove absolutely that no key was persisted. CNG v0.3.0 makes
native causes reachable with `errors.As` (`NCryptError`) and `errors.Is`
(`syscall.Errno`). This module does not query them and keeps not retaining the
native error chain. The Win32 causes that CNG v0.3.x keeps (v0.2.2 dropped
them) do not change the category, as described next.

`diagnostic.Safe` reports the stage, a fixed text and a broad category, and
builds a new error that retains no cause. The category comes from positive
evidence of a network error only: a `*net.OpError` or a `*net.DNSError`
anywhere in the error tree, through `Unwrap() error` and `Unwrap() []error`.
Satisfying the `net.Error` interface is not evidence (`syscall.Errno`,
`os.ErrDeadlineExceeded`, `context.DeadlineExceeded` and a `*url.Error` that
describes a local failure all satisfy or wrap it), and neither the error text,
the stage nor numeric system error codes are used. Without evidence the
category is `operation failed`, which includes a local deadline or a bare
`syscall.Errno`. When the tree holds several causes, the strongest category
present wins: `network timeout` (a recognized network error that reports a
timeout, never a local deadline in another branch), then `network failure`,
then `operation failed`. The category says that it is present, not that every
cause is of that kind. A `*net.OpError` reports a timeout only if its own cause
does (looking through one `*os.SyscallError`); a timeout behind any other
wrapper is not looked through. A real HTTP or timeout failure that does not
keep one of those two types is reported as `operation failed`.

The walk visits at most 1024 errors, counting a cause once for every path that
reaches it. A tree larger than that is not classified: it is reported as
`operation failed`, whatever evidence the part already visited held. The number
of visits depends only on the tree, so this does not depend on the order of the
branches either; for a tree within the limit the precedence above holds in any
order. The limit bounds the classifier's own walk. It assumes that the `Unwrap`
and `Timeout` methods of the errors it calls terminate, and it does not call the
timeout of a `*net.OpError` or `*net.DNSError` cause itself, which it visits as
a node of its own (a `*net.OpError` that wraps itself, directly or behind one
`*os.SyscallError`, therefore ends as `operation failed`). A cycle through
another wrapper that delegates `Timeout`, such as a `*url.Error` or an
`*os.PathError` that wraps the `*net.OpError` that wraps it, is outside that
assumption and can still exhaust the stack.

Before v0.2.3 `diagnostic.Safe` labelled as `network failure` or `network
timeout` any error whose chain contained an error implementing `net.Error`.
That included a file-system error carrying a `syscall.Errno` (for example a JWT
file that cannot be read), any `*url.Error` (including a TLS certificate
verification failure and a local deadline) and an HTTP client timeout; a local
deadline was reported as `network timeout`. These are now `operation failed`.
Scripts or documentation that compare these labels literally need to be updated.

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
and need no live Controller. On Windows, a few of them (missing-key mapping,
dispatch to the engine, the reference-delimiter regression) open the software
KSP and look up key names that do not exist.

Consumer tests also replace the `windowscng.Open`/`LoadOrCreate` calls with
in-memory fake signers. These calls go through unexported package variables
that only tests reassign, and the tests run serially. The tests check that:
- `Open` errors reach `identity.LoadKey` and `CertMatchesSigner` with
  `errors.Is` preserved and no signer returned;
- invalid names and references fail before `Open`/`LoadOrCreate`;
- every signer opened by `CertMatchesSigner` is closed exactly once, and Close
  failures are redacted;
- in the enrollment example, a v0.2.2-shaped `ErrCleanupFailed` maps to the
  fixed cleanup message and a rollback that succeeded stays generic, while the
  reserved output is removed and the setup signer is closed once.

These tests reproduce the documented error shapes of CNG v0.2.2. In CNG v0.3.x
`ErrCleanupFailed` wraps the delete status with `%w` instead of `%v`, which does
not change how the example maps it. They do not
exercise the real KSP, its rollback or its export guard, and they do not observe
the Close-before-enrollment order, which the code fixes.

### Validation status of the CNG v0.3.1 upgrade

Run on Windows 11 with Go 1.26.8: `go mod verify` and `go mod tidy -diff`;
build and `go vet` for windows/amd64, windows/386 and linux/amd64, and on
windows/amd64 also `go vet` with the `cng_smoke` and `cng_enroll` tags
(compilation only); and the default suite on windows/amd64 and windows/386,
with synthetic data only and with the three tests above skipped (for
`TestReferenceRequiresQueryDelimiter` the whole test), using `go test
-buildvcs=false -count=1 -skip
'TestLoadKeyMissingKeyMapped|TestLoadKeyDispatchesToCNG|TestReferenceRequiresQueryDelimiter'
./...`. The same suite also ran with `-race -count=2` on windows/amd64
(`CGO_ENABLED=1`, MinGW-W64 GCC) without race reports. Not run: the live tests
(`cng_smoke`, `cng_enroll`), the three skipped tests, runtime tests on Linux and
the tests of the dependency. There is no remote CI.

A successful sign/verify test establishes that the tested signature verifies
against the returned public key. A type assertion rejecting *ecdsa.PrivateKey
only establishes the returned Go type. Neither proves that private material was
never copied elsewhere. Absence of .pem/.key files is not automatically measured.
Token reuse/consumption, actual ACL behavior and complete TLS SDK operation
require separate controlled integration validation.

### Tagged fixture tests

The pinned CNG v0.3.1 API used here (Open/LoadOrCreate/Delete) exposes no atomic
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
# Choose a unique name, then provision it separately with keppin-oss/cng v0.3.1.
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
