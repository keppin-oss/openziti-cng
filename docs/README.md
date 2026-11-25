# OpenZiti-CNG technical reference

This reference applies to `github.com/keppin-oss/openziti-cng` v0.3.0, built
against `github.com/keppin-oss/cng v0.5.1`, `github.com/openziti/identity
v1.0.140` and `github.com/openziti/sdk-golang/v2 v2.0.0-pre4`, with Go 1.26.8.

## Architecture and registration

`identity.LoadKey` dispatches a parsed engine URL through the OpenZiti engine
registry to `cngengine`, which reads the container name and the policy from the
reference and calls `windowscng.Open(name, policy)`. The returned CNG signer
exposes `crypto.Signer` and `Close() error`. Each successful load opens
independent provider/key handles. The engine itself has no mutable per-call
state and no default policy.

Blank-import `cngengine` even when importing `enrollcng`; registration is a
process-wide initialization step. Runtime replacement of registry entries is
not part of this module's supported lifecycle.

The module delegates token verification, CSR generation and Controller exchanges
to the SDK. An enrollment result does not establish application authorization,
tenant membership, installation state or licensing.

## Reference grammar and compatibility

A reference names the container and the policy its DACL must hold. There are
exactly three canonical forms:

```text
cng:<name>?policy=service-signer
cng:<name>?policy=privileged-only
cng:<name>?policy=service&service=<service-name>
```

Use `enrollcng.KeyReference(name, policy)` to construct them from a
`windowscng.KeyPolicy`. The grammar lives in `internal/keyref`, which keeps the
persistable descriptor of a policy (`keyref.Policy`: the policy name and, for
the service form, the service name) distinct from the `windowscng.KeyPolicy` it
resolves to. The persisted form carries the service name, never its SID or
`ServicePolicy.String()`.

- The name grammar is `[A-Za-z0-9][A-Za-z0-9._-]{0,127}`.
- A service name is valid if `windowscng.NewServicePolicy` accepts it: 1-256
  ASCII letters, digits, `.`, `_` or `-`. Those characters are unreserved in a
  URL query, so the canonical form needs no escaping, and any escaping is
  rejected.
- The parameters come in fixed order, each once, with no other parameter.
- There is no default: a reference without a policy, including the former
  `cng:<name>?`, is rejected, as are an unknown policy, `service` without
  `policy=service` (or the reverse), duplicated, reordered or extra parameters,
  `%`, `+`, fragments and user info.
- Invalid input is rejected, never normalized. `keyref.Parse` accepts a string
  only if `keyref.Format` writes it back byte for byte.

The pinned identity v1.0.140 Windows parser indexes the second element after
splitting engine addresses on `?`. Without the delimiter it can panic before
the engine runs; every canonical reference has one, because it introduces the
policy query. On Windows the parser hands the engine `Host` (the name) and
`RawQuery` (the policy); on other platforms `net/url` hands it `Opaque` and
`RawQuery`. `keyref.FromURL` accepts both shapes with the same query rules and
rejects user info, fragments, path forms, a `?` with no query and conflicting
fields. `TestReferenceRequiresQueryDelimiter` records the upstream parser
behavior, and `TestLoadKeyDispatchesEveryPolicyForm` proves, for each of the
three forms, that `identity.LoadKey` reaches `Open` with exactly the expected
name and policy.

The upstream parser has already removed a leading `//` before engine dispatch;
therefore the engine cannot distinguish `cng://<name>?...` from the canonical
`cng:<name>?...`. The original string is validated where this module sees it:
`enrollcng.KeyReference`, `BuildFlags` and `Enroll` build it, and the
load-identity example runs `keyref.Parse` on the whole string before dispatch.
Callers that hand strings to `identity.LoadKey` directly must validate them
first where strict canonical spelling is required.

With sdk-golang/v2 v2.0.0-pre4, a nonempty `KeyFile` that does not resolve to a file
is retained as the identity key reference. Canonical references do not name
ordinary Windows files; the OTT path loads the CNG signer to create the CSR.
Enroll rejects non-Windows execution before the SDK can interpret a reference as an ordinary Unix filename. Direct BuildFlags/SDK callers must enforce the same platform boundary.

## Key custody and lifecycle

The adapter and `enrollcng` call `Open`, never `Create` or `Delete`. A missing,
inaccessible or mismatching key fails; nothing is created in its place.
Creating a key is the consumer's job (the enrollment example shows it), and
deleting it belongs to the lifecycle owner.

CNG v0.5.1 `Open` checks, before returning a signer, that the key is
non-exportable, that its public key is ECDSA P-256 and that its DACL is
**exactly** the requested policy (`ErrPolicyMismatch` otherwise). It never
creates, modifies or deletes a key. With `PolicyPrivilegedOnly` the open
itself requires a privileged caller (`ErrPrivilegeRequired`). Its public-key
export does not export private-key material. This supports the API-level
non-exportable signing boundary; it does not prove hardware protection,
historical non-export, or resistance to a compromised administrator/provider.

CNG v0.5.1 exports the public key once in `Open` and `Create`, and refuses a
native read whose reported size exceeds a fixed limit before allocating (64
bytes for a signature, 72 bytes for the public key, 128 KiB for the DACL-only
descriptor). An oversized descriptor is a failed read, never
`ErrPolicyMismatch`.

A directly loaded signer is caller-owned. A Windows signer is safe for
concurrent use: Sign calls may overlap each other and Close, Close waits for
Sign calls in progress, and Close is idempotent. Stop and drain signing users
(for example in-flight TLS handshakes) before closing. Closing a handle never
removes a key.

`windowscng.ErrKeyNotFound` means the native open reported the key as **not
found or not accessible** (`NTE_NOT_FOUND`/`NTE_BAD_KEYSET`). The software KSP
has been observed to report `NTE_BAD_KEYSET` to callers the DACL does not grant,
so the error is not proof of absence and must never by itself trigger a
`Create`, reset, regeneration or overwrite of an identity key.

### Creating keys (consumer side)

`windowscng.Create(name, policy)` creates a new persisted machine-scoped key
with the policy's DACL, set before finalization and read back after it. It
never opens, adopts, modifies or deletes an existing key: a name already
persisted returns `ErrKeyExists`. If a later step fails, the key created by the
call is deleted through the same handle, never by name; if that delete cannot
be confirmed, the error also wraps `ErrCleanupFailed` and the new key may
persist. `Create` requires SYSTEM or an elevated Administrator whatever the
policy.

**Residual risk:** `Create` does not reserve the name. Two overlapping creators
of the same name were observed (by CNG) to both succeed with different keys.
The caller must serialize every lifecycle operation on a name (create, delete,
policy change, recovery) across processes, record the key's
`SubjectPublicKeyInfo` and compare it at every later open; a mismatch is a
conflict to report, never a key to adopt or delete by name. The rollback is not
transactional either: a finalized key is visible to other processes before it
is deleted, and termination between creation and rollback can leave it in
place. The tests of this module only inject the final error of `Create`, in
the shapes CNG returns, and check the message, the flow and the removal of the
reserved output file; CNG tests its rollback in its own repository. The absence
of `ErrCleanupFailed` is therefore not an absolute guarantee that no key
persists.

Recording the `SubjectPublicKeyInfo`, deleting with
`windowscng.Delete(name, policy, expectedSPKI)`, cross-process locking,
recovery and policy changes with `windowscng.Apply` are lifecycle work outside
this module. `Open` performs no implicit repair.

### Legacy keys and configurations

Keys created by the former `LoadOrCreate` requested the `PolicyServiceSigner`
DACL (`D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGX;;;LS)`). They open with
`cng:<name>?policy=service-signer` only if their persisted DACL is in one of the
forms CNG v0.5.x accepts: the tolerant legacy check is gone. A DACL that is not
protected, carries allow entries for other principals or entries of other types
(deny, callback), inheritance flags on the required entries, or masks outside
the accepted ones is rejected with `ErrPolicyMismatch` (see the CNG
documentation for the exact masks). Configurations carrying `cng:<name>?` are
rejected and must be migrated explicitly, as the README describes: rewrite the
reference with the policy the key holds, verify that it opens, and never
recreate the key to make it load. The policy selects the DACL check; it does not
replace a comparison with the expected public key or certificate.

CertMatchesSigner closes the signer it opens, including on certificate errors,
and returns cleanup failures. It validates the name and the policy and rejects
a nil config. It checks public-key equality only, without certificate-chain
validation.

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

CNG v0.5.1 defines three exact DACL states, selected by the policy:

| Policy | DACL requested | Principals |
| --- | --- | --- |
| `service-signer` | `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGX;;;LS)` | SYSTEM, Administrators, LOCAL SERVICE (read/execute) |
| `privileged-only` | `D:P(A;;GA;;;SY)(A;;GA;;;BA)` | SYSTEM, Administrators |
| `service` | `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGX;;;<service-SID>)` | SYSTEM, Administrators, one service SID |

`Open` accepts a key only if its DACL is protected, holds exactly the expected
explicit allow entries, and their masks are among those the Microsoft Software
KSP was observed to persist; anything else is `ErrPolicyMismatch`. This is a
check of the DACL the provider persisted, not a certification of every
effective Windows access path (ownership, privileges, a compromised
administrator or provider). LOCAL SERVICE is a shared Windows account: prefer
the `service` policy to grant a key to one service only. Deployment ACL review
and behavioral access testing remain caller responsibilities.

## Errors and logging

Enroll returns stage/category diagnostics and does not retain or wrap raw SDK
errors. This avoids disclosing enrollment URLs with token query parameters,
JWT material or arbitrary Controller response bodies through error formatting
or unwrapping. A network error that carries typed evidence keeps its broad
category (see below).

CertMatchesSigner redacts certificate-parsing and signer-close failures the same
way. When it cannot open the key it wraps the `windowscng` error (key name and
HRESULT, no secrets) so callers can still test `errors.Is(err,
windowscng.ErrKeyNotFound)`.

The load-identity example never prints the identity key field and rejects PEM,
file and malformed references, including references without a policy, before
loading. The enrollment example also builds on Linux/non-Windows, where its CNG
and enrollment operations are not supported at runtime; it accepts a JWT file
path, not a raw JWT argument, requires an explicit `-policy`, and persists JSON
to an exclusively created output. Protect JWT files and output directories with
OS access controls. The output contains identity certificates and CNG
references, not CNG key bytes.

The enrollment example maps a `windowscng.Create` failure to a fixed message,
checked in this order:

- `ErrCleanupFailed`: a step after creating the new key failed and the key could
  not be removed; it may still be persisted and needs verification and
  controlled manual cleanup. A possible residue is reported first.
- `ErrKeyExists`: a key with this name already exists and was not opened,
  adopted or modified; choose a new name, or verify the key and remove it
  through a controlled lifecycle operation. Enrollment is not attempted.
- anything else: a generic `diagnostic.Safe` error. As described above, such a
  failure does not prove absolutely that no key was persisted.

None of them carries the native message, key name, token or path, or retains
the native error chain. The example never deletes the key it created. Every
failure after a successful `Create` is joined with fixed operator signals,
added by one deferred step that runs last, so it also covers a failure of the
deferred output close:

- `errKeyPersisted`, on every failure after `Create`: the key remains
  persisted and a retry with the same name stops because the key already
  exists and does not resume. It is neutral on purpose: when `Enroll` fails the
  example cannot tell whether the OTT was consumed.
- `errEnrolledPreserve`, also on every failure after a completed enrollment
  (incomplete output, certificate check error, mismatch, output close): the OTT
  is consumed; preserve the key and the configuration output, do not repeat the
  enrollment, and recover or verify the configuration. The output is kept.

Neither signal advises removing the key: after a consumed OTT that could
prevent recovering the identity. CNG
makes native causes reachable with `errors.As` (`NCryptError`) and `errors.Is`
(`syscall.Errno`); this module does not query them.

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

BuildFlags is an SDK integration primitive: direct callers receive flags carrying
the JWT/claims and bypass Enroll's safe error boundary. Do not log those flags or
raw SDK errors. The wrapper does not reconfigure the SDK's global logging or
claim that all upstream diagnostics are sanitized.

The separately reported OpenZiti Controller v2.0.3 service-session JWT logging
issue is upstream context. This module neither fixes nor reproduces that issue.

## Validation boundaries

Default tests check the reference grammar for all three policies (byte-for-byte
round trips, both URL shapes, rejection of every non-canonical variant), the
dispatch of every policy form through `identity.LoadKey` to `Open` with the
expected name and policy, engine registration, expected dispatch/platform
errors, token-source handling, error redaction (including the enrollment
example's `ErrCleanupFailed`, `ErrKeyExists` and remaining-key messages, using
synthetic `windowscng` errors), rejection of private-key output, and
configuration serialization/no-overwrite. `TestNoRemovedKeyEntryPointsInModuleSource`
fails if a non-test Go file of the module, examples included, contains
`loadorcreate` or `certreq` in any letter case. The tests use synthetic
identity/token material, never create or delete CNG keys, and need no live
Controller. On Windows, three of them open the software KSP read-only to look up
key names that do not exist: `TestLoadKeyDispatchesToCNG`,
`TestLoadKeyMissingKeyMapped` and the canonical subcase of
`TestReferenceRequiresQueryDelimiter`.

### Continuous integration

`.github/workflows/ci.yml` runs on pull requests and on pushes to `main`. Both
jobs run only when `github.repository_owner == 'keppin-oss'`: in any other copy
of the repository, such as a fork, they are skipped.

- **Windows** (`windows-latest`): build, `go vet` on amd64 and 386, `go vet` with
  the `cng_smoke` and `cng_enroll` tags (compile only, never run), and
  `go test ./... -count=1 -v`.
- **Linux** (`ubuntu-latest`): `gofmt -l .` (the job fails if it lists a file),
  build, vet and test.

The workflow has read-only permissions, actions pinned by SHA and
`persist-credentials: false`. The Windows runner has an elevated token, unlike a
non-elevated development session, and a green job does not tell PASS from SKIP:
check the three KSP tests above by name in the verbose log. The default suite
must not assume a non-elevated process and never creates a CNG key.

### Validation status of v0.3.0

Run before publication on the published tree, with Go 1.26.8 and no fixture or
token variable set:

- Windows 11 (amd64), elevated token: `go test ./... -count=1 -v`, with no test
  skipped, including the three tests that open the software KSP read-only;
  `go build` and `go vet` on windows/amd64, windows/386 and linux/amd64, and
  `go vet` with the `cng_smoke` and `cng_enroll` tags (compilation only).
- Linux (Ubuntu on WSL 2, amd64): the steps of the CI `linux` job (`gofmt -l .`,
  build, vet, `go vet` with both tags, `go test ./... -count=1 -v`), with no
  test skipped.

Not run: the tagged fixture tests (`cng_smoke`, `cng_enroll`) against real keys
and a live Controller, race tests, other Windows builds or key storage
providers, and a caller whose token holds a service SID. The behavior of
`keppin-oss/cng` v0.5.1 relied upon here comes from its documentation and its
own validation.

A successful sign/verify test establishes that the tested signature verifies
against the returned public key. A type assertion rejecting *ecdsa.PrivateKey
only establishes the returned Go type. Neither proves that private material was
never copied elsewhere. Absence of .pem/.key files is not automatically measured.
Token reuse/consumption, actual ACL behavior and complete TLS SDK operation
require separate controlled integration validation.

### Tagged fixture tests

Tagged tests **never create or delete persisted keys**: deleting a key needs
its recorded `SubjectPublicKeyInfo` and belongs to the lifecycle owner, and a
test that created keys would have to own that lifecycle. They own only the
handles they open; cleanup errors fail.

The operator should provision a fresh test-only key with `windowscng.Create` in
a protected environment, with a unique name beginning with the required
`OpenZitiCNG.Test.` prefix, for example `OpenZitiCNG.Test.<random-guid>`, and
record its policy and `SubjectPublicKeyInfo`. Both tagged tests fail if a
configured `CNG_TEST_KEY_NAME` is outside this namespace, or if
`CNG_TEST_KEY_POLICY` (and `CNG_TEST_KEY_SERVICE` for the service policy) is
missing or invalid: there is no default policy. Keep ownership records and
perform any persisted-key cleanup outside these tests. Never use production
keys.

```powershell
# Choose a unique name and its policy, then provision it separately with
# keppin-oss/cng v0.5.1 (windowscng.Create).
$env:CNG_TEST_KEY_NAME = "OpenZitiCNG.Test." + [guid]::NewGuid().ToString("N")
$env:CNG_TEST_KEY_POLICY = "service-signer"
# After provisioning:
go test -tags cng_smoke ./cngengine -run TestIdentityLoadKeySignVerify -count=1 -v
# Live enrollment additionally requires a disposable identity and fresh OTT file:
$env:ZITI_OTT_JWT = "C:\secure\test-identity.jwt"
go test -tags cng_enroll ./enrollcng -run TestLiveOttEnrollmentWithCNGKey -count=1 -v
```

Only absent explicit fixture/token configuration skips these tests. Once configured,
key-open/security-validation, signing, enrollment, verification and cleanup
failures fail the test. Opening a provisioned fixture is governed by its DACL
and, for `privileged-only`, requires a privileged caller; tests do not infer
administrator absence from an arbitrary provider failure. The live test
consumes an OTT token and does not save its disposable configuration.

Compile tags without running live tests using `go vet -tags cng_smoke ./...` and
`go vet -tags cng_enroll ./...`, as CI does. Ordinary tests do not exercise these
tagged paths.
