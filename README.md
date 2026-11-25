# Keppin-OSS OpenZiti-CNG

A consumer-facing engine adapter that lets OpenZiti identities use a
machine-scoped, non-exportable Windows CNG/KSP private key owned by
[`keppin-oss/cng`](https://github.com/keppin-oss/cng) (package `windowscng`).

This document is the consumer contract. It is ordered from "what can I do with
it" to "how do I validate and debug it". Implementation internals appear only
where they are the documented contract (registration, reference syntax, and the
version-specific parser constraints). The detailed technical reference is
[`docs/README.md`](docs/README.md).

---

## 1. Purpose

OpenZiti identities normally reference a private key as PEM text or a PEM file
path. This module adds a third key reference scheme,
`cng:<name>?policy=<policy>`, that resolves to an existing machine-scoped,
non-exportable key in the Microsoft Software Key Storage Provider (CNG/KSP),
whose DACL must hold exactly the named access policy.

The integration path is the smallest possible:

```text
OpenZiti identity key reference
        v
identity.LoadKey(...)
        v
engines.Engine  ("cng")
        v
keppin-oss/cng  (windowscng.Open, with the reference's policy)
        v
Windows CNG/KSP non-exportable key
        v
crypto.Signer
        v
sign + verify
```

No private key is exported, copied, or persisted as PEM by this module. The
private key is used through the Microsoft Software Key Storage Provider.

## 2. Non-goals / boundary

- **`keppin-oss/cng`** owns Windows CNG/KSP mechanics, machine-scoped key custody,
  non-exportability, the key DACL and its exact verification, and the
  `crypto.Signer` implementation.
- **`keppin-oss/openziti-cng`** (this module) owns only the OpenZiti engine adapter
  and the stable key-reference syntax, including the policy it carries.
- **OpenZiti** continues to own identity orchestration, OTT semantics, CSR, and
  controller communication. None of that is reimplemented here.

This module deliberately does **not** implement: a second crypto provider or
key-store, X.509/certificate-store or trust-store behavior, OTT JWT parsing,
Controller HTTP, CSR generation, certificate issuance, or CNG key
provisioning, deletion or ACL policy management. The library never creates a
key. Enrollment is delegated unchanged to the OpenZiti SDK.

## 3. Requirements / compatibility

- **OS**: Windows only. The `cng` engine registers on every platform (so tests
  and tooling can compile), but the underlying key access requires the Windows
  CNG/KSP and returns a platform-unsupported error on non-Windows.
  `enrollcng.Enroll` refuses non-Windows execution before calling the SDK. The
  `examples/enroll` command also builds on Linux/non-Windows, but its CNG and
  enrollment operations are not supported at runtime outside Windows.
- **Privilege**: key **creation** (and deletion, outside this module) requires
  SYSTEM or an elevated Administrator, whatever the policy. Opening an existing
  key is governed by the key's DACL; with `privileged-only` the open itself
  also requires a privileged caller (`windowscng.ErrPrivilegeRequired`).
- **Go**: `go 1.26.8` (see `go.mod`).

### Direct dependencies (resolved)

| Module | Version | Role |
| --- | --- | --- |
| `github.com/openziti/identity` | `v1.0.140` | engine registry + `identity.LoadKey` |
| `github.com/openziti/sdk-golang/v2` | `v2.0.0-pre4` | native `enroll.Enroll` entry point |
| `github.com/keppin-oss/cng` | `v0.5.1` | `windowscng` CNG/KSP mechanics (`Open`, `Create`, policies) |

All dependencies are resolved as regular, published module versions: there is
**no `replace` directive** and no sibling checkout is needed. `go.sum` pins the
checksums.

This module is published at `github.com/keppin-oss/openziti-cng`. This
document describes v0.3.0.

## 4. Installation / import

The module registers its engine in a package-level `init()` call to
`engines.RegisterEngine`. To activate it in a consuming binary, blank-import the
engine package:

```go
import _ "github.com/keppin-oss/openziti-cng/cngengine"
```

For native OTT enrollment, import the enrollment helper normally (keep the blank
import of `cngengine` as well; registration is a process-wide step):

```go
import "github.com/keppin-oss/openziti-cng/enrollcng"
```

There is no configuration and no other setup. The blank import is the only
activation step.

## 5. Quick Start

The shortest correct path, using the module's actual public API:

```go
import (
    "github.com/openziti/identity"

    "github.com/keppin-oss/cng/windowscng"
    "github.com/keppin-oss/openziti-cng/enrollcng"

    _ "github.com/keppin-oss/openziti-cng/cngengine" // activate engine
)

// 0. Choose the key's access policy explicitly: there is no default.
policy := windowscng.PolicyServiceSigner

// 1. Create a NEW dedicated machine-scoped, non-exportable CNG key. Creating is
//    the caller's job, never this module's: Create never opens or adopts an
//    existing key (windowscng.ErrKeyExists), and the caller serializes every
//    lifecycle operation on the name across processes. Creation requires
//    SYSTEM or an elevated Administrator. The name must match the CNG name
//    grammar (section 7).
signer, err := windowscng.Create("keppin-identity-001", policy)
if err != nil {
    // If errors.Is(err, windowscng.ErrCleanupFailed), the new key may still
    // persist: inspect it before retrying (section 8).
    return err
}
if err := signer.Close(); err != nil { // release the create handle
    return err
}

// 2. Load that key through OpenZiti's identity path using the cng: reference.
//    "cng:keppin-identity-001?policy=service-signer"
ref, err := enrollcng.KeyReference("keppin-identity-001", policy)
if err != nil {
    return err
}
key, err := identity.LoadKey(ref)
if err != nil {
    return err
}

// 3. Register cleanup immediately after acquisition, before any fallible
//    operation. (Production callers may surface the close error explicitly.)
if closer, ok := key.(interface{ Close() error }); ok {
    defer closer.Close()
}

// 4. Use it as a crypto.Signer - private material never leaves CNG/KSP.
sig, err := key.(crypto.Signer).Sign(rand.Reader, digest, nil)

// 5. (Optional, Windows + OTT only) Enroll an identity through native
//    OpenZiti OTT, CNG-backed. Enroll only opens the existing key.
cfg, err := enrollcng.Enroll(jwtString, "keppin-identity-001", policy)

// 6. Receive/use the enrolled identity configuration. cfg.ID.Key remains the
//    cng: reference with its policy; the SDK owns config persistence/loading.
```

The conceptual sequence is:

```text
import/register CNG engine
        v
create a dedicated CNG-backed key (caller, create-only, serialized)
        v
use cng:<name>?policy=<policy> reference
        v
invoke supported OpenZiti/native enrollment integration
        v
receive/use enrolled identity configuration
```

Complete, compilable versions of these flows are under [`examples/`](#11-examples).

## 6. Public API / supported entry points

### `cngengine` - engine registration and key loading

| Symbol | Role |
| --- | --- |
| `EngineId` (`const`, `"cng"`) | the engine identifier and reference scheme |
| `init()` | registers the engine globally with `engines.RegisterEngine` |

`cngengine` implements OpenZiti's `engines.Engine` interface:

```go
type Engine interface {
    Id() string
    LoadKey(key *url.URL) (crypto.PrivateKey, error)
}
```

`LoadKey` validates the reference, opens the referenced container with
`windowscng.Open(name, policy)` under the policy the reference names, and
returns the `windowscng.Signer` (a `crypto.Signer`) directly - no wrapping, no
copying. It never creates, modifies or deletes a key: a missing, inaccessible
or mismatching key fails.

### `enrollcng` - native OTT enrollment

Every function takes the key's policy as a `windowscng.KeyPolicy`:
`windowscng.PolicyServiceSigner`, `windowscng.PolicyPrivilegedOnly`, or a
`windowscng.ServicePolicy` from `windowscng.NewServicePolicy`. Anything else,
including `nil`, is rejected before any key is touched.

| Symbol | Role |
| --- | --- |
| `KeyReference(name, policy) (string, error)` | validate name and policy and build the canonical reference (section 7) |
| `BuildFlags(jwt, claims, name, policy) (enroll.EnrollmentFlags, error)` | wire the reference into enrollment flags (no network) |
| `Enroll(jwt, name, policy) (*ziti.Config, error)` | native OTT enrollment via SDK `enroll.Enroll` (Windows only, `ott` method only); the key must already exist |
| `CertMatchesSigner(cfg, name, policy) (bool, error)` | open the key under `policy` and report whether the enrolled certificate carries the same public key as the CNG signer |

`CertMatchesSigner` is a **public-key equality check only**. It does not validate
the certificate chain or trust, and it does **not** prove that the CSR was
generated or signed by the CNG key (CSR provenance).

`BuildFlags` is an SDK integration primitive: the returned flags carry the JWT and
claims, and direct callers bypass `Enroll`'s safe error boundary and its
Windows-only check. Do not log those flags or raw SDK errors.

### OpenZiti extension point (verified against `v1.0.140`)

OpenZiti identity exposes an engine registry in
`github.com/openziti/identity/engines`:

```go
func RegisterEngine(e Engine)      // global, package-level registration
func GetEngine(id string) (Engine, bool)
```

Dispatch path for a key reference:

```text
identity.LoadKey(keyAddr)
    -> parseAddr(keyAddr)
    -> switch scheme:
           "pem"  -> certtools.LoadPrivateKey
           "file"/"" -> certtools.GetKey(nil, path, "")
           default    -> certtools.GetKey(url, "", "")
                             -> LoadEngineKey(url.Scheme, url)
                             -> engines.GetEngine(scheme).LoadKey(url)
```

The URL **scheme** is the engine id. The `"cng"` engine's `LoadKey` reads the
name and the policy query from the URL, opens the container via
`windowscng.Open(name, policy)` and returns the `windowscng.Signer`.

## 7. Key reference syntax

There are exactly three canonical references, one per policy:

| Reference | `windowscng` policy | Who can use the key |
| --- | --- | --- |
| `cng:<name>?policy=service-signer` | `PolicyServiceSigner` | SYSTEM, Administrators, LOCAL SERVICE (read/execute) |
| `cng:<name>?policy=privileged-only` | `PolicyPrivilegedOnly` | SYSTEM and Administrators only |
| `cng:<name>?policy=service&service=<service-name>` | `NewServicePolicy(<service-name>)` | SYSTEM, Administrators and one Windows service's own SID |

- `cng` is the engine id (the URL scheme).
- `<name>` is the exact CNG container/key name; it carries only the container
  identity, never key bytes.
- The policy selects the DACL that `windowscng.Open` verifies **exactly**. It
  does not replace a comparison with the expected public key or certificate.
- The service form persists the **service name**, never its SID.

Example identity configuration `key` value:

```text
key: cng:keppin-identity-001?policy=service-signer
```

**Names** follow a strict grammar: `[A-Za-z0-9][A-Za-z0-9._-]{0,127}` (1-128
ASCII characters, starting with a letter or digit, then letters, digits, `.`,
`_` or `-`). **Service names** are what `windowscng.NewServicePolicy` accepts:
1-256 ASCII letters, digits, `.`, `_` or `-`, so they never need escaping.
Names are **validated, never normalized**: no trimming, no decoding, no case
folding.

**There is no default policy.** These are rejected and fail closed: a reference
without a policy, including the former `cng:<name>?` form; an unknown policy;
a duplicated, reordered or extra parameter; `service` without `policy=service`
or the reverse; any percent-encoding, `+`, fragment or user info. The parameter
order is fixed, and `enrollcng.KeyReference` writes the canonical string, which
round-trips byte for byte.

The engine does not see the original reference string: it receives the URL
components produced by the OpenZiti identity parser (the Windows `Host` shape or
the opaque `net/url` shape), and applies the same rules to the name and to the
query. The upstream parser has already removed a leading `//` before engine
dispatch, so the engine **cannot distinguish `cng://<name>?...` from the
canonical `cng:<name>?...`**. The complete canonical string is guaranteed where
this module sees it: `enrollcng.KeyReference`, `BuildFlags` and `Enroll` build
it, and the `examples/loadidentity` example validates a configuration's whole
string before dispatch. A caller that passes strings to `identity.LoadKey`
directly must validate them first where strict canonical spelling matters.

## 8. Key lifecycle and ownership

- **The private key is owned by CNG/KSP**, not by this module and not by the
  returned signer. It persists until explicitly deleted by its owner.
- **Opening and creating are separate operations.** This module only opens
  (`windowscng.Open`). Creating a key is the consumer's job, with
  `windowscng.Create`, which never opens, adopts, modifies or deletes an
  existing key: a name already persisted returns `windowscng.ErrKeyExists`.
  `Create` does not reserve the name against a concurrent creator: the caller
  must serialize every lifecycle operation on a name (create, delete, policy
  change, recovery) across processes.
- **`windowscng.Open`/`Create`** return a `windowscng.Signer`, which is a
  `crypto.Signer` **and** `interface{ Close() error }`. `Close` releases the
  underlying CNG provider and key handles; it never deletes the key.
- **`Signer` concurrency**: on Windows a signer is safe for concurrent use.
  `Sign` may run in parallel with other `Sign` calls and with `Close`; `Close`
  waits for signatures in progress and is idempotent. Stop and drain your own
  users (for example in-flight TLS handshakes) before closing.
- **`windowscng.ErrCleanupFailed`**: returned by `Create` (joined with the
  original failure) when a step after creating the new key failed and deleting
  that key through its handle failed too. The newly created key **may still be
  persisted**: inspect it and perform a controlled manual cleanup before
  retrying. The rollback is not transactional, so a generic failure is not
  proof that no key exists either.
- **Deleting** a key is out of scope for this module and belongs to the
  lifecycle owner: `windowscng.Delete(name, policy, expectedSPKI)` needs the
  `SubjectPublicKeyInfo` recorded when the key was created, never one read by
  opening the same name just before deleting it.
- **`identity.LoadKey("cng:<name>?policy=...")`** returns the signer as a
  `crypto.PrivateKey`. Type-assert it to `crypto.Signer` to sign and to
  `interface{ Close() error }` to release handles. It is **not** a
  `*ecdsa.PrivateKey`; there is no in-memory private material.
- **`enrollcng.Enroll`** returns `*ziti.Config` owned by the caller. The config's
  `ID.Key` is the `cng:` reference with its policy; the config is otherwise
  owned and loaded/persisted by the OpenZiti SDK. The SDK's internal CSR signer
  handle is not exposed for `Close` (see [`docs/README.md`](docs/README.md)).
- **After a successful `Create`, every failure leaves the key in place.**
  `examples/enroll` never deletes the key it created; a retry with the same
  name stops with `ErrKeyExists` and does not resume. What to do depends on
  how far the run got:
  - **before the enrollment completed** (closing the setup signer, or
    `Enroll` itself failed): the OTT may or may not have been consumed. Find
    out on the Controller before deciding anything about the key; the command
    does not advise removing it.
  - **after the enrollment completed** (writing the configuration, the
    certificate check, a mismatch, or closing the output): the OTT is consumed
    and the identity is bound to the key. Preserve the key and the output, do
    not repeat the enrollment, and recover or verify the configuration.

Use a dedicated key name that is never a Keppin production key name.

### Migrating configurations from the former `cng:<name>?` form

Identity configurations written with v0.2.x carry `cng:<name>?`, which
is now rejected. Migration is an explicit edit, never automatic, and never
recreates the key:

1. Determine the policy the existing key actually holds. Keys created by the
   former `LoadOrCreate` requested the `service-signer` DACL.
2. Rewrite `id.key` to the canonical reference with that policy, for example
   `cng:<name>?policy=service-signer`.
3. Verify it: `examples/loadidentity -config <file>` (or `identity.LoadKey`)
   must open the key. `windowscng.Open` checks the DACL **exactly**: a legacy
   key whose DACL is not protected, carries extra or non-allow entries,
   inheritance flags on the required entries or unexpected masks no longer
   opens. Do not "fix" such a key by recreating it under the same name;
   replacing an identity key is an explicit lifecycle operation.
4. Optionally confirm the certificate with `enrollcng.CertMatchesSigner`.

## 9. Security guarantees and caller responsibilities

Guaranteed by the module and its boundary:

- the permanent private key remains in Windows CNG/KSP;
- no private-key export by this module (`keppin-oss/cng` checks the export
  policy, the P-256 public key and the exact DACL before any signer is exposed);
- no PEM private-key persistence for SDK convenience;
- no key creation, adoption or deletion by the library: the engine and
  `enrollcng` only open;
- no implicit policy: every open names the policy that the key's DACL must
  match exactly;
- no custom OpenZiti OTT enrollment implementation (the SDK's `enroll.Enroll` is
  reused unchanged);
- errors at identity boundaries use `diagnostic.Safe` (`Enroll` token/SDK
  failures, certificate parsing and signer-close failures in
  `CertMatchesSigner`, and the examples): they report the stage and a broad
  category (`operation failed`, `network failure`, `network timeout`) and
  **do not retain or wrap** the original error, so tokens, URLs, key material or
  Controller responses are not disclosed through formatting or unwrapping. The
  category comes from positive evidence of a network error only (see
  [`docs/README.md`](docs/README.md#errors-and-logging)).
  Exception by design: when `CertMatchesSigner` cannot open the key it wraps the
  `windowscng` error (key name and HRESULT, no secrets) so that
  `errors.Is(err, windowscng.ErrKeyNotFound)` keeps working.

Caller responsibilities:

- create keys with `windowscng.Create` only where creating is intended, and
  serialize every lifecycle operation on a name across processes;
- choose the policy explicitly, and run privileged only where `windowscng`
  requires it (creating, and opening a `privileged-only` key);
- use a dedicated key name; never reuse a Keppin production key name;
- call `Close` on signers/handles you no longer need, after draining their users;
- treat the `cng:` reference as non-secret identity, and protect any OTT JWT as a
  single-use secret (never commit it);
- never treat `ErrKeyNotFound` as proof of absence, and never let it trigger an
  automatic `Create`, reset, regeneration or overwrite;
- keep `keppin-oss/cng` as the single owner of CNG key custody - do not reimplement
  key creation/export elsewhere.

A successful OpenZiti OTT enrollment means only that an OpenZiti identity has
been enrolled. It does **not**, by itself, establish Keppin application
authorization, Installation state, Tenant membership, or licensing.

## 10. Compatibility / known version constraints

### The `?` delimiter (identity `v1.0.140`, Windows)

`identity.parseAddr` (`address_windows.go` in identity `v1.0.140`) unconditionally
indexes the result of splitting the address on `?`:

```go
pathAndArgs := strings.SplitN(u[1], "?", 2)
return &url.URL{ ... Host: ..., RawQuery: pathAndArgs[1] }
```

A reference without `?` therefore panics (`index out of range`) before reaching
any engine. Every canonical reference has a `?`, which introduces the mandatory
policy query; on Windows the text after it reaches the engine as `RawQuery`, on
other platforms `net/url` produces `Opaque` and `RawQuery`. Both shapes carry
the same canonical query. Verified against the currently resolved
`identity v1.0.140` (`TestReferenceRequiresQueryDelimiter` and
`TestLoadKeyDispatchesEveryPolicyForm`).

### SDK `enroll.Enroll` key-reference routing (`v2.0.0-pre4`)

The native `enroll.Enroll` treats `EnrollmentFlags.KeyFile` as an **engine
reference** (forwarded verbatim to `identity.LoadKey`) whenever
`os.Stat(KeyFile)` fails. On Windows a `cng:` reference always fails `os.Stat`,
so it is routed into the CNG engine rather than the PEM-key-generation branch.
On Unix such a string can be a real filename, which is why `enrollcng.Enroll`
rejects non-Windows execution up front. `Enroll` also accepts only the `ott`
enrollment method.

### `keppin-oss/cng` `v0.5.1` semantics relied upon

- Four key functions, each taking the policy as a parameter: `Open`, `Create`,
  `Delete` and `Apply`. This module uses only `Open`; the enrollment example
  uses `Create`. The former `Open(name)`, `LoadOrCreate...`, `*WithPolicy`,
  `*ForService`, `ApplyPolicy`, `ApplyServicePolicy` and `Delete(name)` were
  removed in `v0.5.0` with no deprecation period.
- `Open` verifies the export policy, the P-256 public key and that the DACL is
  **exactly** the requested policy (`ErrPolicyMismatch` otherwise); it never
  creates, modifies or deletes a key. `Open` with `PolicyPrivilegedOnly`
  requires a privileged caller (`ErrPrivilegeRequired`).
- `windowscng.ErrKeyNotFound` means the key was **not found or is not
  accessible** to the caller (`NTE_NOT_FOUND` or `NTE_BAD_KEYSET`); a DACL that
  does not grant the caller can look like an absent key.
- `Create` never adopts an existing key (`ErrKeyExists`); if a later step fails
  it deletes the key it created through the same handle, and wraps
  `ErrCleanupFailed` if that delete fails.
- `v0.5.1` exports the public key once in `Open` and `Create`, and refuses
  native reads whose reported size exceeds a fixed limit (64 bytes for a
  signature, 72 bytes for the public key, 128 KiB for the descriptor).
- The sentinels, `NCryptError` and the `NTE*` codes are declared on every
  platform; outside Windows the functions only report that the platform is not
  supported. This module does not query the native causes, and
  `diagnostic.Safe` does not retain the native error chain.

## 11. Examples

Complete, compilable consumer flows (all use only supported public APIs):

| Example | Demonstrates |
| --- | --- |
| [`examples/signverify`](examples/signverify) | register the engine, load an existing CNG-backed key via `identity.LoadKey` with an explicit `-policy`, sign/verify as `crypto.Signer` with no private material exported |
| [`examples/enroll`](examples/enroll) | (runs on Windows only; builds on all platforms) create a **new** key with `windowscng.Create` under an explicit `-policy`, native OTT enrollment via `enrollcng.Enroll`, exclusive no-overwrite output, then `CertMatchesSigner` |
| [`examples/loadidentity`](examples/loadidentity) | load an enrolled identity configuration, reject PEM/file/non-canonical references (including references without a policy), and re-resolve its `cng:` key reference to a signer |

Each example is `package main` and builds with `go build ./...` on Windows and on
Linux/non-Windows; CNG and enrollment operations are supported at runtime only
on Windows. `-policy` is `service-signer`, `privileged-only` or `service` (with
`-service <name>`); there is no default.

`examples/enroll` requires SYSTEM or an elevated Administrator (it creates the
key), reads the OTT JWT from a protected file (raw JWT arguments are not
accepted) and requires a reachable OpenZiti Controller. Its key errors are:

- **name already in use** (`ErrKeyExists`): a specific, safe message; the
  existing key was not opened, adopted or modified, and enrollment is not
  attempted;
- **new key may still be persisted** (`ErrCleanupFailed`): a specific, safe
  message asking for verification and controlled manual cleanup;
- **any other create failure**: a generic safe message.

If the key was created and a later step fails, the error also says that the
key remains persisted and that a retry with the same name does not resume; if
the enrollment had completed, it also says to preserve the key and the output
and not to repeat the enrollment (section 8). None of these messages advises
removing the key.
See each file's header comment for exact prerequisites.

## 12. Validation / testing

### Automated

```text
go build ./...
go vet ./...
go test ./...
```

Automated tests cover the name and reference grammar for all three policies
(byte-for-byte round trips, both URL shapes, and rejection of missing,
unknown, duplicated, reordered, extra and escaped parameters), the dispatch of
every policy form through `identity.LoadKey` to `Open` with the expected name
and policy, engine registration, missing-key error mapping, the guarantee that
a `cng:` reference is never interpreted as PEM or as a file path, token-source
handling, error redaction (including the enrollment example's `ErrKeyExists`
and `ErrCleanupFailed` messages, using synthetic errors), rejection of
private-key output, configuration serialization/no-overwrite, and a guard that
keeps the removed `LoadOrCreate` entry point and `certreq` out of the module's
Go sources. They use synthetic identity/token material, never create or delete
CNG keys, and do **not** require a live Controller or Administrator
privileges. On Windows, `go test ./...` also runs three tests that open the
software KSP read-only to look up key names that do not exist
(`TestLoadKeyDispatchesToCNG`, `TestLoadKeyMissingKeyMapped` and the canonical
subcase of `TestReferenceRequiresQueryDelimiter`). See
[validation status](docs/README.md#validation-status-of-v030).

The same checks run in GitHub Actions on pull requests and on pushes to
`main`; see [continuous integration](docs/README.md#continuous-integration).

### Tagged fixture tests (manual, operator-provisioned)

The sign/verify and live-enrollment proofs are gated behind the `cng_smoke` and
`cng_enroll` build tags and are **not** run by `go test ./...`. They **never
create or delete persisted keys**: the operator provisions a fresh, test-only key
beforehand (with `windowscng.Create`, in a protected environment) whose name
starts with `OpenZitiCNG.Test.`, and performs any cleanup outside the tests.
Never use production keys. The fixture's policy is required: there is no
default.

```powershell
# Choose a unique fixture name and its policy, then provision it separately
# with keppin-oss/cng (windowscng.Create).
$env:CNG_TEST_KEY_NAME = "OpenZitiCNG.Test." + [guid]::NewGuid().ToString("N")
$env:CNG_TEST_KEY_POLICY = "service-signer"   # or privileged-only, or service
# $env:CNG_TEST_KEY_SERVICE = "MyService"     # only with CNG_TEST_KEY_POLICY=service

# Sign/verify through identity.LoadKey:
go test -tags cng_smoke ./cngengine -run TestIdentityLoadKeySignVerify -count=1 -v

# Live enrollment: additionally a disposable OpenZiti identity and a fresh OTT JWT file.
$env:ZITI_OTT_JWT = "C:\secure\test-identity.jwt"
go test -tags cng_enroll ./enrollcng -run TestLiveOttEnrollmentWithCNGKey -count=1 -v
```

Expected PASS observations: the signature verifies against `signer.Public()` and
`identity.LoadKey` did not return a `*ecdsa.PrivateKey`; native `enroll.Enroll`
completes, `cfg.ID.Key` is the canonical reference of the fixture and its
policy, and `CertMatchesSigner` returns `true`. Only absent
`CNG_TEST_KEY_NAME`/`ZITI_OTT_JWT` skips these tests; a configured name outside
the `OpenZitiCNG.Test.` namespace, or a missing or invalid policy, fails. The
live test consumes the OTT token. See [`docs/README.md`](docs/README.md) for
what these tests do and do not prove.

## 13. Troubleshooting

Work through these in order; source inspection is a last resort.

1. **"engine not supported" / non-Windows error** - confirm you blank-imported
   `cngengine`, and confirm you are on Windows. The engine is a Windows CNG/KSP
   adapter; `Enroll` refuses non-Windows execution.
2. **`index out of range` / panic on a `cng:` reference without `?`** - use a
   canonical reference built by `enrollcng.KeyReference`. This is the identity
   `v1.0.140` constraint documented in
   [Compatibility](#10-compatibility--known-version-constraints).
3. **"CNG reference has no policy" / "expected canonical CNG reference"** - the
   reference is in the former `cng:<name>?` form or not canonical. Migrate it
   explicitly (section 8); never recreate the key to make it load.
4. **name, policy or reference rejected** - the name does not match
   `[A-Za-z0-9][A-Za-z0-9._-]{0,127}`, the service name is not valid for
   `windowscng.NewServicePolicy`, or the reference has another parameter,
   escaping, a fragment or a path. Nothing is trimmed or normalized; fix the
   input.
5. **`windowscng: persisted CNG key not found or not accessible`**
   (`ErrKeyNotFound`) - the exact container name does not exist **or** the
   caller is not granted access by the key's DACL. Check the name and the
   calling account before anything else. Do **not** automatically create,
   recreate or overwrite the key on this error.
6. **`ErrPolicyMismatch`** - the key's DACL is not exactly the policy the
   reference names (or its public key is not P-256). Check that the reference
   names the policy the key was created with. A legacy key may carry a DACL
   that the exact check of cng `v0.5.x` rejects (section 8). Do **not**
   recreate or overwrite it automatically; replacing an identity key is an
   explicit lifecycle operation.
7. **`ErrPrivilegeRequired`** - opening a `privileged-only` key, or creating
   any key, needs SYSTEM or an elevated Administrator.
8. **"a key with this name already exists"** (`examples/enroll`, from
   `windowscng.ErrKeyExists`) - the example never adopts an existing key.
   Choose a new name, or verify the existing key and remove it through a
   controlled lifecycle operation.
9. **"newly created key ... may still be persisted"** (`examples/enroll`, from
   `windowscng.ErrCleanupFailed`) - a step after creating the new key failed and
   the key could not be removed. Verify whether the key exists and perform a
   controlled manual cleanup before retrying.
10. **`... (sensitive details withheld)`** - the error was intentionally
    redacted by `diagnostic.Safe`. Use the stage and category to locate the
    failing step; reproduce in a controlled environment rather than adding raw
    error logging.
11. **enrollment fails** - verify the Controller is reachable, the OTT JWT is
    valid and single-use, the enrollment method is `ott`, and the key exists
    with the policy you pass. Enrollment is delegated to the SDK; it is not a
    local key problem. If `examples/enroll` created the key, it remains; do
    not remove it before you know whether the OTT was consumed (section 8).
