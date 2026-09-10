# OpenZiti-CNG — Technical Reference

This document holds the implementation-oriented material behind
[`openziti-cng`](../README.md). It is ordered from architecture down to
validation and troubleshooting.

## 1. Architecture and ownership boundary

The integration path is the smallest possible:

```text
OpenZiti identity key reference
        ↓
identity.LoadKey(...)
        ↓
engines.Engine  ("cng")
        ↓
Keppin-OSS CNG  (windowscng)
        ↓
Windows CNG/KSP non-exportable key
        ↓
crypto.Signer
        ↓
sign + verify
```

Ownership is deliberately split three ways:

- **Keppin-OSS CNG** owns Windows CNG/KSP mechanics, machine-scoped key
  custody, non-exportability, and the `crypto.Signer` implementation.
- **Keppin-OSS OpenZiti-CNG** (this module) owns the OpenZiti CNG engine
  adapter, the CNG key-reference syntax, and the integration glue that wires
  that reference into OpenZiti's native enrollment flow.
- **OpenZiti** owns identity orchestration, OTT semantics, CSR, and Controller
  communication.

No private key is ever exported, copied, or persisted as PEM. The private key
never leaves the Microsoft Software Key Storage Provider.

This module deliberately does **not** implement: a second crypto provider or
key-store, X.509/certificate-store or trust-store behavior, Controller HTTP,
CSR generation, or certificate issuance. OTT token parsing and the
OTT/CSR/Controller exchange are delegated to the OpenZiti SDK
(`enroll.ParseToken` and `enroll.Enroll`); this module does not reimplement
that protocol.

## 2. OpenZiti engine registration / dispatch

`cngengine` implements OpenZiti's `engines.Engine` interface and registers
itself in a package-level `init()`:

```go
type Engine interface {
    Id() string
    LoadKey(key *url.URL) (crypto.PrivateKey, error)
}
```

```go
const EngineId = "cng"            // engine id and URL scheme

func (e *engine) Id() string      { return EngineId }

func init() {
    engines.RegisterEngine(e)     // global, package-level registration
}
```

The registry (`github.com/openziti/identity/engines`) exposes:

```go
func RegisterEngine(e Engine)      // global, package-level registration
func GetEngine(id string) (Engine, bool)
func ListEngines() []string
```

Dispatch path for a key reference:

```text
identity.LoadKey(keyAddr)
    -> parseAddr(keyAddr)
    -> switch scheme:
           "pem"      -> certtools.LoadPrivateKey
           "file"/""  -> certtools.GetKey(nil, path, "")
           default    -> certtools.GetKey(url, "", "")
                              -> LoadEngineKey(url.Scheme, url)
                              -> engines.GetEngine(scheme).LoadKey(url)
```

The URL **scheme** is the engine id. `LoadEngineKey` returns
`engine '%s' is not supported` when no engine matches that scheme.

## 3. Public API details

### `cngengine`

| Symbol | Role |
| --- | --- |
| `EngineId` (`const`, `"cng"`) | engine identifier and reference scheme |
| `init()` | registers the engine globally with `engines.RegisterEngine` |
| `LoadKey(key *url.URL) (crypto.PrivateKey, error)` | opens the referenced key |

`LoadKey` parses the container name from the URL (`parseReference`), then opens
an **existing** key with `windowscng.Open(name)` and returns the
`windowscng.Signer` directly — no wrapping, no copying. The signer is a
`crypto.Signer` and also satisfies `interface{ Close() error }`.

### `enrollcng`

| Symbol | Role |
| --- | --- |
| `KeyReference(name) (string, error)` | build the `cng:<name>?` reference |
| `BuildFlags(jwt, claims, name) (enroll.EnrollmentFlags, error)` | wire the reference into enrollment flags (no network) |
| `Enroll(jwt, name) (*ziti.Config, error)` | native OTT enrollment |
| `CertMatchesSigner(cfg, name) (bool, error)` | prove the enrolled cert matches the CNG key |

`Enroll` builds the key reference, calls `enroll.ParseToken(jwt)` to parse the
OTT token, wires the reference into `enroll.EnrollmentFlags` (`KeyFile` =
reference), and then delegates to the SDK's `enroll.Enroll`. No private key is
generated, exported, or persisted by this package.

### OTT JWT resolution (`ottjwt.go`)

`loadOTTJWT` resolves an OTT JWT source value that may be either a filesystem
path or the raw JWT string. A value that clearly names a path — it contains a
path separator or carries a `.jwt` extension — is read from disk; a read
failure is surfaced explicitly rather than being silently reinterpreted as a
malformed raw JWT. Any other value is returned verbatim as the raw JWT. This
helper backs the live enrollment proof (see [Validation](#8-validation--testing)).

## 4. Key-reference parsing and lifecycle

Canonical reference: `cng:<container-name>?`

- `cng` is the engine id (the URL scheme).
- `<container-name>` is the exact CNG container/key name; it carries only the
  container identity, never key bytes.
- The trailing `?` is **mandatory on Windows** — see
  [Compatibility](#6-compatibility-identity-v10140-trailing-).

`cngengine.parseReference` extracts the container name from the parsed
`*url.URL`. The exact shape differs by platform:

- On Windows, `identity.parseAddr` (`address_windows.go`) places the container
  name in `url.Host` and any query string in `url.RawQuery`.
- On non-Windows, `identity.parseAddr` (`address.go`) uses `net/url.Parse`,
  which places an opaque reference (including any `?query` suffix) in
  `url.Opaque`.

The engine accepts both shapes (`Host`, then `Opaque`, then `Path`), strips any
`?query` suffix, trims whitespace, and rejects an empty name. It never
falls back to treating the reference as PEM or file material.

`enrollcng.KeyReference` rejects an empty name and any name containing `?` or
`:`, failing closed before an insecure fallback could occur.

Example identity configuration `key` value:

```text
key: cng:keppin-identity-001?
```

Key lifecycle and ownership:

- **The private key is owned by CNG/KSP**, not by this module and not by the
  returned signer. It persists until the caller deletes it (`windowscng.Delete`).
- **`windowscng.LoadOrCreate`/`Open`** return a `windowscng.Signer`, which is a
  `crypto.Signer` **and** `interface{ Close() error }`. `Close` releases the
  underlying CNG provider and key handles.
- **`identity.LoadKey("cng:<name>?")`** returns the signer as a
  `crypto.PrivateKey`. Type-assert it to `crypto.Signer` to sign and to
  `interface{ Close() error }` to release handles. It is **not** a
  `*ecdsa.PrivateKey`; there is no in-memory private material.
- **`enrollcng.Enroll`** returns `*ziti.Config` owned by the caller. The
  config's `ID.Key` is the `cng:` reference; the config is otherwise owned and
  loaded/persisted by the OpenZiti SDK.

Key creation is **not** part of this module's API. Create keys with
Keppin-OSS CNG (`windowscng.LoadOrCreate`) or through Keppin itself, using a
dedicated name that is never a Keppin production key name.

## 5. Security guarantees and caller responsibilities

Guaranteed by the module and its boundary:

- the permanent private key remains in Windows CNG/KSP;
- no private-key export (export policy is asserted before any signer is
  exposed);
- no PEM private-key persistence for SDK convenience;
- no custom OpenZiti OTT enrollment implementation (the SDK's `enroll.ParseToken`
  and `enroll.Enroll` are reused unchanged);
- the key is machine-scoped with a least-privilege DACL (SYSTEM,
  Administrators, LOCAL SERVICE only — enforced by Keppin-OSS CNG).

Caller responsibilities:

- run elevated only when creating/deleting a machine-scoped key (opening and
  signing an existing key are governed by the DACL);
- use a dedicated key name; never reuse a Keppin production key name;
- call `Close` on signers/handles you no longer need;
- treat the `cng:` reference as non-secret identity, and protect any OTT JWT as
  a single-use secret (never commit it);
- keep Keppin-OSS CNG as the single owner of CNG key custody — do not
  reimplement key creation/export elsewhere.

A successful OpenZiti OTT enrollment means only that an OpenZiti identity has
been enrolled. It does **not**, by itself, establish Keppin application
authorization, Installation state, Tenant membership, or licensing.

## 6. Compatibility: identity v1.0.140 trailing `?`

`identity.parseAddr` (`address_windows.go` in identity `v1.0.140`)
unconditionally indexes the result of splitting the address on `?`:

```go
pathAndArgs := strings.SplitN(u[1], "?", 2)
return &url.URL{ ... RawQuery: pathAndArgs[1] }
```

A reference without `?` therefore panics (`index out of range`) before reaching
any engine. The trailing `?` is a **version-specific compatibility workaround
for `github.com/openziti/identity v1.0.140`**, not an eternal semantic of this
module. On non-Windows the `?` is harmless. Any query text after `?` is ignored
by this engine.

`enrollcng.KeyReference` and `enrollcng.Enroll` own the construction of this
reference. Do not re-derive it in consumer code; call the helper.

Verified against the currently resolved `identity v1.0.140`
(`address_windows.go`; confirmed by `TestReferenceRequiresQueryDelimiter`).

## 7. Compatibility: sdk-golang/v2 v2.0.0-pre4 enrollment routing

Native `enroll.Enroll` (`v2.0.0-pre4`) handles a non-empty `KeyFile` by calling
`os.Stat(KeyFile)`:

```go
if enFlags.Token.EnrollmentMethod != "updb" {
    if strings.TrimSpace(enFlags.KeyFile) != "" {
        stat, err := os.Stat(enFlags.KeyFile)
        if stat != nil && !os.IsNotExist(err) {
            // existing file -> cfg.ID.Key = "file://" + absPath
        } else {
            // not a file -> cfg.ID.Key = enFlags.KeyFile  (engine reference)
        }
    } else {
        // generate an in-memory PEM key
    }
}
```

When `os.Stat` does not resolve to an existing file, `KeyFile` is forwarded
verbatim as `cfg.ID.Key`, which `identity.LoadKey` later resolves through the
engine registry. A `cng:<name>?` value always fails `os.Stat` (it contains `:`
and `?`), so it is routed into the CNG engine rather than the
PEM-key-generation branch. `enrollOTT` then calls `identity.LoadKey(cfg.ID.Key)`
and uses the returned signer to produce the CSR, so the private key stays
CNG-backed throughout.

## 8. Validation / testing

### Automated

```text
go build ./...
go vet ./...
go test ./...
```

Automated tests cover reference parsing/rejection, engine registration and
dispatch, missing-key error mapping, OTT JWT source resolution, and the
guarantee that a `cng:` reference is never interpreted as PEM or as a file
path. They do **not** require a live Controller or Administrator privileges.

### Windows integration proof (manual Administrator run)

The sign/verify path through `identity.LoadKey` requires a machine-scoped CNG
key, which needs an elevated process. It is gated behind the `cng_smoke` build
tag and is **not** run by `go test ./...`.

Run from an **Administrator** PowerShell prompt:

```powershell
go test -tags cng_smoke ./cngengine/ -run TestIdentityLoadKeySignVerify -v
```

Expected observation:

```text
=== RUN   TestIdentityLoadKeySignVerify
--- PASS: TestIdentityLoadKeySignVerify
PASS
```

If the process is not elevated, the test reports
`NOT EXECUTED — requires manual Administrator run` and skips (the implementation
is never weakened to satisfy the non-elevated environment).

The test creates key `Keppin.Test.OpenZiti.CNG.v1`, signs a SHA-256 digest
through the CNG-backed `crypto.Signer`, verifies it against `signer.Public()`,
asserts no materialized `*ecdsa.PrivateKey` was returned, and deletes the key.

## 9. Live Controller proof (manual Administrator + Controller run)

The decisive proof requires a reachable OpenZiti Controller and a single-use OTT
JWT, plus elevation for the machine-scoped key. It is gated behind the
`cng_enroll` build tag and is **not** run by `go test ./...`.

From an **Administrator** PowerShell prompt:

```powershell
# 1. Create a dedicated identity and export its single-use OTT JWT
#    (OpenZiti v2 CLI: the identity-type positional argument was removed):
ziti edge create identity "keppin-oss-cng-test" -o "C:\tmp\keppin-oss-cng-test.jwt"

# 2. Run the live enrollment proof (ZITI_OTT_JWT may be a path or the raw JWT):
$env:ZITI_OTT_JWT = "C:\tmp\keppin-oss-cng-test.jwt"
$env:CNG_KEY_NAME = "Keppin.Test.OpenZiti.CNG.v1"
go test -tags cng_enroll ./enrollcng/ -run TestLiveOttEnrollmentWithCNGKey -v

# 3. Clean up:
ziti edge delete identity "keppin-oss-cng-test"
```

Expected PASS observations: native `enroll.Enroll` completes, `cfg.ID.Key`
remains `cng:Keppin.Test.OpenZiti.CNG.v1?`, `CertMatchesSigner` returns `true`,
and no `*.pem`/`*.key` file is created. Verify the OTT token was consumed by
re-running the same JWT (it must now fail) or by listing the enrolled identity.

The test skips when `ZITI_OTT_JWT` is missing, and skips as requiring the
Administrator/manual environment when the machine CNG key cannot be
created/opened. Once those prerequisites are present, a native OTT enrollment
failure — including an unreachable Controller or an enrollment error — is a
test failure, not a skip.

## 10. Troubleshooting

Work through these in order; source inspection is a last resort.

1. **"engine not supported" / non-Windows error** — confirm you blank-imported
   `cngengine`, and confirm you are on Windows. The engine is a Windows CNG/KSP
   adapter.
2. **`index out of range` / panic on a `cng:` reference without `?`** — use the
   canonical `cng:<name>?` form (or `enrollcng.KeyReference`). This is the
   identity `v1.0.140` workaround documented in
   [Compatibility](#6-compatibility-identity-v10140-trailing-).
3. **`windowscng: persisted CNG key not found`** — the exact container name does
   not exist yet. Create it with `windowscng.LoadOrCreate` in an elevated
   process.
4. **security validation / DACL / export-policy failure** — the existing key was
   not created with the Keppin-OSS CNG least-privilege settings. Recreate it
   with Keppin-OSS CNG rather than a generic tool.
5. **enrollment fails** — verify the Controller is reachable, the OTT JWT is
   valid and single-use, and the key exists. Enrollment is delegated to the
   SDK; it is not a local key problem.
