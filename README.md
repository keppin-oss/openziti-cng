# Keppin-OSS OpenZiti-CNG

A consumer-facing engine adapter that lets OpenZiti identities use a
machine-scoped, non-exportable Windows CNG/KSP private key owned by
[Keppin-OSS CNG](https://github.com/keppin-oss/cng).

## Purpose

OpenZiti identities normally reference a private key as PEM text or a file
path. This module adds a third scheme, `cng:<name>?`, that resolves to an
existing machine-scoped, non-exportable key in the Microsoft Software Key
Storage Provider (CNG/KSP).

**Core guarantee:** the permanent private key stays CNG/KSP-backed and
non-exportable. It is never exported, copied, or persisted as PEM, and it never
leaves the CNG/KSP provider. This module only adapts OpenZiti's identity engine
interface to Keppin-OSS CNG; it does not reimplement OpenZiti's OTT/CSR/
Controller protocol.

## Requirements

- **OS**: Windows only. The `cng` engine registers on every platform so code
  compiles everywhere, but key access requires Windows CNG/KSP and returns a
  platform-unsupported error elsewhere.
- **Privilege**: creating/deleting a machine-scoped key requires an elevated
  (Administrator) process. Opening/signing an existing key is governed by the
  key's DACL.
- **Go**: `1.26.5` (see `go.mod`).

### Dependencies (resolved)

| Module | Version | Role |
| --- | --- | --- |
| `github.com/openziti/identity` | `v1.0.140` | engine registry + `identity.LoadKey` |
| `github.com/openziti/sdk-golang/v2` | `v2.0.0-pre4` | native `enroll.Enroll` entry point |
| `github.com/keppin-oss/cng` | `v0.1.1` | `windowscng` CNG/KSP mechanics |

## Install / import

Blank-import the engine package to register it (the only activation step):

```go
import _ "github.com/keppin-oss/openziti-cng/cngengine"
```

For native OTT enrollment, import the helper normally:

```go
import "github.com/keppin-oss/openziti-cng/enrollcng"
```

No configuration or further setup is required.

## Key reference

Canonical form:

```text
cng:<container-name>?
```

- `cng` is the engine id (the URL scheme).
- `<container-name>` is the exact CNG container/key name; it carries only the
  container identity, never key bytes.
- The trailing `?` is a compatibility workaround required by
  `github.com/openziti/identity v1.0.140` on Windows (see
  [docs/README.md](docs/README.md)). Use `enrollcng.KeyReference` or
  `enrollcng.Enroll` to construct it; do not re-derive it by hand.

Container names must not be empty or contain `?` or `:` (`KeyReference`
rejects both).

## Packages / API

### `cngengine`

- `EngineId` (`"cng"`) — engine id and reference scheme.
- `init()` — registers the engine via `engines.RegisterEngine`.
- `LoadKey(*url.URL) (crypto.PrivateKey, error)` — opens the referenced key with
  `windowscng.Open` and returns the `windowscng.Signer` (a `crypto.Signer`)
  directly. The returned key also satisfies `interface{ Close() error }`.

### `enrollcng`

- `KeyReference(name) (string, error)` — builds `cng:<name>?`.
- `BuildFlags(jwt, claims, name) (enroll.EnrollmentFlags, error)` — wires the
  reference into enrollment flags (no network).
- `Enroll(jwt, name) (*ziti.Config, error)` — parses the OTT token with
  `enroll.ParseToken`, then delegates to `enroll.Enroll`.
- `CertMatchesSigner(cfg, name) (bool, error)` — proves the enrolled certificate
  matches the CNG key.

## Examples

| Example | Demonstrates |
| --- | --- |
| [examples/signverify/main.go](examples/signverify/main.go) | load a CNG key via `identity.LoadKey`, sign/verify as `crypto.Signer` |
| [examples/enroll/main.go](examples/enroll/main.go) | native OTT enrollment + `CertMatchesSigner` |
| [examples/loadidentity/main.go](examples/loadidentity/main.go) | re-resolve a `cng:` reference from an identity config |

## Security / boundary

- **Keppin-OSS CNG** owns CNG/KSP mechanics, machine-scoped key custody,
  non-exportability, and the `crypto.Signer` implementation.
- **This module** owns the OpenZiti CNG engine adapter, the CNG key-reference
  syntax, and the integration glue that wires that reference into OpenZiti's
  native enrollment flow.
- **OpenZiti** owns identity orchestration, OTT semantics, CSR, and Controller
  communication.

The private key never leaves the CNG/KSP provider, and no PEM private key is
persisted. Callers must create keys with Keppin-OSS CNG (for example
`windowscng.LoadOrCreate`), use a dedicated key name, run elevated only for
create/delete, and call `Close` on handles they no longer need.

## Further reading

See [docs/README.md](docs/README.md) for architecture, dispatch path, key
lifecycle, security details, compatibility constraints, validation, and
troubleshooting.
