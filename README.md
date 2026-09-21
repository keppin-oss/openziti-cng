# Keppin-OSS OpenZiti-CNG

An OpenZiti identity engine adapter for existing machine-scoped Windows CNG
keys in the Microsoft Software Key Storage Provider.

## Dependencies

- Go 1.26.8
- github.com/keppin-oss/cng **v0.1.2**
- github.com/openziti/identity **v1.0.140**
- github.com/openziti/sdk-golang/v2 **v2.0.0-pre4**

The engine registers on every platform. Key access requires Windows; other
platforms return the CNG platform-not-supported error.

## Activation and API

Consumers must register the engine, including when using enrollment helpers:

```go
import (
    _ "github.com/keppin-oss/openziti-cng/cngengine"
    "github.com/keppin-oss/openziti-cng/enrollcng"
)
```

- `enrollcng.KeyReference(name)` constructs a validated reference.
- `enrollcng.BuildFlags(jwt, claims, name)` wires SDK flags without network access.
  Callers using these flags directly own SDK error handling and diagnostics.
- `enrollcng.Enroll(jwt, name)` validates the token and delegates OTT enrollment.
  It returns safe stage/category errors instead of raw SDK diagnostics.
- `enrollcng.CertMatchesSigner(cfg, name)` compares the leaf certificate public
  key with the CNG signer. It does not verify certificate trust or prove CSR provenance.

## Key reference

Canonical form: `cng:<container-name>?`.

Names follow `[A-Za-z0-9][A-Za-z0-9._-]{0,127}`. Names are exact and are never
trimmed or decoded. Whitespace, slashes, colons, percent escapes, Unicode,
query values, fragments and other ambiguous forms are rejected.

The trailing `?` remains required by the pinned OpenZiti identity Windows
parser. Always construct references using `KeyReference`. An arbitrary direct
call to upstream `identity.LoadKey` can still panic on a missing delimiter.
See [technical details](docs/README.md).

## Examples

- [signverify](examples/signverify/main.go): sign and verify using an existing key.
- [enroll](examples/enroll/main.go): enroll and save a new identity JSON file.
- [loadidentity](examples/loadidentity/main.go): accept only a canonical CNG
  reference, load its signer, and print a status without the identity key field.

Enrollment requires a protected JWT file and a new output file:

```powershell
go run -buildvcs=false ./examples/enroll -jwt C:\secure\identity.jwt -key Keppin.Identity.001 -out C:\secure\identity.json
go run -buildvcs=false ./examples/loadidentity -config C:\secure\identity.json
```

The enrollment example rejects raw JWT command-line arguments and refuses to
overwrite output. It reserves the output before enrollment and checks writing,
syncing and closing. Protect the directory using Windows ACLs: Go mode 0600 is
not a Windows DACL guarantee. Disk/process failures after token consumption can
still require configuration recovery; preserve the key and any partial output.

## Security and ownership

CNG owns private-key custody and signing. The adapter opens existing keys and
does not export or serialize private-key bytes. CNG v0.1.2 checks export policy
before exposing a signer and exports a public-key blob for verification.
This is a software-provider/API property, not hardware isolation or a guarantee
against administrator compromise or the key's history before opening.

CNG requests restrictive provisioning permissions and validates required
principals plus selected disallowed principals. **It does not certify exclusive
principal membership or full Windows effective access.** LOCAL SERVICE is shared
by multiple services. See the precise [DACL boundary](docs/README.md#dacl-boundary).

Close directly owned signers when no signing operation can still use them.
Closing releases handles; it does not delete persisted keys. The pinned SDK
does not close its internally loaded enrollment signer, and the module cannot
retrieve it through the public enrollment API. This residual limitation is
documented; no global signer cache is used.

Protect OTT tokens, identity configuration and logs. The module sanitizes
returned enrollment errors, but does not override the SDK's global logger.
The separately reported Controller v2.0.3 service-session JWT logging issue is
upstream context, outside this module's remediation.

## Validation

```text
go mod verify
go mod tidy -diff
go build -buildvcs=false ./...
go vet -buildvcs=false ./...
go test -buildvcs=false -count=1 ./...
```

Default tests exercise parsing, registration, safe diagnostics, examples and
configuration serialization. They do not perform live enrollment or create/
delete persisted CNG keys. See [tagged fixture tests](docs/README.md#tagged-fixture-tests).
