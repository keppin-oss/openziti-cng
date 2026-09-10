package cngengine

import (
	"crypto"
	"net/url"

	"github.com/keppin-oss/cng/windowscng"
	"github.com/openziti/identity/engines"
)

// EngineId is the OpenZiti engine identifier that selects this engine. It is
// also the URL scheme of the corresponding key reference, e.g. "cng:<name>".
const EngineId = "cng"

// engine is the OpenZiti identity engine backed by Keppin-OSS CNG. It is a
// singleton with no mutable state; each LoadKey call opens its own independent
// CNG provider/key handle set.
type engine struct{}

// Id reports the OpenZiti engine identifier.
func (e *engine) Id() string {
	return EngineId
}

// LoadKey resolves an OpenZiti key reference to an existing machine-scoped CNG
// key and returns it as a crypto.PrivateKey.
//
// The returned value is the windowscng.Signer itself (which implements
// crypto.Signer and Close() error). No private key bytes are exported, copied,
// or persisted; the private key never leaves the CNG/KSP provider. The returned
// key also satisfies interface{ Close() error } so callers can release the
// underlying provider and key handles.
func (e *engine) LoadKey(key *url.URL) (crypto.PrivateKey, error) {
	name, err := parseReference(key)
	if err != nil {
		return nil, err
	}

	signer, err := windowscng.Open(name)
	if err != nil {
		return nil, err
	}

	return signer, nil
}

// e is the process-wide engine instance. Registration is package-level and
// global to the process, mirroring how OpenZiti's own engines register.
var e = &engine{}

func init() {
	engines.RegisterEngine(e)
}




