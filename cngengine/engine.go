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
// The reference names the container and the policy its DACL must hold (see
// the internal/keyref grammar). The key is opened with windowscng.Open under
// that policy, which never creates, modifies or deletes a key. There is no
// default policy.
//
// The returned value is the windowscng.Signer itself (which implements
// crypto.Signer and Close() error). No private key bytes are exported, copied,
// or persisted; the private key never leaves the CNG/KSP provider. The returned
// key also satisfies interface{ Close() error } so callers can release the
// underlying provider and key handles.
func (e *engine) LoadKey(key *url.URL) (crypto.PrivateKey, error) {
	ref, err := parseReference(key)
	if err != nil {
		return nil, err
	}
	policy, err := ref.Policy.KeyPolicy()
	if err != nil {
		return nil, err
	}

	signer, err := openSigner(ref.Name, policy)
	if err != nil {
		return nil, err
	}

	return signer, nil
}

// openSigner is windowscng.Open. It is a package variable only so in-package
// tests can inject Open failures and fake signers without touching a real KSP
// key; production code never reassigns it.
var openSigner = windowscng.Open

// e is the process-wide engine instance. Registration is package-level and
// global to the process, mirroring how OpenZiti's own engines register.
var e = &engine{}

func init() {
	engines.RegisterEngine(e)
}
