// Package enrollcng wires Keppin-OSS CNG machine keys into OpenZiti's native OTT
// enrollment flow.
//
// It reuses the OpenZiti SDK's exported `enroll.Enroll` entry point unchanged.
// The only responsibility of this package is to hand OpenZiti the CNG key
// reference (never a PEM/file path and never an in-memory private key) and to
// offer a separate certificate public-key comparison helper.
package enrollcng

import (
	"crypto"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"github.com/keppin-oss/openziti-cng/internal/diagnostic"
	"github.com/keppin-oss/openziti-cng/internal/keyref"
	"reflect"
	"runtime"

	"github.com/keppin-oss/cng/windowscng"
	"github.com/openziti/identity"
	"github.com/openziti/sdk-golang/v2/ziti"
	"github.com/openziti/sdk-golang/v2/ziti/enroll"
)

// KeyReference returns the OpenZiti key reference for a CNG container name and
// the policy its DACL must hold. It is one of exactly three canonical forms:
//
//	cng:<container-name>?policy=service-signer
//	cng:<container-name>?policy=privileged-only
//	cng:<container-name>?policy=service&service=<service-name>
//
// policy must be windowscng.PolicyServiceSigner, windowscng.PolicyPrivilegedOnly
// or a windowscng.ServicePolicy built by windowscng.NewServicePolicy; anything
// else, including nil, is rejected. There is no default policy. The service
// form persists the service name, never its SID.
func KeyReference(name string, policy windowscng.KeyPolicy) (string, error) {
	p, err := keyref.FromKeyPolicy(policy)
	if err != nil {
		return "", err
	}
	return keyref.Format(name, p)
}

// BuildFlags wires a CNG key reference into OpenZiti's native enrollment flags
// without touching the network. It fails closed on a malformed key name or an
// unsupported policy before any insecure fallback could occur. The returned
// flags carry KeyFile set to the CNG reference, which routes OpenZiti's
// enroll.Enroll into the engine path (identity.LoadKey) instead of generating
// an in-memory PEM key.
func BuildFlags(jwtString string, claims *ziti.EnrollmentClaims, keyName string, policy windowscng.KeyPolicy) (enroll.EnrollmentFlags, error) {
	keyRef, err := KeyReference(keyName, policy)
	if err != nil {
		return enroll.EnrollmentFlags{}, err
	}
	return enroll.EnrollmentFlags{
		Token:     claims,
		JwtString: jwtString,
		KeyFile:   keyRef,
	}, nil
}

// Enroll performs native OpenZiti OTT enrollment using an existing
// machine-scoped, non-exportable CNG key referenced by name, whose DACL must
// hold policy.
//
// It parses the OTT JWT, wires the CNG key reference into the enrollment flags,
// and delegates the whole OTT/CSR/Controller exchange to the OpenZiti SDK's
// enroll.Enroll. It never creates a key: the key must already exist (creating
// it is the caller's job, see the enrollment example). No private key is
// generated, exported, or persisted by this package.
func Enroll(jwtString, keyName string, policy windowscng.KeyPolicy) (*ziti.Config, error) {
	// On Unix a canonical reference can be an actual filename. Do not let the
	// SDK's os.Stat routing substitute a file-backed key for CNG.
	if runtime.GOOS != "windows" {
		return nil, errors.New("enrollcng: CNG enrollment requires Windows")
	}
	keyRef, err := KeyReference(keyName, policy)
	if err != nil {
		return nil, err
	}

	claims, _, err := enroll.ParseToken(jwtString)
	if err != nil {
		return nil, diagnostic.Safe("enrollcng: validate OTT token", err)
	}

	flags := enroll.EnrollmentFlags{
		Token:     claims,
		JwtString: jwtString,
		KeyFile:   keyRef,
	}

	if claims.EnrollmentMethod != "ott" {
		return nil, errors.New("enrollcng: only OTT enrollment is supported")
	}
	// The SDK owns the CSR signer and does not expose it for Close. See docs.
	cfg, err := enroll.Enroll(flags)
	if err != nil {
		return nil, diagnostic.Safe("enrollcng: enroll", err)
	}
	return cfg, nil
}

// openSigner is windowscng.Open. It is a package variable only so in-package
// tests can inject Open failures and fake signers without touching a real KSP
// key; production code never reassigns it.
var openSigner = windowscng.Open

// CertMatchesSigner opens the CNG key under policy and reports whether the leaf
// certificate returned by enrollment carries the same public key as the CNG
// signer. It is a public-key equality check, not certificate trust or CSR
// provenance validation.
func CertMatchesSigner(cfg *ziti.Config, keyName string, policy windowscng.KeyPolicy) (matches bool, resultErr error) {
	if cfg == nil {
		return false, errors.New("enrollcng: missing enrollment configuration")
	}
	if err := keyref.ValidateName(keyName); err != nil {
		return false, err
	}
	p, err := keyref.FromKeyPolicy(policy)
	if err != nil {
		return false, err
	}
	resolved, err := p.KeyPolicy()
	if err != nil {
		return false, err
	}
	signer, err := openSigner(keyName, resolved)
	if err != nil {
		return false, fmt.Errorf("enrollcng: open CNG key %q: %w", keyName, err)
	}
	defer func() {
		if err := signer.Close(); err != nil {
			matches = false
			resultErr = errors.Join(resultErr, diagnostic.Safe("enrollcng: close signer", err))
		}
	}()

	certs, err := identity.LoadCert(cfg.ID.Cert)
	if err != nil {
		return false, diagnostic.Safe("enrollcng: parse enrolled certificate", err)
	}
	if len(certs) == 0 {
		return false, fmt.Errorf("enrollcng: no certificate in enrollment result")
	}

	return publicKeysEqual(certs[0].PublicKey, signer.Public()), nil
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	ea, okA := a.(*ecdsa.PublicKey)
	eb, okB := b.(*ecdsa.PublicKey)
	if okA && okB {
		return ea.Curve == eb.Curve && ea.X.Cmp(eb.X) == 0 && ea.Y.Cmp(eb.Y) == 0
	}
	return reflect.DeepEqual(a, b)
}
