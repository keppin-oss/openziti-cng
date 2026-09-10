// Package enrollcng wires Keppin-OSS CNG machine keys into OpenZiti's native OTT
// enrollment flow.
//
// It reuses the OpenZiti SDK's exported `enroll.Enroll` entry point unchanged.
// The only responsibility of this package is to hand OpenZiti the CNG key
// reference (never a PEM/file path and never an in-memory private key) and to
// verify, after enrollment, that the returned certificate matches the CNG key.
package enrollcng

import (
	"crypto"
	"crypto/ecdsa"
	"fmt"
	"reflect"
	"strings"

	"github.com/keppin-oss/cng/windowscng"
	"github.com/openziti/identity"
	"github.com/openziti/sdk-golang/v2/ziti"
	"github.com/openziti/sdk-golang/v2/ziti/enroll"
)

// KeyReference returns the OpenZiti key reference for a CNG container name.
//
// The reference carries only the container identity and uses the syntax
// validated by OZCNG-001:
//
//	cng:<container-name>?
//
// The trailing '?' is an OpenZiti identity v1.0.140 Windows parseAddr
// compatibility workaround, not a desired permanent semantic.
func KeyReference(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("enrollcng: CNG container name is empty")
	}
	if strings.ContainsAny(name, "?:") {
		return "", fmt.Errorf("enrollcng: CNG container name must not contain '?' or ':'")
	}
	return "cng:" + name + "?", nil
}

// BuildFlags wires a CNG key reference into OpenZiti's native enrollment flags
// without touching the network. It fails closed on a malformed key name before
// any insecure fallback could occur. The returned flags carry KeyFile set to the
// CNG reference, which routes OpenZiti's enroll.Enroll into the engine path
// (identity.LoadKey) instead of generating an in-memory PEM key.
func BuildFlags(jwtString string, claims *ziti.EnrollmentClaims, keyName string) (enroll.EnrollmentFlags, error) {
	keyRef, err := KeyReference(keyName)
	if err != nil {
		return enroll.EnrollmentFlags{}, err
	}
	return enroll.EnrollmentFlags{
		Token:     claims,
		JwtString: jwtString,
		KeyFile:   keyRef,
	}, nil
}

// Enroll performs native OpenZiti OTT enrollment using a machine-scoped,
// non-exportable CNG key referenced by name.
//
// It parses the OTT JWT, wires the CNG key reference into the enrollment flags,
// and delegates the whole OTT/CSR/Controller exchange to the OpenZiti SDK's
// enroll.Enroll. No private key is generated, exported, or persisted by this
// package.
func Enroll(jwtString, keyName string) (*ziti.Config, error) {
	keyRef, err := KeyReference(keyName)
	if err != nil {
		return nil, err
	}

	claims, _, err := enroll.ParseToken(jwtString)
	if err != nil {
		return nil, fmt.Errorf("enrollcng: parse OTT token: %w", err)
	}

	flags := enroll.EnrollmentFlags{
		Token:     claims,
		JwtString: jwtString,
		KeyFile:   keyRef,
	}

	return enroll.Enroll(flags)
}

// CertMatchesSigner opens the CNG key and reports whether the leaf certificate
// returned by enrollment carries the same public key as the CNG signer. It is
// the post-enrollment proof that the CSR was signed by the CNG-backed key.
func CertMatchesSigner(cfg *ziti.Config, keyName string) (bool, error) {
	signer, err := windowscng.Open(keyName)
	if err != nil {
		return false, fmt.Errorf("enrollcng: open CNG key %q: %w", keyName, err)
	}
	defer func() { _ = signer.Close() }()

	certs, err := identity.LoadCert(cfg.ID.Cert)
	if err != nil {
		return false, fmt.Errorf("enrollcng: parse enrolled certificate: %w", err)
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




