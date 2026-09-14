//go:build windows && cng_smoke

package cngengine

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"github.com/keppin-oss/openziti-cng/internal/keyref"
	"os"
	"strings"
	"testing"

	"github.com/openziti/identity"
)

// TestIdentityLoadKeySignVerify uses an operator-provisioned, dedicated fixture.
// It never creates or deletes persisted keys.
func TestIdentityLoadKeySignVerify(t *testing.T) {
	name := os.Getenv("CNG_TEST_KEY_NAME")
	if name == "" {
		t.Skip("set CNG_TEST_KEY_NAME to an explicitly provisioned test fixture")
	}
	// Fixture namespace is test-only; the general CNG name grammar is unchanged.
	if !strings.HasPrefix(name, "OpenZitiCNG.Test.") {
		t.Fatal("CNG_TEST_KEY_NAME must start with OpenZitiCNG.Test.")
	}
	ref, err := keyref.Format(name)
	if err != nil {
		t.Fatal(err)
	}
	// Resolve through the normal OpenZiti identity loading path.
	priv, err := identity.LoadKey(ref)
	if err != nil {
		t.Fatalf("identity.LoadKey: %v", err)
	}

	signer, ok := priv.(crypto.Signer)
	if !ok {
		t.Fatalf("identity.LoadKey returned %T, want crypto.Signer", priv)
	}

	if closer, ok := priv.(interface{ Close() error }); ok {
		defer func() {
			if err := closer.Close(); err != nil {
				t.Errorf("close signer: %v", err)
			}
		}()
	}

	// Deterministic digest.
	digest := sha256.Sum256([]byte("keppin-oss-openziti-cng-proof"))

	sig, err := signer.Sign(rand.Reader, digest[:], nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("Public() = %T, want *ecdsa.PublicKey", signer.Public())
	}

	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		t.Fatal("signature did not verify against signer.Public()")
	}

	// Check only the returned Go type; this is not proof that private
	// material was never copied elsewhere.
	if _, isMaterial := priv.(*ecdsa.PrivateKey); isMaterial {
		t.Fatal("identity.LoadKey returned a materialized *ecdsa.PrivateKey")
	}
}
