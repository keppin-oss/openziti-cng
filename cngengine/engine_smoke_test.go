//go:build windows && cng_smoke

package cngengine

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/keppin-oss/cng/windowscng"
	"github.com/openziti/identity"
)

// testLifecycleKeyName is a dedicated test-namespace key. It must never equal a
// Keppin production key name.
const testLifecycleKeyName = "Keppin.Test.OpenZiti.CNG.v1"

// TestIdentityLoadKeySignVerify proves the full integration path end to end:
//
//	identity.LoadKey("cng:<name>?") -> windowscng -> CNG/KSP -> crypto.Signer
//	    -> Sign(...) -> verify with signer.Public()
//
// It requires an elevated (Administrator) process because it creates a
// machine-scoped, non-exportable CNG key. When not elevated it reports
// "NOT EXECUTED — requires manual Administrator run".
func TestIdentityLoadKeySignVerify(t *testing.T) {
	// Create (or open) the machine-scoped test key. This is the only step that
	// needs elevation; if it fails, skip rather than weaken anything.
	if _, err := windowscng.LoadOrCreate(testLifecycleKeyName); err != nil {
		t.Skipf("NOT EXECUTED — requires manual Administrator run: %v", err)
	}
	t.Cleanup(func() {
		_ = windowscng.Delete(testLifecycleKeyName)
	})

	// Resolve through the normal OpenZiti identity loading path.
	priv, err := identity.LoadKey("cng:" + testLifecycleKeyName + "?")
	if err != nil {
		t.Fatalf("identity.LoadKey: %v", err)
	}

	signer, ok := priv.(crypto.Signer)
	if !ok {
		t.Fatalf("identity.LoadKey returned %T, want crypto.Signer", priv)
	}

	if closer, ok := priv.(interface{ Close() error }); ok {
		defer func() { _ = closer.Close() }()
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

	// The key must not be a plaintext ECDSA private key: prove no private
	// material was returned by identity.LoadKey.
	if _, isMaterial := priv.(*ecdsa.PrivateKey); isMaterial {
		t.Fatal("identity.LoadKey returned a materialized *ecdsa.PrivateKey")
	}
}



