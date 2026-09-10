// Command signverify demonstrates loading an existing machine-scoped,
// non-exportable CNG key through OpenZiti's identity key-loading path and using
// the returned value as a crypto.Signer without exporting any private-key
// material.
//
// It requires a persisted machine-scoped CNG key named by -key (default
// "Keppin.Demo.OpenZiti.CNG.v1"). The key is created by Keppin-OSS CNG (for example
// via windowscng.LoadOrCreate) in an elevated (Administrator) process; see the
// "Validation" section of the README.
//
// The example runs on Windows. On non-Windows platforms identity.LoadKey
// returns a platform-unsupported error.
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"flag"
	"fmt"
	"log"

	"github.com/openziti/identity"

	"github.com/keppin-oss/openziti-cng/enrollcng"

	// Register the "cng" engine with OpenZiti's identity package. The blank
	// import is the only activation step required from a consumer.
	_ "github.com/keppin-oss/openziti-cng/cngengine"
)

func main() {
	name := flag.String("key", "Keppin.Demo.OpenZiti.CNG.v1", "CNG container name")
	flag.Parse()

	ref, err := enrollcng.KeyReference(*name)
	if err != nil {
		log.Fatalf("key reference: %v", err)
	}

	priv, err := identity.LoadKey(ref)
	if err != nil {
		log.Fatalf("identity.LoadKey(%q): %v", ref, err)
	}

	signer, ok := priv.(crypto.Signer)
	if !ok {
		log.Fatalf("identity.LoadKey returned %T, want crypto.Signer", priv)
	}

	if closer, ok := priv.(interface{ Close() error }); ok {
		defer func() { _ = closer.Close() }()
	}

	digest := sha256.Sum256([]byte("keppin-oss-openziti-cng-example"))
	sig, err := signer.Sign(rand.Reader, digest[:], nil)
	if err != nil {
		log.Fatalf("Sign: %v", err)
	}

	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		log.Fatalf("Public() = %T, want *ecdsa.PublicKey", signer.Public())
	}
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		log.Fatal("signature did not verify against signer.Public()")
	}

	if _, isMaterial := priv.(*ecdsa.PrivateKey); isMaterial {
		log.Fatal("identity.LoadKey returned a materialized *ecdsa.PrivateKey")
	}

	fmt.Printf("signed and verified via CNG-backed signer %q (no private-key material exported)\n", *name)
}




