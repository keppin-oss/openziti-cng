// Command signverify signs and verifies using an existing CNG-backed key.
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	_ "github.com/keppin-oss/openziti-cng/cngengine"
	"github.com/keppin-oss/openziti-cng/enrollcng"
	"github.com/keppin-oss/openziti-cng/internal/diagnostic"
	"github.com/openziti/identity"
	"log"
)

func run(name string) (resultErr error) {
	ref, err := enrollcng.KeyReference(name)
	if err != nil {
		return err
	}
	priv, err := identity.LoadKey(ref)
	if err != nil {
		return diagnostic.Safe("open CNG signer", err)
	}
	if closer, ok := priv.(interface{ Close() error }); ok {
		defer func() {
			if err := closer.Close(); err != nil {
				resultErr = errors.Join(resultErr, diagnostic.Safe("close CNG signer", err))
			}
		}()
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return errors.New("CNG engine did not return a signer")
	}
	digest := sha256.Sum256([]byte("keppin-oss-openziti-cng-example"))
	sig, err := signer.Sign(rand.Reader, digest[:], nil)
	if err != nil {
		return diagnostic.Safe("sign", err)
	}
	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		return errors.New("expected ECDSA public key")
	}
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		return errors.New("signature verification failed")
	}
	return nil
}
func main() {
	name := flag.String("key", "Keppin.Demo.OpenZiti.CNG.v1", "existing CNG container name")
	flag.Parse()
	if err := run(*name); err != nil {
		log.Fatal(err)
	}
	fmt.Println("signed and verified using the CNG-backed signer")
}
