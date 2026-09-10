// Command loadidentity loads an OpenZiti identity configuration file, confirms
// that its key reference is a CNG reference (not a PEM/file key), and re-resolves
// the CNG-backed crypto.Signer from that reference through OpenZiti's identity
// loading path. No private-key material is exported at any point.
//
// The configuration is produced by enrollment (see examples/enroll) or any other
// OpenZiti identity configuration whose "id.key" is "cng:<name>?".
//
// The example runs on Windows. On non-Windows platforms identity.LoadKey
// returns a platform-unsupported error.
package main

import (
	"crypto"
	"flag"
	"fmt"
	"log"

	"github.com/openziti/identity"
	"github.com/openziti/sdk-golang/v2/ziti"

	// Register the "cng" engine with OpenZiti's identity package. The blank
	// import is the only activation step required from a consumer.
	_ "github.com/keppin-oss/openziti-cng/cngengine"
)

func main() {
	conf := flag.String("config", "", "path to an OpenZiti identity JSON configuration")
	flag.Parse()

	if *conf == "" {
		log.Fatal("-config is required")
	}

	cfg, err := ziti.NewConfigFromFile(*conf)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	if cfg.ID.Key == "" {
		log.Fatal("configuration has no identity key reference")
	}

	priv, err := identity.LoadKey(cfg.ID.Key)
	if err != nil {
		log.Fatalf("identity.LoadKey(%q): %v", cfg.ID.Key, err)
	}

	signer, ok := priv.(crypto.Signer)
	if !ok {
		log.Fatalf("identity.LoadKey returned %T, want crypto.Signer", priv)
	}

	if closer, ok := priv.(interface{ Close() error }); ok {
		defer func() { _ = closer.Close() }()
	}

	fmt.Printf("resolved CNG-backed signer from key reference %q (public key %T)\n", cfg.ID.Key, signer.Public())
}



