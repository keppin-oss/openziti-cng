// Command loadidentity accepts only canonical CNG identity references.
package main

import (
	"crypto"
	"flag"
	"fmt"
	_ "github.com/keppin-oss/openziti-cng/cngengine"
	"github.com/keppin-oss/openziti-cng/internal/diagnostic"
	"github.com/keppin-oss/openziti-cng/internal/keyref"
	"github.com/openziti/identity"
	"github.com/openziti/sdk-golang/v2/ziti"
	"io"
	"log"
	"os"
)

func run(path string, output io.Writer) (resultErr error) {
	cfg, err := ziti.NewConfigFromFile(path)
	if err != nil {
		return diagnostic.Safe("load configuration", err)
	}
	if _, err := keyref.Parse(cfg.ID.Key); err != nil {
		return err
	}
	priv, err := identity.LoadKey(cfg.ID.Key)
	if err != nil {
		return diagnostic.Safe("open CNG identity key", err)
	}
	if closer, ok := priv.(interface{ Close() error }); ok {
		defer func() {
			if err := closer.Close(); err != nil {
				resultErr = diagnostic.Safe("close CNG identity key", err)
			}
		}()
	}
	if _, ok := priv.(crypto.Signer); !ok {
		return fmt.Errorf("CNG engine did not return a signer")
	}
	// Never print the arbitrary identity key field, even after validation.
	_, err = fmt.Fprintln(output, "resolved CNG-backed signer")
	return err
}

func main() {
	path := flag.String("config", "", "path to an OpenZiti identity JSON configuration")
	flag.Parse()
	if *path == "" {
		log.Fatal("-config is required")
	}
	if err := run(*path, os.Stdout); err != nil {
		log.Fatal(err)
	}
}
