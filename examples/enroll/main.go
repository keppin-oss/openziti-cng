// Command enroll saves a usable OpenZiti identity configuration using a CNG key.
// The JWT input file and output directory must be protected by the operator's
// Windows ACLs. No CNG private-key bytes are serialized.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/keppin-oss/cng/windowscng"
	_ "github.com/keppin-oss/openziti-cng/cngengine"
	"github.com/keppin-oss/openziti-cng/enrollcng"
	"github.com/keppin-oss/openziti-cng/internal/diagnostic"
	"github.com/openziti/sdk-golang/v2/ziti"
)

// reserveOutput refuses overwrites and checks the destination before enrollment.
// Mode 0600 is not a Windows DACL guarantee; use an appropriately protected folder.
func reserveOutput(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, diagnostic.Safe("reserve new configuration output", err)
	}
	return f, nil
}

func writeConfig(f *os.File, cfg *ziti.Config, ref string) error {
	if cfg == nil || cfg.ID.Key != ref || cfg.ID.Cert == "" {
		return errors.New("enrollment did not return the expected CNG identity configuration")
	}
	if err := json.NewEncoder(f).Encode(cfg); err != nil {
		return diagnostic.Safe("write configuration", err)
	}
	if err := f.Sync(); err != nil {
		return diagnostic.Safe("sync configuration", err)
	}
	return nil
}

func run(jwtPath, keyName, output string) (resultErr error) {
	if _, err := enrollcng.KeyReference(keyName); err != nil {
		return err
	}
	data, err := os.ReadFile(jwtPath)
	if err != nil {
		return diagnostic.Safe("read OTT JWT file", err)
	}
	jwt := strings.TrimSpace(string(data))
	if jwt == "" {
		return errors.New("OTT JWT file is empty")
	}
	f, err := reserveOutput(output)
	if err != nil {
		return err
	}
	enrolled := false
	defer func() {
		if err := f.Close(); err != nil {
			resultErr = errors.Join(resultErr, diagnostic.Safe("close configuration output", err))
		}
		// Only remove the file this call exclusively created, before a successful
		// enrollment. Preserve any output after consumption for operator recovery.
		if !enrolled {
			if err := os.Remove(output); err != nil {
				resultErr = errors.Join(resultErr, diagnostic.Safe("remove unused configuration output", err))
			}
		}
	}()
	signer, err := windowscng.LoadOrCreate(keyName)
	if err != nil {
		return diagnostic.Safe("load or create CNG key", err)
	}
	if err := signer.Close(); err != nil {
		return diagnostic.Safe("close setup signer", err)
	}
	cfg, err := enrollcng.Enroll(jwt, keyName)
	if err != nil {
		return err
	}
	enrolled = true
	ref, _ := enrollcng.KeyReference(keyName)
	if err := writeConfig(f, cfg, ref); err != nil {
		return errors.Join(errors.New("enrollment succeeded; output incomplete, preserve the key and recover the configuration before retrying"), err)
	}
	ok, err := enrollcng.CertMatchesSigner(cfg, keyName)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("saved certificate does not match the CNG signer")
	}
	return nil
}

func main() {
	jwtPath := flag.String("jwt", "", "path to a protected OTT JWT file (raw JWT arguments are not accepted)")
	keyName := flag.String("key", "Keppin.Demo.OpenZiti.CNG.v1", "CNG container name")
	output := flag.String("out", "", "new identity JSON file in a protected directory (required; never overwritten)")
	flag.Parse()
	if *jwtPath == "" || *output == "" {
		log.Fatal("-jwt and -out are required")
	}
	if err := run(*jwtPath, *keyName, *output); err != nil {
		log.Fatal(err)
	}
	fmt.Println("enrolled CNG identity configuration saved and public key matched")
}
