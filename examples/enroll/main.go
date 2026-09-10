// Command enroll performs native OpenZiti OTT enrollment with a machine-scoped,
// non-exportable CNG key, then verifies that the returned identity certificate
// matches the CNG signer's public key.
//
// Requirements:
//   - an elevated (Administrator) process to create the machine-scoped key;
//   - a reachable OpenZiti Controller and a single-use OTT enrollment JWT.
//
// The JWT is passed via -jwt as either a filesystem path or the raw JWT string.
// No private-key material is generated, exported, or persisted by this example:
// enrollment is delegated unchanged to the OpenZiti SDK, which is routed into
// the "cng" engine via the KeyFile reference built by enrollcng.
//
// The example runs on Windows. On non-Windows platforms the machine-scoped CNG
// key cannot be created and the example fails with a platform-unsupported error.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/keppin-oss/cng/windowscng"
	"github.com/keppin-oss/openziti-cng/enrollcng"

	// Register the "cng" engine with OpenZiti's identity package. The blank
	// import is the only activation step required from a consumer.
	_ "github.com/keppin-oss/openziti-cng/cngengine"
)

func main() {
	jwt := flag.String("jwt", "", "path to the OTT JWT file, or the raw JWT string")
	keyName := flag.String("key", "Keppin.Demo.OpenZiti.CNG.v1", "CNG container name")
	flag.Parse()

	if strings.TrimSpace(*jwt) == "" {
		log.Fatal("-jwt is required")
	}

	// Accept either a filesystem path or a raw JWT. A value that names an
	// existing file is read from disk; otherwise it is treated as the raw JWT.
	jwtString := strings.TrimSpace(*jwt)
	if data, err := os.ReadFile(*jwt); err == nil {
		jwtString = strings.TrimSpace(string(data))
	}

	// Create (or open) the machine-scoped, non-exportable CNG key. This is the
	// only step that needs elevation. The returned signer owns CNG handles and
	// must be closed; enrollcng.Enroll opens the key again through the engine,
	// so close this handle as soon as the persisted key is known to exist.
	signer, err := windowscng.LoadOrCreate(*keyName)
	if err != nil {
		log.Fatalf("load or create CNG key: %v", err)
	}
	if err := signer.Close(); err != nil {
		log.Fatalf("close CNG key handle: %v", err)
	}

	cfg, err := enrollcng.Enroll(jwtString, *keyName)
	if err != nil {
		log.Fatalf("native OTT enrollment: %v", err)
	}

	ok, err := enrollcng.CertMatchesSigner(cfg, *keyName)
	if err != nil {
		log.Fatalf("verify enrolled certificate: %v", err)
	}
	if !ok {
		log.Fatal("enrolled certificate public key does not match the CNG signer")
	}

	fmt.Printf("enrolled identity: key reference %q resolves to the CNG-backed signer\n", cfg.ID.Key)
}



