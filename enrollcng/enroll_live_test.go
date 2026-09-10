//go:build windows && cng_enroll

package enrollcng

import (
	"os"
	"strings"
	"testing"

	"github.com/keppin-oss/cng/windowscng"
)

// TestLiveOttEnrollmentWithCNGKey performs the decisive proof: native OpenZiti
// OTT enrollment against a real Controller using a machine-scoped,
// non-exportable CNG key.
//
// It requires:
//   - an elevated (Administrator) process (machine-scoped key creation);
//   - a reachable OpenZiti Controller and a single-use OTT enrollment JWT.
//
// Environment:
//
//	ZITI_OTT_JWT   (required) path to the OTT JWT file, or the raw JWT string
//	CNG_KEY_NAME   (optional) CNG container name; default Keppin.Test.OpenZiti.CNG.v1
func TestLiveOttEnrollmentWithCNGKey(t *testing.T) {
	jwt := strings.TrimSpace(os.Getenv("ZITI_OTT_JWT"))
	if jwt == "" {
		t.Skip("NOT EXECUTED — set ZITI_OTT_JWT to the OTT enrollment JWT")
	}

	keyName := os.Getenv("CNG_KEY_NAME")
	if keyName == "" {
		keyName = "Keppin.Test.OpenZiti.CNG.v1"
	}

	// A path-like value is read as a file; a missing file fails explicitly
	// rather than being silently reinterpreted as a raw JWT.
	var err error
	jwt, err = loadOTTJWT(jwt)
	if err != nil {
		t.Fatalf("ZITI_OTT_JWT: %v", err)
	}

	// Create (or open) the machine-scoped CNG key. This is the only step that
	// needs elevation; if it fails, skip rather than weaken anything.
	if _, err := windowscng.LoadOrCreate(keyName); err != nil {
		t.Skipf("NOT EXECUTED — requires manual Administrator run: %v", err)
	}
	t.Cleanup(func() { _ = windowscng.Delete(keyName) })

	cfg, err := Enroll(jwt, keyName)
	if err != nil {
		t.Fatalf("native OTT enrollment failed: %v", err)
	}

	if cfg.ID.Key != "cng:"+keyName+"?" {
		t.Fatalf("enrolled config key = %q, want the CNG reference %q", cfg.ID.Key, "cng:"+keyName+"?")
	}

	ok, err := CertMatchesSigner(cfg, keyName)
	if err != nil {
		t.Fatalf("verifying enrolled certificate: %v", err)
	}
	if !ok {
		t.Fatal("enrolled certificate public key does not match the CNG signer public key")
	}
}



