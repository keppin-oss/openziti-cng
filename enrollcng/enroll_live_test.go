//go:build windows && cng_enroll

package enrollcng

import (
	"os"
	"strings"
	"testing"

	"github.com/keppin-oss/cng/windowscng"
	"github.com/keppin-oss/openziti-cng/internal/diagnostic"
	"github.com/keppin-oss/openziti-cng/internal/keyref"
)

// TestLiveOttEnrollmentWithCNGKey uses a pre-provisioned test fixture and a
// single-use OTT token. It never creates or deletes persisted keys. The
// fixture's policy is required (CNG_TEST_KEY_POLICY, and CNG_TEST_KEY_SERVICE
// for the service policy): there is no default.
func TestLiveOttEnrollmentWithCNGKey(t *testing.T) {
	keyName := os.Getenv("CNG_TEST_KEY_NAME")
	if keyName == "" {
		t.Skip("set CNG_TEST_KEY_NAME to an explicitly provisioned test fixture")
	}
	// Reject a configured non-test name before any token prerequisite skip.
	if !strings.HasPrefix(keyName, "OpenZitiCNG.Test.") {
		t.Fatal("CNG_TEST_KEY_NAME must start with OpenZitiCNG.Test.")
	}
	policy, err := keyref.KeyPolicyFromNames(os.Getenv("CNG_TEST_KEY_POLICY"), os.Getenv("CNG_TEST_KEY_SERVICE"))
	if err != nil {
		t.Fatalf("CNG_TEST_KEY_POLICY / CNG_TEST_KEY_SERVICE: %v", err)
	}
	wantRef, err := KeyReference(keyName, policy)
	if err != nil {
		t.Fatal(err)
	}

	jwt := strings.TrimSpace(os.Getenv("ZITI_OTT_JWT"))
	if jwt == "" {
		t.Skip("NOT EXECUTED — set ZITI_OTT_JWT to the OTT enrollment JWT")
	}

	// A path-like value is read as a file; a missing file fails explicitly
	// rather than being silently reinterpreted as a raw JWT.
	jwt, err = loadOTTJWT(jwt)
	if err != nil {
		t.Fatal(diagnostic.Safe("read OTT JWT", err))
	}

	// Fixture ownership stays with the operator; this test owns only this handle.
	signer, err := windowscng.Open(keyName, policy)
	if err != nil {
		t.Fatal(diagnostic.Safe("open test fixture", err))
	}
	if err := signer.Close(); err != nil {
		t.Fatal(diagnostic.Safe("close test fixture", err))
	}

	cfg, err := Enroll(jwt, keyName, policy)
	if err != nil {
		t.Fatalf("native OTT enrollment failed: %v", err)
	}

	if cfg.ID.Key != wantRef {
		t.Fatal("enrolled configuration did not retain the expected CNG reference")
	}

	ok, err := CertMatchesSigner(cfg, keyName, policy)
	if err != nil {
		t.Fatalf("verifying enrolled certificate: %v", err)
	}
	if !ok {
		t.Fatal("enrolled certificate public key does not match the CNG signer public key")
	}
}
