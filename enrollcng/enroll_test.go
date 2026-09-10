package enrollcng

import (
	"strings"
	"testing"

	"github.com/openziti/identity/engines"
	"github.com/openziti/sdk-golang/v2/ziti"

	_ "github.com/keppin-oss/openziti-cng/cngengine"
)

func TestKeyReference(t *testing.T) {
	got, err := KeyReference("keppin-oz-001")
	if err != nil {
		t.Fatalf("KeyReference: %v", err)
	}
	if got != "cng:keppin-oz-001?" {
		t.Fatalf("KeyReference = %q, want %q", got, "cng:keppin-oz-001?")
	}
}

func TestKeyReferenceTrims(t *testing.T) {
	got, err := KeyReference("  keppin-oz-001  ")
	if err != nil {
		t.Fatalf("KeyReference: %v", err)
	}
	if got != "cng:keppin-oz-001?" {
		t.Fatalf("KeyReference = %q, want %q", got, "cng:keppin-oz-001?")
	}
}

func TestKeyReferenceRejectsMalformed(t *testing.T) {
	for _, name := range []string{"", "   ", "a?b", "a:b"} {
		if _, err := KeyReference(name); err == nil {
			t.Fatalf("KeyReference(%q) must fail", name)
		}
	}
}

func TestKeyReferenceIsNotPEMOrFilePath(t *testing.T) {
	ref, err := KeyReference("keppin-oz-001")
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(ref, "pem:") || strings.HasPrefix(ref, "file:") {
		t.Fatalf("reference %q must not be a pem/file address", ref)
	}
	if strings.Contains(ref, "-----BEGIN") {
		t.Fatalf("reference %q must not contain key material", ref)
	}
}

// TestBuildFlagsUsesCNGReference proves the enrollment flags are wired with the
// CNG key reference rather than a PEM/file path or an empty key (which would
// make OpenZiti's enroll.Enroll generate an in-memory PEM key).
func TestBuildFlagsUsesCNGReference(t *testing.T) {
	claims := &ziti.EnrollmentClaims{EnrollmentMethod: "ott"}
	flags, err := BuildFlags("jwt", claims, "keppin-oz-001")
	if err != nil {
		t.Fatalf("BuildFlags: %v", err)
	}

	if flags.KeyFile != "cng:keppin-oz-001?" {
		t.Fatalf("KeyFile = %q, want the CNG reference %q", flags.KeyFile, "cng:keppin-oz-001?")
	}
	if flags.Token != claims {
		t.Fatal("Token not carried through to flags")
	}
	if flags.KeyAlg != "" {
		t.Fatalf("KeyAlg = %q, want empty so no PEM key generation occurs", flags.KeyAlg)
	}
}

func TestBuildFlagsRejectsMalformedName(t *testing.T) {
	claims := &ziti.EnrollmentClaims{EnrollmentMethod: "ott"}
	if _, err := BuildFlags("jwt", claims, ""); err == nil {
		t.Fatal("BuildFlags with an empty key name must fail closed")
	}
	if _, err := BuildFlags("jwt", claims, "a?b"); err == nil {
		t.Fatal("BuildFlags with a '?' name must fail closed")
	}
}

// TestEngineRegistered proves the cng engine is registered when this module is
// compiled (the enrollment path relies on it).
func TestEngineRegistered(t *testing.T) {
	if _, ok := engines.GetEngine("cng"); !ok {
		t.Fatal("cng engine is not registered")
	}
}



