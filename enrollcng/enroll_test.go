package enrollcng

import (
	"strings"
	"testing"

	"github.com/keppin-oss/cng/windowscng"
	"github.com/openziti/identity/engines"
	"github.com/openziti/sdk-golang/v2/ziti"

	_ "github.com/keppin-oss/openziti-cng/cngengine"
)

func TestKeyReference(t *testing.T) {
	sp, err := windowscng.NewServicePolicy("KeppinAgent")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		policy windowscng.KeyPolicy
		want   string
	}{
		{windowscng.PolicyServiceSigner, "cng:keppin-oz-001?policy=service-signer"},
		{windowscng.PolicyPrivilegedOnly, "cng:keppin-oz-001?policy=privileged-only"},
		{sp, "cng:keppin-oz-001?policy=service&service=KeppinAgent"},
	} {
		got, err := KeyReference("keppin-oz-001", c.policy)
		if err != nil {
			t.Fatalf("KeyReference(%v): %v", c.policy, err)
		}
		if got != c.want {
			t.Fatalf("KeyReference = %q, want %q", got, c.want)
		}
	}
}

// TestKeyReferenceRequiresAValidPolicy: there is no default policy, and the
// service form never persists a SID.
func TestKeyReferenceRequiresAValidPolicy(t *testing.T) {
	for _, policy := range []windowscng.KeyPolicy{nil, windowscng.Policy(0), windowscng.Policy(99), windowscng.ServicePolicy{}} {
		if _, err := KeyReference("keppin-oz-001", policy); err == nil {
			t.Fatalf("KeyReference accepted policy %v", policy)
		}
	}
	sp, err := windowscng.NewServicePolicy("KeppinAgent")
	if err != nil {
		t.Fatal(err)
	}
	ref, err := KeyReference("keppin-oz-001", sp)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(ref, sp.SID()) || strings.Contains(ref, "S-1-5-80") {
		t.Fatalf("reference %q persists the service SID", ref)
	}
}

func TestKeyReferenceRejectsWhitespace(t *testing.T) {
	if _, err := KeyReference(" name ", windowscng.PolicyServiceSigner); err == nil {
		t.Fatal("ambiguous whitespace accepted")
	}
}

func TestKeyReferenceRejectsMalformed(t *testing.T) {
	for _, name := range []string{"", "   ", "a?b", "a:b"} {
		if _, err := KeyReference(name, windowscng.PolicyServiceSigner); err == nil {
			t.Fatalf("KeyReference(%q) must fail", name)
		}
	}
}

func TestKeyReferenceIsNotPEMOrFilePath(t *testing.T) {
	ref, err := KeyReference("keppin-oz-001", windowscng.PolicyServiceSigner)
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
	flags, err := BuildFlags("jwt", claims, "keppin-oz-001", windowscng.PolicyPrivilegedOnly)
	if err != nil {
		t.Fatalf("BuildFlags: %v", err)
	}

	const want = "cng:keppin-oz-001?policy=privileged-only"
	if flags.KeyFile != want {
		t.Fatalf("KeyFile = %q, want the CNG reference %q", flags.KeyFile, want)
	}
	if flags.Token != claims {
		t.Fatal("Token not carried through to flags")
	}
	if flags.KeyAlg != "" {
		t.Fatalf("KeyAlg = %q, want empty so no PEM key generation occurs", flags.KeyAlg)
	}
}

func TestBuildFlagsRejectsMalformedNameOrPolicy(t *testing.T) {
	claims := &ziti.EnrollmentClaims{EnrollmentMethod: "ott"}
	if _, err := BuildFlags("jwt", claims, "", windowscng.PolicyServiceSigner); err == nil {
		t.Fatal("BuildFlags with an empty key name must fail closed")
	}
	if _, err := BuildFlags("jwt", claims, "a?b", windowscng.PolicyServiceSigner); err == nil {
		t.Fatal("BuildFlags with a '?' name must fail closed")
	}
	if _, err := BuildFlags("jwt", claims, "keppin-oz-001", nil); err == nil {
		t.Fatal("BuildFlags without a policy must fail closed")
	}
}

// TestEngineRegistered proves the cng engine is registered when this module is
// compiled (the enrollment path relies on it).
func TestEngineRegistered(t *testing.T) {
	if _, ok := engines.GetEngine("cng"); !ok {
		t.Fatal("cng engine is not registered")
	}
}

func TestEnrollRejectsMalformedTokenSafely(t *testing.T) {
	_, err := Enroll("PRIVATE_TOKEN.invalid", "Test", windowscng.PolicyServiceSigner)
	if err == nil || strings.Contains(err.Error(), "PRIVATE_TOKEN") {
		t.Fatal("malformed token not handled safely")
	}
}

func TestCertMatchesSignerRejectsNil(t *testing.T) {
	if _, err := CertMatchesSigner(nil, "Test", windowscng.PolicyServiceSigner); err == nil {
		t.Fatal("nil configuration accepted")
	}
}
