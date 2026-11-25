package enrollcng

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/keppin-oss/cng/windowscng"
	"github.com/openziti/identity"
	"github.com/openziti/sdk-golang/v2/ziti"
)

// These tests replace openSigner with in-memory fakes. No CNG provider is
// opened and no persisted key is created, opened or deleted.

type fakeSigner struct {
	key      *ecdsa.PrivateKey
	closeErr error
	closed   int
}

func newFakeSigner(t *testing.T) *fakeSigner {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeSigner{key: key}
}

func (f *fakeSigner) Public() crypto.PublicKey { return &f.key.PublicKey }

func (f *fakeSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return f.key.Sign(rand.Reader, digest, opts)
}

func (f *fakeSigner) Close() error {
	f.closed++
	return f.closeErr
}

// openCall records one call to the openSigner seam.
type openCall struct {
	name   string
	policy windowscng.KeyPolicy
}

func stubOpenSigner(t *testing.T, open func(string) (windowscng.Signer, error)) *[]openCall {
	t.Helper()
	var calls []openCall
	orig := openSigner
	openSigner = func(name string, policy windowscng.KeyPolicy) (windowscng.Signer, error) {
		calls = append(calls, openCall{name, policy})
		return open(name)
	}
	t.Cleanup(func() { openSigner = orig })
	return &calls
}

// testPolicy is the policy most tests pass; it only has to be a valid one.
const testPolicy = windowscng.PolicyServiceSigner

// configFor returns an enrollment result whose leaf certificate carries pub.
func configFor(t *testing.T, pub *ecdsa.PublicKey) *ziti.Config {
	t.Helper()
	issuer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "enrollcng-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, issuer)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return &ziti.Config{ID: identity.Config{Key: "cng:OpenZitiCNG.Fake.Key?policy=service-signer", Cert: "pem:" + string(certPEM)}}
}

var errSyntheticOpen = errors.New("synthetic windowscng Open failure")

// TestCertMatchesSignerPropagatesOpenError covers the public contract: an Open
// failure (for example the v0.2.2 public-key export error that used to panic)
// is returned wrapped, so callers can still use errors.Is on the cause.
func TestCertMatchesSignerPropagatesOpenError(t *testing.T) {
	fake := newFakeSigner(t)
	stubOpenSigner(t, func(name string) (windowscng.Signer, error) {
		return nil, fmt.Errorf("key %q: export public key: %w", name, errSyntheticOpen)
	})

	ok, err := CertMatchesSigner(configFor(t, &fake.key.PublicKey), "OpenZitiCNG.Fake.Key", testPolicy)
	if ok {
		t.Fatal("match reported despite Open failure")
	}
	if !errors.Is(err, errSyntheticOpen) {
		t.Fatalf("Open cause not reachable with errors.Is: %v", err)
	}
	if !strings.Contains(err.Error(), "enrollcng: open CNG key") {
		t.Fatalf("missing helper stage in error: %v", err)
	}
}

func TestCertMatchesSignerInvalidNameNeverOpens(t *testing.T) {
	stubOpenSigner(t, func(name string) (windowscng.Signer, error) {
		t.Fatalf("Open reached for invalid name %q", name)
		return nil, nil
	})
	fake := newFakeSigner(t)
	for _, name := range []string{"", "a?b", "a:b", " name "} {
		if _, err := CertMatchesSigner(configFor(t, &fake.key.PublicKey), name, testPolicy); err == nil {
			t.Fatalf("CertMatchesSigner(%q) must fail before Open", name)
		}
	}
}

// TestCertMatchesSignerMatchAndMismatch gives each call its own signer, as two
// independent Open calls would, and checks that each one is closed exactly
// once by the call that opened it.
func TestCertMatchesSignerMatchAndMismatch(t *testing.T) {
	t.Run("match", func(t *testing.T) {
		fake := newFakeSigner(t)
		stubOpenSigner(t, func(string) (windowscng.Signer, error) { return fake, nil })

		ok, err := CertMatchesSigner(configFor(t, &fake.key.PublicKey), "OpenZitiCNG.Fake.Key", testPolicy)
		if err != nil || !ok {
			t.Fatalf("matching certificate: ok=%v err=%v", ok, err)
		}
		if fake.closed != 1 {
			t.Fatalf("signer closed %d times, want 1", fake.closed)
		}
	})

	t.Run("mismatch", func(t *testing.T) {
		fake := newFakeSigner(t)
		unrelated := newFakeSigner(t)
		stubOpenSigner(t, func(string) (windowscng.Signer, error) { return fake, nil })

		ok, err := CertMatchesSigner(configFor(t, &unrelated.key.PublicKey), "OpenZitiCNG.Fake.Key", testPolicy)
		if err != nil || ok {
			t.Fatalf("mismatching certificate: ok=%v err=%v", ok, err)
		}
		if fake.closed != 1 {
			t.Fatalf("signer closed %d times, want 1", fake.closed)
		}
		if unrelated.closed != 0 {
			t.Fatal("certificate-only key must never be opened or closed")
		}
	})
}

func TestCertMatchesSignerCloseFailureIsSafeAndFailsMatch(t *testing.T) {
	fake := newFakeSigner(t)
	fake.closeErr = errors.New("NCryptFreeObject hr=0x80090026 Keppin.Secret.Key")
	stubOpenSigner(t, func(string) (windowscng.Signer, error) { return fake, nil })

	ok, err := CertMatchesSigner(configFor(t, &fake.key.PublicKey), "OpenZitiCNG.Fake.Key", testPolicy)
	if ok {
		t.Fatal("match reported despite Close failure")
	}
	if err == nil || !strings.Contains(err.Error(), "enrollcng: close signer") {
		t.Fatalf("expected close failure, got %v", err)
	}
	if strings.Contains(err.Error(), "Keppin.Secret.Key") || strings.Contains(err.Error(), "hr=0x") {
		t.Fatalf("close failure discloses native details: %v", err)
	}
	if fake.closed != 1 {
		t.Fatalf("signer closed %d times, want 1", fake.closed)
	}
}

func TestCertMatchesSignerBadCertificateClosesSigner(t *testing.T) {
	fake := newFakeSigner(t)
	stubOpenSigner(t, func(string) (windowscng.Signer, error) { return fake, nil })

	cfg := &ziti.Config{ID: identity.Config{Cert: "pem:not a certificate"}}
	ok, err := CertMatchesSigner(cfg, "OpenZitiCNG.Fake.Key", testPolicy)
	if ok || err == nil {
		t.Fatalf("unparseable certificate accepted: ok=%v err=%v", ok, err)
	}
	if fake.closed != 1 {
		t.Fatalf("signer closed %d times, want 1", fake.closed)
	}
}

// TestCertMatchesSignerOpensWithThePolicy checks that the helper opens the key
// under exactly the policy it was given, for each policy kind.
func TestCertMatchesSignerOpensWithThePolicy(t *testing.T) {
	sp, err := windowscng.NewServicePolicy("KeppinAgent")
	if err != nil {
		t.Fatal(err)
	}
	for _, policy := range []windowscng.KeyPolicy{windowscng.PolicyServiceSigner, windowscng.PolicyPrivilegedOnly, sp} {
		fake := newFakeSigner(t)
		calls := stubOpenSigner(t, func(string) (windowscng.Signer, error) { return fake, nil })
		ok, err := CertMatchesSigner(configFor(t, &fake.key.PublicKey), "OpenZitiCNG.Fake.Key", policy)
		if err != nil || !ok {
			t.Fatalf("policy %v: ok=%v err=%v", policy, ok, err)
		}
		if len(*calls) != 1 || (*calls)[0].name != "OpenZitiCNG.Fake.Key" || (*calls)[0].policy != policy {
			t.Fatalf("Open calls = %+v, want exactly [{OpenZitiCNG.Fake.Key %v}]", *calls, policy)
		}
	}
}

// TestCertMatchesSignerInvalidPolicyNeverOpens: there is no default policy.
func TestCertMatchesSignerInvalidPolicyNeverOpens(t *testing.T) {
	stubOpenSigner(t, func(name string) (windowscng.Signer, error) {
		t.Fatalf("Open reached with an invalid policy (name %q)", name)
		return nil, nil
	})
	fake := newFakeSigner(t)
	for _, policy := range []windowscng.KeyPolicy{nil, windowscng.Policy(0), windowscng.ServicePolicy{}} {
		if _, err := CertMatchesSigner(configFor(t, &fake.key.PublicKey), "OpenZitiCNG.Fake.Key", policy); err == nil {
			t.Fatalf("CertMatchesSigner with policy %v must fail before Open", policy)
		}
	}
}
