package cngengine

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/url"
	"testing"

	"github.com/keppin-oss/cng/windowscng"
)

// These tests replace openSigner with in-memory fakes. No CNG provider is
// opened and no persisted key is created, opened or deleted.

type fakeSigner struct {
	key    *ecdsa.PrivateKey
	closed int
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
	return nil
}

// openCall records one call to the openSigner seam.
type openCall struct {
	name   string
	policy windowscng.KeyPolicy
}

func stubOpenSigner(t *testing.T, open func(string, windowscng.KeyPolicy) (windowscng.Signer, error)) *[]openCall {
	t.Helper()
	var calls []openCall
	orig := openSigner
	openSigner = func(name string, policy windowscng.KeyPolicy) (windowscng.Signer, error) {
		calls = append(calls, openCall{name, policy})
		return open(name, policy)
	}
	t.Cleanup(func() { openSigner = orig })
	return &calls
}

func mustServicePolicy(t *testing.T, service string) windowscng.ServicePolicy {
	t.Helper()
	sp, err := windowscng.NewServicePolicy(service)
	if err != nil {
		t.Fatal(err)
	}
	return sp
}

// errSyntheticExport stands in for a windowscng.Open failure such as a
// public-key export error. The engine must propagate it unchanged and never
// return a signer.
var errSyntheticExport = errors.New("synthetic windowscng public-key export failure")

// TestLoadKeyDispatchesEveryPolicyForm is the dispatch proof of the reference
// grammar: for each of the three canonical forms, identity.LoadKey (the real
// OpenZiti address parser and engine registry, on this OS) reaches Open with
// exactly the expected container name and windowscng policy.
func TestLoadKeyDispatchesEveryPolicyForm(t *testing.T) {
	cases := []struct {
		ref    string
		policy windowscng.KeyPolicy
	}{
		{"cng:OpenZitiCNG.Fake.Key?policy=service-signer", windowscng.PolicyServiceSigner},
		{"cng:OpenZitiCNG.Fake.Key?policy=privileged-only", windowscng.PolicyPrivilegedOnly},
		{"cng:OpenZitiCNG.Fake.Key?policy=service&service=KeppinAgent", mustServicePolicy(t, "KeppinAgent")},
	}
	for _, c := range cases {
		t.Run(c.ref, func(t *testing.T) {
			fake := newFakeSigner(t)
			calls := stubOpenSigner(t, func(string, windowscng.KeyPolicy) (windowscng.Signer, error) { return fake, nil })

			key, err := loadKeyForTest(t, c.ref)
			if err != nil {
				t.Fatalf("identity.LoadKey(%q): %v", c.ref, err)
			}
			if key != crypto.PrivateKey(fake) {
				t.Fatalf("LoadKey returned %T, want the signer returned by Open", key)
			}
			if len(*calls) != 1 || (*calls)[0].name != "OpenZitiCNG.Fake.Key" || (*calls)[0].policy != c.policy {
				t.Fatalf("Open calls = %+v, want exactly [{OpenZitiCNG.Fake.Key %v}]", *calls, c.policy)
			}
		})
	}
}

func TestLoadKeyPropagatesOpenError(t *testing.T) {
	calls := stubOpenSigner(t, func(string, windowscng.KeyPolicy) (windowscng.Signer, error) {
		return nil, fmt.Errorf("export public key: %w", errSyntheticExport)
	})

	key, err := loadKeyForTest(t, "cng:OpenZitiCNG.Fake.Key?policy=service-signer")
	if !errors.Is(err, errSyntheticExport) {
		t.Fatalf("Open error not propagated through identity.LoadKey: %v", err)
	}
	if key != nil {
		t.Fatalf("LoadKey returned a key (%T) together with an Open error", key)
	}
	if len(*calls) != 1 || (*calls)[0].name != "OpenZitiCNG.Fake.Key" {
		t.Fatalf("Open called with %+v, want exactly [OpenZitiCNG.Fake.Key]", *calls)
	}
}

func TestLoadKeyReturnsOpenedSignerUnchanged(t *testing.T) {
	fake := newFakeSigner(t)
	stubOpenSigner(t, func(string, windowscng.KeyPolicy) (windowscng.Signer, error) { return fake, nil })

	key, err := e.LoadKey(&url.URL{Scheme: EngineId, Host: "OpenZitiCNG.Fake.Key", RawQuery: "policy=privileged-only"})
	if err != nil {
		t.Fatalf("LoadKey: %v", err)
	}
	if key != crypto.PrivateKey(fake) {
		t.Fatalf("LoadKey returned %T, want the signer returned by Open", key)
	}
	if fake.closed != 0 {
		t.Fatal("LoadKey must hand handle ownership to the caller, not close the signer")
	}
}

// TestLoadKeyInvalidReferenceNeverOpens covers the engine's own check: an
// invalid reference, including one without a policy, never reaches Open.
func TestLoadKeyInvalidReferenceNeverOpens(t *testing.T) {
	stubOpenSigner(t, func(name string, _ windowscng.KeyPolicy) (windowscng.Signer, error) {
		t.Fatalf("Open reached for an invalid reference (name %q)", name)
		return nil, nil
	})
	for _, u := range []*url.URL{
		nil,
		{Scheme: EngineId},
		{Scheme: EngineId, Host: "Name"},
		{Scheme: EngineId, Host: "Name", ForceQuery: true},
		{Scheme: EngineId, Host: "a?b", RawQuery: "policy=service-signer"},
		{Scheme: EngineId, Host: "-----BEGIN EC PRIVATE KEY-----", RawQuery: "policy=service-signer"},
		{Scheme: EngineId, Host: "Name", RawQuery: "token=SECRET"},
		{Scheme: EngineId, Host: "Name", RawQuery: "policy=unknown"},
		{Scheme: EngineId, Host: "Name", RawQuery: "policy=service"},
		{Scheme: EngineId, Host: "Name", RawQuery: "policy=service&service=Bad%20Name"},
	} {
		if _, err := e.LoadKey(u); err == nil {
			t.Fatalf("LoadKey(%#v) must fail before Open", u)
		}
	}
	for _, ref := range []string{
		"cng:Name?",
		"cng:Name?policy=",
		"cng:Name?policy=service-signer&policy=privileged-only",
		"cng:Name?policy=service-signer&token=SECRET",
	} {
		if _, err := loadKeyForTest(t, ref); err == nil {
			t.Fatalf("identity.LoadKey(%q) must fail before Open", ref)
		}
	}
}
