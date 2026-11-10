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

func stubOpenSigner(t *testing.T, open func(string) (windowscng.Signer, error)) {
	t.Helper()
	orig := openSigner
	openSigner = open
	t.Cleanup(func() { openSigner = orig })
}

// errSyntheticExport stands in for a windowscng.Open failure such as the
// v0.2.2 public-key export guard (zero-size or inconsistent export) that used
// to panic. The engine must propagate it unchanged and never return a signer.
var errSyntheticExport = errors.New("synthetic windowscng public-key export failure")

func TestLoadKeyPropagatesOpenError(t *testing.T) {
	var opened []string
	stubOpenSigner(t, func(name string) (windowscng.Signer, error) {
		opened = append(opened, name)
		return nil, fmt.Errorf("export public key: %w", errSyntheticExport)
	})

	key, err := loadKeyForTest(t, "cng:OpenZitiCNG.Fake.Key?")
	if !errors.Is(err, errSyntheticExport) {
		t.Fatalf("Open error not propagated through identity.LoadKey: %v", err)
	}
	if key != nil {
		t.Fatalf("LoadKey returned a key (%T) together with an Open error", key)
	}
	if len(opened) != 1 || opened[0] != "OpenZitiCNG.Fake.Key" {
		t.Fatalf("Open called with %q, want exactly [OpenZitiCNG.Fake.Key]", opened)
	}
}

func TestLoadKeyReturnsOpenedSignerUnchanged(t *testing.T) {
	fake := newFakeSigner(t)
	stubOpenSigner(t, func(string) (windowscng.Signer, error) { return fake, nil })

	key, err := e.LoadKey(&url.URL{Scheme: EngineId, Host: "OpenZitiCNG.Fake.Key"})
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

func TestLoadKeyInvalidReferenceNeverOpens(t *testing.T) {
	stubOpenSigner(t, func(name string) (windowscng.Signer, error) {
		t.Fatalf("Open reached for an invalid reference (name %q)", name)
		return nil, nil
	})
	for _, u := range []*url.URL{
		nil,
		{Scheme: EngineId},
		{Scheme: EngineId, Host: "a?b"},
		{Scheme: EngineId, Host: "-----BEGIN EC PRIVATE KEY-----"},
		{Scheme: EngineId, Host: "Name", RawQuery: "token=SECRET"},
	} {
		if _, err := e.LoadKey(u); err == nil {
			t.Fatalf("LoadKey(%v) must fail before Open", u)
		}
	}
}
