package cngengine

import (
	"crypto"

	"net/url"

	"strings"
	"testing"

	"github.com/openziti/identity"
	"github.com/openziti/identity/engines"
)

func TestEngineIsRegistered(t *testing.T) {
	e, ok := engines.GetEngine(EngineId)
	if !ok {
		t.Fatalf("engine %q is not registered", EngineId)
	}
	if e.Id() != EngineId {
		t.Fatalf("engine Id() = %q, want %q", e.Id(), EngineId)
	}
}

func TestEngineListed(t *testing.T) {
	found := false
	for _, id := range engines.ListEngines() {
		if id == EngineId {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("engine %q missing from ListEngines(): %v", EngineId, engines.ListEngines())
	}
}

// TestLoadKeyDispatchesToCNG proves identity.LoadKey reaches this engine (via
// the real OpenZiti engine registry) rather than reporting "engine not
// supported". The key does not exist, so a concrete error is expected; the
// point is the shape of that error proves the dispatch path.
func TestLoadKeyDispatchesToCNG(t *testing.T) {
	_, err := loadKeyForTest(t, "cng:keppin-oz-does-not-exist?")
	if err == nil {
		t.Fatal("identity.LoadKey must fail for a missing CNG key")
	}
	if strings.Contains(err.Error(), "engine 'cng' is not supported") {
		t.Fatalf("engine was not dispatched; got OpenZiti fallback error: %v", err)
	}
}

// TestLoadKeyNoPEMOrFileFallback checks rejection of a PEM-like CNG name
// without a PEM-decoding or file-reading error.
func TestLoadKeyNoPEMOrFileFallback(t *testing.T) {
	pemLike := "-----BEGIN EC PRIVATE KEY-----"
	_, err := loadKeyForTest(t, "cng:"+pemLike+"?")
	if err == nil {
		t.Fatal("expected an error for a PEM-like CNG reference")
	}
	if strings.Contains(err.Error(), "no key found") {
		t.Fatalf("reference was interpreted as PEM: %v", err)
	}
	if strings.Contains(err.Error(), "could not read file") || strings.Contains(err.Error(), "no file found") {
		t.Fatalf("reference was interpreted as a file: %v", err)
	}
}

// TestEngineLoadKeyRejectsNilAndEmpty mirrors parseReference behavior through
// the engine's LoadKey entry point.
func TestEngineLoadKeyRejectsNilAndEmpty(t *testing.T) {
	if _, err := e.LoadKey(nil); err == nil {
		t.Fatal("LoadKey(nil) must fail")
	}
	if _, err := e.LoadKey(&url.URL{Scheme: EngineId}); err == nil {
		t.Fatal("LoadKey with an empty name must fail")
	}
}

func loadKeyForTest(t *testing.T, ref string) (crypto.PrivateKey, error) {
	t.Helper()
	key, err := identity.LoadKey(ref)
	if closer, ok := key.(interface{ Close() error }); ok {
		t.Cleanup(func() {
			if err := closer.Close(); err != nil {
				t.Errorf("close test signer: %v", err)
			}
		})
	}
	return key, err
}
