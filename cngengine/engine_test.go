package cngengine

import (
	"errors"
	"net/url"
	"runtime"
	"strings"
	"testing"

	"github.com/keppin-oss/cng/windowscng"
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
	_, err := identity.LoadKey("cng:keppin-oz-does-not-exist?")
	if err == nil {
		t.Fatal("identity.LoadKey must fail for a missing CNG key")
	}
	if strings.Contains(err.Error(), "is not supported") {
		t.Fatalf("engine was not dispatched; got OpenZiti fallback error: %v", err)
	}
}

// TestLoadKeyMissingKeyMapped verifies a missing CNG key is surfaced as
// windowscng.ErrKeyNotFound on Windows (where CNG is available) and as a
// platform error elsewhere, and never as a PEM/file parse error.
func TestLoadKeyMissingKeyMapped(t *testing.T) {
	_, err := identity.LoadKey("cng:keppin-oz-missing-key?")
	if err == nil {
		t.Fatal("expected an error for a missing key")
	}

	if runtime.GOOS == "windows" {
		if !errors.Is(err, windowscng.ErrKeyNotFound) {
			t.Fatalf("missing key error = %v, want windowscng.ErrKeyNotFound", err)
		}
	} else {
		if !strings.Contains(err.Error(), "not supported") {
			t.Fatalf("non-Windows error = %v, want a platform-unsupported error", err)
		}
	}
}

// TestLoadKeyNoPEMOrFileFallback proves a cng: reference is never interpreted
// as PEM or as a file path by the OpenZiti loading path.
func TestLoadKeyNoPEMOrFileFallback(t *testing.T) {
	pemLike := "-----BEGIN EC PRIVATE KEY-----"
	_, err := identity.LoadKey("cng:" + pemLike + "?")
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



