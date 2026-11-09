package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openziti/identity"
	"github.com/openziti/sdk-golang/v2/ziti"
)

// Sensitive markers that must never reach the operator-facing error.
var sensitiveMarkers = []string{"Keppin.Secret.Key", "hr=0x8009", "C:\\secret", "TOKEN_SECRET", "NCrypt"}

// syntheticNative builds an error that looks like a windowscng failure carrying
// a key name, HRESULT, path and token. No CNG key is created or deleted.
func syntheticNative() error {
	return fmt.Errorf("created key %q failed security validation at C:\\secret TOKEN_SECRET: NCryptSetProperty hr=0x80090009", "Keppin.Secret.Key")
}

func assertNoSensitive(t *testing.T, err error) {
	t.Helper()
	for _, marker := range sensitiveMarkers {
		if strings.Contains(err.Error(), marker) {
			t.Fatalf("operator error discloses %q: %v", marker, err)
		}
	}
}

// assertCleanupError checks the specific cleanup-failed error: it must tell the
// operator to verify a possibly persisted key, without native details.
func assertCleanupError(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, errKeyMayPersist) {
		t.Fatalf("expected the specific cleanup-failed error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "may still be persisted") || !strings.Contains(err.Error(), "manual cleanup") {
		t.Fatalf("specific error does not tell the operator to verify the persisted key: %v", err)
	}
	assertNoSensitive(t, err)
}

// assertGenericError checks the generic diagnostic.Safe error used for every
// LoadOrCreate failure other than a failed cleanup.
func assertGenericError(t *testing.T, err error) {
	t.Helper()
	if errors.Is(err, errKeyMayPersist) {
		t.Fatalf("non-cleanup failure mapped to the cleanup error: %v", err)
	}
	if !strings.Contains(err.Error(), "load or create CNG key") || !strings.Contains(err.Error(), "sensitive details withheld") {
		t.Fatalf("generic safe error expected, got: %v", err)
	}
	assertNoSensitive(t, err)
}

func TestCleanupErrorMessageIsSpecificAndSafe(t *testing.T) {
	assertCleanupError(t, errKeyMayPersist)
}

func TestLoadOrCreateErrorOtherFailuresStayGeneric(t *testing.T) {
	native := syntheticNative()
	err := loadOrCreateError(native)
	assertGenericError(t, err)
	if errors.Is(err, native) {
		t.Fatal("native error chain must not be retained")
	}
}

func TestConfigurationPersistenceAndNoOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")
	f, err := reserveOutput(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ziti.Config{ZtAPI: "https://controller", ID: identity.Config{Key: "cng:Test_001?", Cert: "pem:CERT", CA: "pem:CA"}}
	if err := writeConfig(f, cfg, cfg.ID.Key); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := ziti.NewConfigFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.ZtAPI != cfg.ZtAPI || got.ID.Key != cfg.ID.Key || got.ID.Cert != cfg.ID.Cert || got.ID.CA != cfg.ID.CA {
		t.Fatal("configuration did not round trip")
	}
	if other, err := reserveOutput(path); err == nil {
		other.Close()
		t.Fatal("existing configuration overwritten")
	}
}
func TestRejectUnexpectedEnrollmentKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")
	f, err := reserveOutput(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	cfg := &ziti.Config{ID: identity.Config{Key: "pem:SECRET", Cert: "pem:CERT"}}
	if err := writeConfig(f, cfg, "cng:Test?"); err == nil {
		t.Fatal("non-CNG result accepted")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 0 {
		t.Fatal("unexpected key persisted")
	}
}
