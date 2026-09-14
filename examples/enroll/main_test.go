package main

import (
	"github.com/openziti/identity"
	"github.com/openziti/sdk-golang/v2/ziti"
	"os"
	"path/filepath"
	"testing"
)

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
