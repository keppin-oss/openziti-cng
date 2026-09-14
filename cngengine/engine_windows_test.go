//go:build windows

package cngengine

import (
	"errors"
	"github.com/keppin-oss/cng/windowscng"
	"testing"
)

func TestLoadKeyMissingKeyMapped(t *testing.T) {
	_, err := loadKeyForTest(t, "cng:keppin-oz-missing-key?")
	if !errors.Is(err, windowscng.ErrKeyNotFound) {
		t.Fatalf("expected CNG key-not-found error, got %v", err)
	}
}
