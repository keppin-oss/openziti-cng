//go:build !windows

package main

import (
	"errors"
	"testing"

	"github.com/keppin-oss/cng/windowscng"
)

// Off Windows windowscng.LoadOrCreate only reports that CNG is unsupported; it
// creates nothing. The adapter must never select the cleanup-failed message.
func TestLoadOrCreateErrorNonWindowsStaysGeneric(t *testing.T) {
	_, native := windowscng.LoadOrCreate("Test")
	if native == nil {
		t.Fatal("expected the non-Windows platform error")
	}
	if isCleanupFailed(native) || isCleanupFailed(errors.Join(native, syntheticNative())) {
		t.Fatal("adapter reported a cleanup failure off Windows")
	}
	assertGenericError(t, loadOrCreateError(native))
}
