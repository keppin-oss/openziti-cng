//go:build !windows

package main

import (
	"errors"
	"testing"

	"github.com/keppin-oss/cng/windowscng"
)

// Off Windows windowscng.Create only reports that CNG is unsupported; it
// creates nothing. The adapter must never select the cleanup-failed or
// key-exists message.
func TestCreateErrorNonWindowsStaysGeneric(t *testing.T) {
	_, native := windowscng.Create("Test", windowscng.PolicyServiceSigner)
	if native == nil {
		t.Fatal("expected the non-Windows platform error")
	}
	joined := errors.Join(native, syntheticNative())
	if isCleanupFailed(native) || isCleanupFailed(joined) || isKeyExists(native) || isKeyExists(joined) {
		t.Fatal("adapter classified a failure off Windows")
	}
	assertGenericError(t, createError(native))
}
