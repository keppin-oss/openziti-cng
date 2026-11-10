//go:build windows

package main

import (
	"errors"
	"fmt"
	"testing"

	"github.com/keppin-oss/cng/windowscng"
)

// These tests use synthetic errors built around the real windowscng
// sentinels. No CNG key is created, opened or deleted.

func TestLoadOrCreateErrorRecognizesRealCleanupFailedSentinel(t *testing.T) {
	// Same shape windowscng uses: the original failure joined with a
	// wrapped ErrCleanupFailed that carries native details.
	native := errors.Join(syntheticNative(), fmt.Errorf("%w: NCryptDeleteKey hr=0x80090016 Keppin.Secret.Key", windowscng.ErrCleanupFailed))
	if !isCleanupFailed(native) {
		t.Fatal("adapter does not recognize windowscng.ErrCleanupFailed")
	}
	err := loadOrCreateError(native)
	assertCleanupError(t, err)
	if errors.Is(err, windowscng.ErrCleanupFailed) {
		t.Fatal("native error chain must not be retained")
	}
}

// TestRunLoadOrCreateCleanupFailedIsSpecific drives run with the v0.2.2 shape
// of a failed rollback (original failure joined with a wrapped
// ErrCleanupFailed, as returned when the signer cannot be built after a new
// key was created and deleting it failed). run must stop before enrollment,
// return the specific operator error and drop the reserved output.
func TestRunLoadOrCreateCleanupFailedIsSpecific(t *testing.T) {
	stubLoadOrCreate(t, func(string) (windowscng.Signer, error) {
		return nil, errors.Join(syntheticNative(), fmt.Errorf("%w: NCryptDeleteKey hr=0x80090016 Keppin.Secret.Key", windowscng.ErrCleanupFailed))
	})
	jwtPath, output := runFixture(t)

	err := run(jwtPath, runKeyName, output)
	assertCleanupError(t, err)
	if errors.Is(err, windowscng.ErrCleanupFailed) {
		t.Fatal("native error chain must not be retained")
	}
	assertOutputRemoved(t, output)
}

func TestLoadOrCreateErrorKeyNotFoundStaysGeneric(t *testing.T) {
	native := fmt.Errorf("key %q: NCryptOpenKey hr=0x80090016: %w", "Keppin.Secret.Key", windowscng.ErrKeyNotFound)
	if isCleanupFailed(native) {
		t.Fatal("ErrKeyNotFound misclassified as a cleanup failure")
	}
	err := loadOrCreateError(native)
	assertGenericError(t, err)
	if errors.Is(err, windowscng.ErrKeyNotFound) {
		t.Fatal("native error chain must not be retained")
	}
}
