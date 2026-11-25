//go:build windows

package main

import (
	"errors"
	"fmt"
	"testing"

	"github.com/keppin-oss/cng/windowscng"
)

// These tests use synthetic errors built around the real windowscng
// sentinels, wrapped as windowscng wraps them. No CNG key is created, opened
// or deleted.

// cleanupFailedNative has the shape windowscng.Create returns when the key it
// created could not be deleted: the original failure joined with a wrapped
// ErrCleanupFailed that carries native details.
func cleanupFailedNative() error {
	return errors.Join(syntheticNative(), fmt.Errorf("%w: NCryptDeleteKey hr=0x80090016 Keppin.Secret.Key", windowscng.ErrCleanupFailed))
}

// keyExistsNative has the shape of a create collision: ErrKeyExists wrapped
// with the key name and HRESULT.
func keyExistsNative() error {
	return fmt.Errorf("create key %q: NCryptCreatePersistedKey hr=0x8009000F: %w", "Keppin.Secret.Key", windowscng.ErrKeyExists)
}

func TestCreateErrorRecognizesRealCleanupFailedSentinel(t *testing.T) {
	native := cleanupFailedNative()
	if !isCleanupFailed(native) {
		t.Fatal("adapter does not recognize windowscng.ErrCleanupFailed")
	}
	err := createError(native)
	assertCleanupError(t, err)
	if errors.Is(err, windowscng.ErrCleanupFailed) {
		t.Fatal("native error chain must not be retained")
	}
}

func TestCreateErrorRecognizesRealKeyExistsSentinel(t *testing.T) {
	native := keyExistsNative()
	if !isKeyExists(native) || isCleanupFailed(native) {
		t.Fatal("adapter does not classify windowscng.ErrKeyExists")
	}
	err := createError(native)
	assertKeyExistsError(t, err)
	if errors.Is(err, windowscng.ErrKeyExists) {
		t.Fatal("native error chain must not be retained")
	}
}

// TestCreateErrorCleanupFailedWinsOverKeyExists: a possible residue is the
// outcome the operator must not miss, so it is reported first.
func TestCreateErrorCleanupFailedWinsOverKeyExists(t *testing.T) {
	assertCleanupError(t, createError(errors.Join(keyExistsNative(), cleanupFailedNative())))
}

// TestRunCreateCleanupFailedIsSpecific: run must stop before enrollment,
// return the specific operator error and drop the reserved output.
func TestRunCreateCleanupFailedIsSpecific(t *testing.T) {
	stubCreate(t, func(string, windowscng.KeyPolicy) (windowscng.Signer, error) {
		return nil, cleanupFailedNative()
	})
	jwtPath, output := runFixture(t)

	err := run(jwtPath, runKeyName, runPolicy, output)
	assertCleanupError(t, err)
	if errors.Is(err, windowscng.ErrCleanupFailed) {
		t.Fatal("native error chain must not be retained")
	}
	assertOutputRemoved(t, output)
}

// TestRunCreateKeyExistsStopsBeforeEnrollment: a name already in use is
// refused. Create is called once and nothing else happens: the existing key
// is not opened or adopted, and enrollment is not attempted.
func TestRunCreateKeyExistsStopsBeforeEnrollment(t *testing.T) {
	calls := stubCreate(t, func(string, windowscng.KeyPolicy) (windowscng.Signer, error) {
		return nil, keyExistsNative()
	})
	jwtPath, output := runFixture(t)

	err := run(jwtPath, runKeyName, runPolicy, output)
	assertKeyExistsError(t, err)
	if errors.Is(err, windowscng.ErrKeyExists) {
		t.Fatal("native error chain must not be retained")
	}
	if len(*calls) != 1 {
		t.Fatalf("Create calls = %d, want 1", len(*calls))
	}
	assertOutputRemoved(t, output)
}

func TestCreateErrorKeyNotFoundStaysGeneric(t *testing.T) {
	native := fmt.Errorf("key %q: NCryptOpenKey hr=0x80090016: %w", "Keppin.Secret.Key", windowscng.ErrKeyNotFound)
	if isCleanupFailed(native) || isKeyExists(native) {
		t.Fatal("ErrKeyNotFound misclassified")
	}
	err := createError(native)
	assertGenericError(t, err)
	if errors.Is(err, windowscng.ErrKeyNotFound) {
		t.Fatal("native error chain must not be retained")
	}
}
