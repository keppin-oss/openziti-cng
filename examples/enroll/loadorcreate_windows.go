//go:build windows

package main

import (
	"errors"

	"github.com/keppin-oss/cng/windowscng"
)

// isCleanupFailed reports whether a windowscng.LoadOrCreate failure carries
// windowscng.ErrCleanupFailed: a step after creating a new key failed (for
// example finalization, validation or, since CNG v0.2.2, building the signer,
// including public-key export) and the key could not be deleted, so it may
// still be persisted.
func isCleanupFailed(err error) bool {
	return errors.Is(err, windowscng.ErrCleanupFailed)
}
