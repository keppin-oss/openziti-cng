//go:build windows

package main

import (
	"errors"

	"github.com/keppin-oss/cng/windowscng"
)

// isCleanupFailed reports whether a windowscng.Create failure carries
// windowscng.ErrCleanupFailed: a step after creating the new key failed (for
// example finalization, the policy check or public-key export) and the key
// could not be deleted through its handle, so it may still be persisted.
func isCleanupFailed(err error) bool {
	return errors.Is(err, windowscng.ErrCleanupFailed)
}

// isKeyExists reports whether a windowscng.Create failure carries
// windowscng.ErrKeyExists: a key is already persisted under the name. Create
// did not open, adopt, modify or delete it.
func isKeyExists(err error) bool {
	return errors.Is(err, windowscng.ErrKeyExists)
}
