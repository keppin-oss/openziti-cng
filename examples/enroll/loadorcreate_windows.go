//go:build windows

package main

import (
	"errors"

	"github.com/keppin-oss/cng/windowscng"
)

// isCleanupFailed reports whether a windowscng.LoadOrCreate failure carries
// windowscng.ErrCleanupFailed: a newly created key failed validation and could
// not be deleted, so it may still be persisted.
func isCleanupFailed(err error) bool {
	return errors.Is(err, windowscng.ErrCleanupFailed)
}
