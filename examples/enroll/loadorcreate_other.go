//go:build !windows

package main

// isCleanupFailed is always false off Windows: windowscng.ErrCleanupFailed is
// not declared there and windowscng.LoadOrCreate only reports that CNG is not
// supported, so no key can have been created. Every failure stays generic.
func isCleanupFailed(error) bool {
	return false
}
