//go:build !windows

package main

// isCleanupFailed is always false off Windows: windowscng.LoadOrCreate only
// reports that CNG is not supported there (windowscng.ErrCleanupFailed is
// declared on every platform since CNG v0.3.0, but never returned), so no key
// can have been created. Every failure stays generic.
func isCleanupFailed(error) bool {
	return false
}
