//go:build !windows

package main

// isCleanupFailed is always false off Windows: windowscng.Create only reports
// that CNG is not supported there (windowscng.ErrCleanupFailed is declared on
// every platform, but never returned), so no key can have been created. Every
// failure stays generic.
func isCleanupFailed(error) bool {
	return false
}

// isKeyExists is always false off Windows for the same reason: no key store is
// reached, so windowscng.ErrKeyExists is never returned.
func isKeyExists(error) bool {
	return false
}
