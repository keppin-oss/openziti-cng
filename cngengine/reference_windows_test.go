//go:build windows

package cngengine

import (
	"testing"
)

// TestReferenceRequiresQueryDelimiter documents a concrete limitation of
// github.com/openziti/identity v1.0.140: on Windows, identity.parseAddr
// (address_windows.go) unconditionally indexes pathAndArgs[1] after splitting
// the address on '?'. A CNG reference without a '?' therefore panics before it
// reaches any engine.
//
// Every canonical reference therefore carries a '?': it introduces the
// mandatory policy query ("cng:<container-name>?policy=..."). This test locks
// in the parser behavior so a future identity upgrade that changes it is
// detected.
func TestReferenceRequiresQueryDelimiter(t *testing.T) {
	t.Run("missing question mark panics", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("identity.LoadKey of a cng reference without '?' should panic on Windows")
			}
		}()
		_, _ = loadKeyForTest(t, "cng:keppin-oz-noquery")
	})

	t.Run("canonical policy query does not panic", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("canonical reference must not panic, got: %v", r)
			}
		}()
		_, _ = loadKeyForTest(t, "cng:keppin-oz-noquery?policy=service-signer")
	})
}
