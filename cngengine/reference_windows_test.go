//go:build windows

package cngengine

import (
	"testing"

	"github.com/openziti/identity"
)

// TestReferenceRequiresQueryDelimiter documents a concrete limitation of
// github.com/openziti/identity v1.0.140: on Windows, identity.parseAddr
// (address_windows.go) unconditionally indexes pathAndArgs[1] after splitting
// the address on '?'. A CNG reference without a '?' therefore panics before it
// reaches any engine.
//
// The canonical reference format is therefore "cng:<container-name>?" (a
// trailing '?' with an empty query). This test locks in that requirement so a
// future identity upgrade that fixes the parseAddr panic is detected.
func TestReferenceRequiresQueryDelimiter(t *testing.T) {
	t.Run("missing question mark panics", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("identity.LoadKey of a cng reference without '?' should panic on Windows")
			}
		}()
		_, _ = identity.LoadKey("cng:keppin-oz-noquery")
	})

	t.Run("trailing question mark does not panic", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("canonical reference must not panic, got: %v", r)
			}
		}()
		_, _ = identity.LoadKey("cng:keppin-oz-noquery?")
	})
}



