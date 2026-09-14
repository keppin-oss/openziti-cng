//go:build !windows

package cngengine

import (
	"github.com/keppin-oss/cng/windowscng"
	"testing"
)

func TestLoadKeyPlatformUnsupported(t *testing.T) {
	_, want := windowscng.Open("Test")
	_, got := loadKeyForTest(t, "cng:Test?")
	if got == nil || want == nil || got.Error() != want.Error() {
		t.Fatalf("expected CNG platform error, got %v", got)
	}
}
