//go:build !windows

package cngengine

import (
	"github.com/keppin-oss/cng/windowscng"
	"testing"
)

func TestLoadKeyPlatformUnsupported(t *testing.T) {
	_, want := windowscng.Open("Test", windowscng.PolicyServiceSigner)
	_, got := loadKeyForTest(t, "cng:Test?policy=service-signer")
	if got == nil || want == nil || got.Error() != want.Error() {
		t.Fatalf("expected CNG platform error, got %v", got)
	}
}
