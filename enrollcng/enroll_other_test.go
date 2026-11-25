//go:build !windows

package enrollcng

import (
	"os"
	"strings"
	"testing"

	"github.com/keppin-oss/cng/windowscng"
)

// TestEnrollRejectsNonWindowsFileRouting: on Unix the canonical reference is a
// valid file name. Even when a file with exactly that name exists, Enroll must
// stop before the SDK could route the reference to it as a key file.
func TestEnrollRejectsNonWindowsFileRouting(t *testing.T) {
	t.Chdir(t.TempDir())
	ref, err := KeyReference("Test", windowscng.PolicyServiceSigner)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ref, []byte("PRIVATE_FILE_MATERIAL"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err = Enroll("UNTRUSTED_TOKEN", "Test", windowscng.PolicyServiceSigner)
	if err == nil || !strings.Contains(err.Error(), "requires Windows") {
		t.Fatalf("expected early platform rejection, got %v", err)
	}
}
