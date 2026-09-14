//go:build !windows

package enrollcng

import (
	"os"
	"strings"
	"testing"
)

func TestEnrollRejectsNonWindowsFileRouting(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.WriteFile("cng:Test?", []byte("PRIVATE_FILE_MATERIAL"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := Enroll("UNTRUSTED_TOKEN", "Test")
	if err == nil || !strings.Contains(err.Error(), "requires Windows") {
		t.Fatalf("expected early platform rejection, got %v", err)
	}
}
