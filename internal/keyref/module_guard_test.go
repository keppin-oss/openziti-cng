package keyref

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoRemovedKeyEntryPointsInModuleSource keeps removed key entry points out
// of the module: no non-test Go file of the module, examples included, may
// contain one of the forbidden terms in any letter case, in code or in
// comments.
//
//   - "loadorcreate": opening and creating are separate operations, and a
//     failed open must never lead to a create (cng v0.5.0 removed the
//     load-or-create functions).
//   - "certreq": this module never delegates key or certificate requests to
//     certreq.exe. It has never used it; the term is forbidden as prevention.
//
// Test files are not scanned: they may name the terms on purpose.
func TestNoRemovedKeyEntryPointsInModuleSource(t *testing.T) {
	forbidden := []string{"loadorcreate", "certreq"}
	root := filepath.Join("..", "..")
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("module root not found from the keyref package: %v", err)
	}
	scanned := 0
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if path != root && (strings.HasPrefix(name, ".") || name == "graphify-out" || name == "testdata") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		scanned++
		src := strings.ToLower(string(data))
		for _, term := range forbidden {
			if strings.Contains(src, term) {
				t.Errorf("%s contains the forbidden term %q", filepath.ToSlash(path), term)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if scanned == 0 {
		t.Fatal("no module Go source files scanned")
	}
}
