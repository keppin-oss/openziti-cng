package enrollcng

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadOTTJWTRawJWT(t *testing.T) {
	raw := "eyJhbGciOiJub25lIn0.eyJpc3MiOiJodHRwczovL2NvbnRyb2xsZXIifQ.signature"
	got, err := loadOTTJWT(raw)
	if err != nil {
		t.Fatalf("loadOTTJWT: %v", err)
	}
	if got != raw {
		t.Fatalf("loadOTTJWT = %q, want the raw JWT unchanged", got)
	}
}

func TestLoadOTTJWTReadsFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keppin-oss-cng-test.jwt")
	want := "eyJhbGciOiJub25lIn0.eyJpc3MiOiJodHRwczovL2NvbnRyb2xsZXIifQ.signature"
	if err := os.WriteFile(path, []byte(want+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	got, err := loadOTTJWT(path)
	if err != nil {
		t.Fatalf("loadOTTJWT: %v", err)
	}
	if got != want {
		t.Fatalf("loadOTTJWT = %q, want %q", got, want)
	}
}

func TestLoadOTTJWTMissingFileFailsExplicitly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.jwt")
	_, err := loadOTTJWT(path)
	if err == nil {
		t.Fatal("loadOTTJWT must fail when a path-like value names a missing file")
	}
	if !strings.Contains(err.Error(), path) {
		t.Fatalf("error %q must mention the path %q", err.Error(), path)
	}
}

func TestLoadOTTJWTEmptyFails(t *testing.T) {
	if _, err := loadOTTJWT(""); err == nil {
		t.Fatal("loadOTTJWT with empty source must fail")
	}
	if _, err := loadOTTJWT("   "); err == nil {
		t.Fatal("loadOTTJWT with whitespace source must fail")
	}
}

func TestLooksLikePath(t *testing.T) {
	pathLike := []string{
		`C:\tmp\keppin-oss-cng-test.jwt`,
		`C:\tmp\keppin-oss-cng-test`,
		`keppin-oss-cng-test.jwt`,
		`.\keppin-oss-cng-test.jwt`,
		`/tmp/keppin-oss-cng-test.jwt`,
	}
	for _, v := range pathLike {
		if !looksLikePath(v) {
			t.Errorf("looksLikePath(%q) = false, want true", v)
		}
	}

	rawJWT := []string{
		"eyJhbGciOiJub25lIn0.eyJpc3MiOiJodHRwczovL2NvbnRyb2xsZXIifQ.signature",
		"a.b.c",
	}
	for _, v := range rawJWT {
		if looksLikePath(v) {
			t.Errorf("looksLikePath(%q) = true, want false (raw JWT)", v)
		}
	}
}



