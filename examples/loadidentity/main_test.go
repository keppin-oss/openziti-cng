package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRejectPrivateOrNoncanonicalKeyWithoutOutput(t *testing.T) {
	for _, ref := range []string{"pem:-----BEGIN PRIVATE KEY----- SECRET", "file:SECRET", "cng:name", "cng:name?token=SECRET", "cng://SECRET?"} {
		path := filepath.Join(t.TempDir(), "identity.json")
		data, _ := json.Marshal(map[string]any{"id": map[string]string{"key": ref}})
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		var output bytes.Buffer
		err := run(path, &output)
		if err == nil {
			t.Fatal("invalid identity accepted")
		}
		if output.Len() != 0 || strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), "PRIVATE KEY") {
			t.Fatal("identity material disclosed")
		}
	}
}
