package enrollcng

import (
	"fmt"
	"os"
	"strings"
)

// loadOTTJWT resolves an OTT JWT source value that may be either a filesystem
// path or the raw JWT string.
//
// A value that clearly names a filesystem path is read from disk; a read
// failure is surfaced explicitly instead of being silently reinterpreted as a
// malformed raw JWT. A value that is not path-like is returned verbatim as the
// raw JWT.
func loadOTTJWT(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("enrollcng: OTT JWT source is empty")
	}

	if looksLikePath(raw) {
		data, err := os.ReadFile(raw)
		if err != nil {
			return "", fmt.Errorf("enrollcng: reading OTT JWT file %q: %w", raw, err)
		}
		return strings.TrimSpace(string(data)), nil
	}

	return raw, nil
}

// looksLikePath reports whether a value clearly names a filesystem path rather
// than an inline JWT: it contains a path separator or carries a .jwt extension.
func looksLikePath(raw string) bool {
	return strings.ContainsAny(raw, `/\`) || strings.HasSuffix(strings.ToLower(raw), ".jwt")
}



