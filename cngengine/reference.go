package cngengine

import (
	"errors"
	"net/url"
	"strings"
)

// parseReference extracts the CNG container name from an OpenZiti key URL.
//
// The reference carries only the container identity — never private key bytes.
// OpenZiti's identity package hands the engine the parsed *url.URL for the key
// address. The exact URL shape differs by platform:
//
//   - On Windows, identity.parseAddr (address_windows.go) places the container
//     name in url.Host and any query string in url.RawQuery.
//   - On non-Windows, identity.parseAddr (address.go) uses net/url.Parse, which
//     places an opaque reference (including any "?query" suffix) in url.Opaque.
//
// The engine accepts both shapes and never falls back to treating the reference
// as PEM or file material.
func parseReference(u *url.URL) (string, error) {
	if u == nil {
		return "", errors.New("cngengine: nil key reference")
	}

	name := u.Host
	if name == "" {
		name = u.Opaque
	}
	if name == "" {
		name = u.Path
	}

	// net/url.Parse keeps a "?query" suffix inside Opaque; strip it so the
	// container name is the exact CNG key name.
	if i := strings.IndexByte(name, '?'); i >= 0 {
		name = name[:i]
	}

	name = strings.TrimSpace(name)
	if name == "" {
		return "", errors.New("cngengine: key reference is missing a CNG container name")
	}

	return name, nil
}



