// Package keyref defines the shared, deliberately restricted CNG reference grammar.
package keyref

import (
	"errors"
	"net/url"
	"strings"
)

// ValidateName accepts ASCII letters/digits followed by letters/digits, dot,
// underscore or hyphen, up to 128 bytes. It never normalizes a name.
func ValidateName(name string) error {
	if len(name) == 0 || len(name) > 128 {
		return errors.New("CNG name must contain 1 to 128 ASCII characters")
	}
	for i, c := range []byte(name) {
		alphaNum := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
		if !alphaNum && (i == 0 || c != '.' && c != '_' && c != '-') {
			return errors.New("CNG name must start with an ASCII letter or digit and contain only letters, digits, dot, underscore or hyphen")
		}
	}
	return nil
}

func Format(name string) (string, error) {
	if err := ValidateName(name); err != nil {
		return "", err
	}
	return "cng:" + name + "?", nil
}

// Parse accepts only the canonical form, before OpenZiti's Windows parser runs.
func Parse(ref string) (string, error) {
	if !strings.HasPrefix(ref, "cng:") || !strings.HasSuffix(ref, "?") {
		return "", errors.New("expected canonical CNG reference cng:<name>?")
	}
	name := strings.TrimSuffix(strings.TrimPrefix(ref, "cng:"), "?")
	if err := ValidateName(name); err != nil {
		return "", err
	}
	return name, nil
}

// FromURL supports the pinned Windows Host shape and net/url's opaque shape.
// The Windows parser has already consumed the required question mark.
func FromURL(u *url.URL) (string, error) {
	if u == nil || u.Scheme != "cng" || u.User != nil || u.RawQuery != "" ||
		u.Fragment != "" || u.RawFragment != "" || u.Path != "" || u.RawPath != "" {
		return "", errors.New("invalid CNG reference")
	}
	name := u.Host
	if u.Opaque != "" {
		if name != "" {
			return "", errors.New("ambiguous CNG reference")
		}
		name = strings.TrimSuffix(u.Opaque, "?")
	}
	if err := ValidateName(name); err != nil {
		return "", err
	}
	return name, nil
}
