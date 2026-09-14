package keyref

import (
	"net/url"
	"strings"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	for _, name := range []string{"A", "Keppin.Test-001_key", strings.Repeat("a", 128)} {
		ref, err := Format(name)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Parse(ref)
		if err != nil || got != name {
			t.Fatalf("canonical round trip failed: %v", err)
		}
		u, err := url.Parse(ref)
		if err != nil {
			t.Fatal(err)
		}
		got, err = FromURL(u)
		if err != nil || got != name {
			t.Fatalf("net/url round trip failed: %v", err)
		}
		got, err = FromURL(&url.URL{Scheme: "cng", Host: name})
		if err != nil || got != name {
			t.Fatalf("Windows round trip failed: %v", err)
		}
	}
}
func TestRejectAmbiguousNames(t *testing.T) {
	for _, name := range []string{"", " name", "name ", "a b", "//name", "/name", "a/b", "a\\b", "a:b", "a?b", "a#b", "a%b", "a@b", "a\x00b", "a\nb", "é", ".name", "-name", strings.Repeat("a", 129)} {
		if _, err := Format(name); err == nil {
			t.Errorf("accepted invalid name %q", name)
		}
	}
}
func TestRejectNoncanonicalReferences(t *testing.T) {
	for _, ref := range []string{"pem:PRIVATE", "file:key", "cng:name", "CNG:name?", "cng://name?", "cng:name?token=SECRET", "cng:name??", "cng:name?#frag", "cng:name%20?", " cng:name?"} {
		if _, err := Parse(ref); err == nil {
			t.Errorf("accepted invalid reference %q", ref)
		}
	}
}
func TestRejectURLAmbiguities(t *testing.T) {
	for _, u := range []*url.URL{nil, {Scheme: "file", Host: "name"}, {Scheme: "cng", Host: "name", Opaque: "other"}, {Scheme: "cng", Host: "name", Path: "/other"}, {Scheme: "cng", Host: "name", RawQuery: "token=secret"}, {Scheme: "cng", Host: "name", User: url.User("user")}, {Scheme: "cng", Host: "name", Fragment: "secret"}} {
		if _, err := FromURL(u); err == nil {
			t.Error("accepted ambiguous URL")
		}
	}
}
