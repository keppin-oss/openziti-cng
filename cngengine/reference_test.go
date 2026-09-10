package cngengine

import (
	"net/url"
	"strings"
	"testing"
)

func TestParseReferenceWindowsShape(t *testing.T) {
	// identity.parseAddr on Windows (address_windows.go) yields
	// {Scheme:"cng", Host:"name", RawQuery:"..."}.
	u := &url.URL{Scheme: EngineId, Host: "keppin-oz-001", RawQuery: ""}
	got, err := parseReference(u)
	if err != nil {
		t.Fatalf("parseReference: %v", err)
	}
	if got != "keppin-oz-001" {
		t.Fatalf("parseReference = %q, want %q", got, "keppin-oz-001")
	}
}

func TestParseReferenceStripsHostDoubleSlash(t *testing.T) {
	u := &url.URL{Scheme: EngineId, Host: "keppin-oz-001", RawQuery: "scope=machine"}
	got, err := parseReference(u)
	if err != nil {
		t.Fatalf("parseReference: %v", err)
	}
	if got != "keppin-oz-001" {
		t.Fatalf("parseReference = %q, want %q", got, "keppin-oz-001")
	}
}

func TestParseReferenceNonWindowsOpaqueShape(t *testing.T) {
	// net/url.Parse("cng:keppin-oz-001?scope=machine") on non-Windows yields an
	// Opaque field that includes the query suffix.
	u := &url.URL{Scheme: EngineId, Opaque: "keppin-oz-001?scope=machine"}
	got, err := parseReference(u)
	if err != nil {
		t.Fatalf("parseReference: %v", err)
	}
	if got != "keppin-oz-001" {
		t.Fatalf("parseReference = %q, want %q", got, "keppin-oz-001")
	}
}

func TestParseReferenceRejectsNil(t *testing.T) {
	if _, err := parseReference(nil); err == nil {
		t.Fatal("parseReference(nil) must fail")
	}
}

func TestParseReferenceRejectsEmpty(t *testing.T) {
	for _, u := range []*url.URL{
		{Scheme: EngineId},
		{Scheme: EngineId, Host: "  "},
		{Scheme: EngineId, Opaque: "?scope=machine"},
	} {
		if _, err := parseReference(u); err == nil {
			t.Fatalf("parseReference(%+v) must fail for an empty name", u)
		}
	}
}

func TestParseReferenceNoPEMFallback(t *testing.T) {
	// A container name that looks like PEM material must be treated as a plain
	// CNG container name, never decoded as a key.
	pemLike := "-----BEGIN EC PRIVATE KEY-----"
	u := &url.URL{Scheme: EngineId, Host: pemLike}
	got, err := parseReference(u)
	if err != nil {
		t.Fatalf("parseReference: %v", err)
	}
	if got != pemLike {
		t.Fatalf("parseReference = %q, want the literal container name %q", got, pemLike)
	}
	if strings.Contains(got, "BEGIN") == false {
		t.Fatal("expected the container name to be preserved verbatim")
	}
}



