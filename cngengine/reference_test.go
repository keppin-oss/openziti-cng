package cngengine

import (
	"net/url"
	"testing"

	"github.com/keppin-oss/openziti-cng/internal/keyref"
)

// TestParseReferenceShapes accepts the Windows Host shape and the net/url
// opaque shape, each with the canonical policy query.
func TestParseReferenceShapes(t *testing.T) {
	want, err := keyref.NewPolicy(keyref.PolicyServiceSigner, "")
	if err != nil {
		t.Fatal(err)
	}
	q := "policy=service-signer"
	for _, u := range []*url.URL{
		{Scheme: EngineId, Host: "keppin-oz-001", RawQuery: q},
		{Scheme: EngineId, Opaque: "keppin-oz-001", RawQuery: q},
	} {
		got, err := parseReference(u)
		if err != nil || got.Name != "keppin-oz-001" || got.Policy != want {
			t.Fatalf("parseReference(%#v) = %+v, %v", u, got, err)
		}
	}
}

func TestParseReferenceRejectsInvalid(t *testing.T) {
	q := "policy=service-signer"
	for _, u := range []*url.URL{
		nil,
		{Scheme: EngineId},
		{Scheme: EngineId, Host: "keppin-oz-001"},
		{Scheme: EngineId, Opaque: "keppin-oz-001?"},
		{Scheme: EngineId, Host: "  ", RawQuery: q},
		{Scheme: EngineId, Opaque: "?scope=machine"},
		{Scheme: EngineId, Host: "name", RawQuery: "scope=machine"},
		{Scheme: EngineId, Host: "-----BEGIN EC PRIVATE KEY-----", RawQuery: q},
		{Scheme: EngineId, Path: "name", RawQuery: q},
	} {
		if _, err := parseReference(u); err == nil {
			t.Fatalf("accepted invalid reference %#v", u)
		}
	}
}
