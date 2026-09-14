package cngengine

import (
	"net/url"
	"testing"
)

func TestParseReferenceShapes(t *testing.T) {
	for _, u := range []*url.URL{{Scheme: EngineId, Host: "keppin-oz-001"}, {Scheme: EngineId, Opaque: "keppin-oz-001"}, {Scheme: EngineId, Opaque: "keppin-oz-001?"}} {
		got, err := parseReference(u)
		if err != nil || got != "keppin-oz-001" {
			t.Fatalf("parseReference failed: %v", err)
		}
	}
}
func TestParseReferenceRejectsInvalid(t *testing.T) {
	for _, u := range []*url.URL{nil, {Scheme: EngineId}, {Scheme: EngineId, Host: "  "}, {Scheme: EngineId, Opaque: "?scope=machine"}, {Scheme: EngineId, Host: "name", RawQuery: "scope=machine"}, {Scheme: EngineId, Host: "-----BEGIN EC PRIVATE KEY-----"}, {Scheme: EngineId, Path: "name"}} {
		if _, err := parseReference(u); err == nil {
			t.Fatal("accepted invalid reference")
		}
	}
}
