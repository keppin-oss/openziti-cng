package cngengine

import (
	"github.com/keppin-oss/openziti-cng/internal/keyref"
	"net/url"
)

// parseReference accepts the pinned identity Windows shape and the net/url
// opaque shape, each with the canonical policy query. Names and queries are
// validated without trimming, decoding or query stripping.
func parseReference(u *url.URL) (keyref.Reference, error) { return keyref.FromURL(u) }
