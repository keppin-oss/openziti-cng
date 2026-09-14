package cngengine

import (
	"github.com/keppin-oss/openziti-cng/internal/keyref"
	"net/url"
)

// parseReference accepts the pinned identity Windows shape and net/url opaque
// shape. Names are validated without trimming, decoding or query stripping.
func parseReference(u *url.URL) (string, error) { return keyref.FromURL(u) }
