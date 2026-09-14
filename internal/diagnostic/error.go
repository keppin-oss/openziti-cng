// Package diagnostic provides errors safe to print at identity boundaries.
package diagnostic

import (
	"errors"
	"fmt"
	"net"
)

// Safe deliberately does not retain or wrap the original error: it may contain
// an enrollment token, identity material, a URL or a controller response body.
func Safe(stage string, err error) error {
	if err == nil {
		return nil
	}
	category := "operation failed"
	var networkError net.Error
	if errors.As(err, &networkError) {
		category = "network failure"
		if networkError.Timeout() {
			category = "network timeout"
		}
	}
	return fmt.Errorf("%s: %s (sensitive details withheld)", stage, category)
}
