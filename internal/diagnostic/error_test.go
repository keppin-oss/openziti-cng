package diagnostic

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
)

func TestSafeErrorDoesNotRetainSecrets(t *testing.T) {
	for _, cause := range []error{
		&url.Error{Op: "Post", URL: "https://controller/enroll?token=SECRET", Err: errors.New("RESPONSE_PRIVATE")},
		fmt.Errorf("JWT_PRIVATE: %w", errors.New("-----BEGIN PRIVATE KEY-----")),
		&url.Error{Op: "Post", URL: "https://controller/enroll?token=SECRET", Err: os.ErrDeadlineExceeded},
	} {
		err := Safe("enroll", cause)
		for _, format := range []string{"%s", "%v", "%+v", "%#v"} {
			rendered := fmt.Sprintf(format, err)
			for _, secret := range []string{"SECRET", "PRIVATE", "https://"} {
				if strings.Contains(rendered, secret) {
					t.Fatal("secret retained in safe error")
				}
			}
		}
		if errors.Unwrap(err) != nil {
			t.Fatal("raw error remains reachable")
		}
	}
	if Safe("enroll", nil) != nil {
		t.Fatal("nil should remain nil")
	}
	if !strings.Contains(Safe("enroll", os.ErrDeadlineExceeded).Error(), "timeout") {
		t.Fatal("lost useful timeout category")
	}
}
