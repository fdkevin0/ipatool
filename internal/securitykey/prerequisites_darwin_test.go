//go:build darwin && !ios

package securitykey

import (
	"context"
	"os"
	"testing"
)

// Opt-in service/libfido2 check; does not log in, open a key or print headers.
func TestLocalSecurityKeyPrerequisites(t *testing.T) {
	if os.Getenv("IPATOOL_TEST_LOCAL_SECURITY_KEY") != "1" {
		t.Skip("local macOS smoke check is opt-in")
	}

	if err := CheckSupport(); err != nil {
		t.Fatal(err)
	}

	if _, err := Headers(context.Background(), os.Getenv("IPATOOL_TEST_ANISETTE_URL")); err != nil {
		t.Fatal(err)
	}
}
