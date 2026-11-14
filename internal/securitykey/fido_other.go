//go:build !darwin || ios

package securitykey

import (
	"context"
	"errors"
)

func CheckSupport() error {
	return errors.New("experimental security-key login currently requires macOS")
}
func getAssertion(context.Context, challenge, []byte, Interaction) (assertion, error) {
	return assertion{}, CheckSupport()
}
