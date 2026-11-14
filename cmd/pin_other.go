//go:build !darwin

package cmd

import (
	"context"
	"errors"
)

func readPIN(context.Context) (string, error) {
	return "", errors.New("security-key PIN input requires macOS")
}
