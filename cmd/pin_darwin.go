//go:build darwin

package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

func readPIN(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("read PIN: %w", err)
	}
	// A separate nonblocking descriptor avoids changing stdin or leaving a reader behind.
	fd, err := unix.Open("/dev/tty", unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", fmt.Errorf("open PIN terminal: %w", err)
	}

	defer unix.Close(fd)

	state, err := term.MakeRaw(fd)
	if err != nil {
		return "", fmt.Errorf("configure PIN terminal: %w", err)
	}

	// Match the existing password prompt: restore the terminal on every exit.
	defer term.Restore(fd, state) //nolint:errcheck

	if _, err := io.WriteString(os.Stderr, "enter security-key PIN (local only): "); err != nil {
		return "", fmt.Errorf("write PIN prompt: %w", err)
	}

	defer fmt.Fprint(os.Stderr, "\r\n")

	return readMaskedInput(pinReader{ctx, fd}, os.Stderr)
}

type pinReader struct {
	ctx context.Context
	fd  int
}

func (r pinReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	for {
		if err := r.ctx.Err(); err != nil {
			return 0, fmt.Errorf("read PIN: %w", err)
		}

		fds := []unix.PollFd{{Fd: int32(r.fd), Events: unix.POLLIN}}
		if _, err := unix.Poll(fds, 50); err != nil && !errors.Is(err, unix.EINTR) {
			return 0, fmt.Errorf("poll PIN terminal: %w", err)
		}

		if err := r.ctx.Err(); err != nil {
			return 0, fmt.Errorf("read PIN: %w", err)
		}

		if fds[0].Revents == 0 {
			continue
		}
		// Read one byte so Enter never consumes input belonging to a later prompt.
		n, err := unix.Read(r.fd, p[:1])
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
			continue
		}

		if n == 0 && err == nil {
			return 0, io.EOF
		}

		if err != nil {
			return n, fmt.Errorf("read PIN terminal: %w", err)
		}

		return n, nil
	}
}
