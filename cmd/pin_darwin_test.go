//go:build darwin

package cmd

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestPINInputCancellation(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		var fds [2]int
		if err := unix.Pipe(fds[:]); err != nil {
			t.Fatal(err)
		}

		func() {
			defer unix.Close(fds[0])
			defer unix.Close(fds[1])

			ctx, cancel := context.WithCancel(context.Background())
			want := context.Canceled

			if deadline {
				ctx, cancel = context.WithTimeout(context.Background(), 20*time.Millisecond)
				want = context.DeadlineExceeded
			}

			defer cancel()

			done := make(chan error, 1)

			go func() { _, err := readMaskedInput(pinReader{ctx, fds[0]}, io.Discard); done <- err }()

			if !deadline {
				time.AfterFunc(20*time.Millisecond, cancel)
			}
			select {
			case err := <-done:
				if !errors.Is(err, want) {
					t.Fatalf("got %v, want %v", err, want)
				}
			case <-time.After(time.Second):
				t.Fatal("PIN input did not stop")
			}
			// Cancellation leaves no background reader consuming the next prompt's input.
			if _, err := unix.Write(fds[1], []byte("1234\n")); err != nil {
				t.Fatal(err)
			}

			value, err := readMaskedInput(pinReader{context.Background(), fds[0]}, io.Discard)
			if err != nil || value != "1234" {
				t.Fatalf("next input = %q, %v", value, err)
			}
		}()
	}
}
