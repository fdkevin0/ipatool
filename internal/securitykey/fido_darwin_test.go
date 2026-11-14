//go:build darwin && !ios

package securitykey

import (
	"context"
	"errors"
	"testing"
	"time"
)

func fakeDeviceScanner(counts []uintptr) (*fidoLibrary, *int, *int) {
	scans, frees := 0, 0
	f := &fidoLibrary{
		infoNew: func(uintptr) uintptr { return 1 }, infoFree: func(*uintptr, uintptr) { frees++ },
		manifest: func(_ uintptr, _ uintptr, count *uintptr) int {
			*count = counts[min(scans, len(counts)-1)]
			scans++

			return 0
		},
		infoPtr: func(uintptr, uintptr) uintptr { return 2 }, path: func(uintptr) string { return "test-device" },
	}

	return f, &scans, &frees
}

func TestWaitForUSBInsertion(t *testing.T) {
	f, scans, frees := fakeDeviceScanner([]uintptr{0, 1})
	notices := 0
	path, err := f.waitForDevice(context.Background(), Interaction{Status: func(string) { notices++ }})

	if err != nil || path != "test-device" || *scans != 2 || *frees != 2 || notices != 1 {
		t.Fatalf("path=%q err=%v scans=%d frees=%d notices=%d", path, err, *scans, *frees, notices)
	}
}

func TestWaitForUSBStopsOnCancellation(t *testing.T) {
	f, scans, frees := fakeDeviceScanner([]uintptr{0})
	ctx, cancel := context.WithCancel(context.Background())
	f.manifest = func(_ uintptr, _ uintptr, count *uintptr) int {
		*count = 0
		*scans++

		cancel()

		return 0
	}

	_, err := f.waitForDevice(ctx, Interaction{})
	if !errors.Is(err, context.Canceled) || *scans != 1 || *frees != 1 {
		t.Fatalf("err=%v scans=%d frees=%d", err, *scans, *frees)
	}
}

func TestWaitForUSBDeadlineAndMultipleKeys(t *testing.T) {
	f, _, _ := fakeDeviceScanner([]uintptr{0})

	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()

	if _, err := f.waitForDevice(ctx, Interaction{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}

	f, scans, frees := fakeDeviceScanner([]uintptr{2})
	if _, err := f.waitForDevice(context.Background(), Interaction{}); err == nil || *scans != 1 || *frees != 1 {
		t.Fatal("multiple devices were not rejected/cleaned up")
	}
}

func TestAssertionCancellationAndPINFailure(t *testing.T) {
	for _, mode := range []string{"cancel", "incorrect PIN"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()

			f, _, _ := fakeDeviceScanner([]uintptr{1})
			calls, prompts, freed := 0, 0, 0
			cancelled := make(chan struct{})
			cancelReturned := make(chan struct{})
			f.devNew = func() uintptr { return 3 }
			f.open = func(uintptr, string) int { return 0 }
			f.close = func(uintptr) int {
				if mode == "cancel" {
					select {
					case <-cancelReturned:
					default:
						t.Error("device closed before cancellation returned")
					}
				}

				return 0
			}
			f.devFree = func(*uintptr) { freed++ }
			f.timeout = func(uintptr, int) int { return 0 }
			f.assertNew = func() uintptr { return 4 }
			f.assertFree = func(*uintptr) { freed++ }
			f.setRP = func(uintptr, string) int { return 0 }
			f.setHash = func(uintptr, []byte, uintptr) int { return 0 }
			f.setUP = func(uintptr, int) int { return 0 }
			f.cancel = func(uintptr) int {
				defer close(cancelReturned)
				close(cancelled)

				return 0
			}
			f.get = func(_, _ uintptr, pin *byte) int {
				calls++

				if mode == "cancel" {
					cancel()
					<-cancelled

					return -1
				}

				if calls == 1 {
					if pin != nil {
						t.Error("initial assertion unexpectedly supplied a PIN")
					}

					return 0x36 // CTAP2 PIN_REQUIRED.
				}

				if pin == nil || *pin != '1' {
					t.Error("PIN was not passed to the device")
				}

				return 0x31 // CTAP2 PIN_INVALID.
			}

			_, err := f.getAssertion(ctx, challenge{RPID: "apple.com"}, []byte("client data"), Interaction{
				PIN: func(context.Context) (string, error) {
					prompts++

					return "1234", nil
				},
			})
			if err == nil || freed != 2 {
				t.Fatalf("err=%v freed=%d", err, freed)
			}

			if mode == "cancel" {
				if !errors.Is(err, context.Canceled) || calls != 1 || prompts != 0 {
					t.Fatalf("err=%v calls=%d prompts=%d", err, calls, prompts)
				}
			} else if calls != 2 || prompts != 1 {
				t.Fatalf("incorrect PIN was retried: calls=%d prompts=%d", calls, prompts)
			}
		})
	}
}
