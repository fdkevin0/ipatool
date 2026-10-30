//go:build darwin && !ios

package securitykey

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"github.com/ebitengine/purego"
)

type fidoLibrary struct {
	handle                          uintptr
	init                            func(int)
	strerr                          func(int) string
	infoNew                         func(uintptr) uintptr
	infoFree                        func(*uintptr, uintptr)
	manifest                        func(uintptr, uintptr, *uintptr) int
	infoPtr                         func(uintptr, uintptr) uintptr
	path                            func(uintptr) string
	devNew                          func() uintptr
	devFree                         func(*uintptr)
	open                            func(uintptr, string) int
	close                           func(uintptr) int
	timeout                         func(uintptr, int) int
	cancel                          func(uintptr) int
	assertNew                       func() uintptr
	assertFree                      func(*uintptr)
	setRP                           func(uintptr, string) int
	setHash                         func(uintptr, []byte, uintptr) int
	allow                           func(uintptr, []byte, uintptr) int
	setUP                           func(uintptr, int) int
	get                             func(uintptr, uintptr, *byte) int
	authPtr, sigPtr, idPtr, userPtr func(uintptr, uintptr) unsafe.Pointer
	authLen, sigLen, idLen, userLen func(uintptr, uintptr) uintptr
}

var loadFIDO = sync.OnceValues(openFIDO)

func openFIDO() (*fidoLibrary, error) {
	f := &fidoLibrary{}

	for _, path := range []string{"/opt/homebrew/lib/libfido2.dylib", "/usr/local/lib/libfido2.dylib"} {
		handle, err := purego.Dlopen(path, purego.RTLD_NOW|purego.RTLD_LOCAL)
		if err == nil {
			f.handle = handle

			break
		}
	}

	if f.handle == 0 {
		return nil, errors.New("libfido2 is required: install it with brew install libfido2")
	}

	symbols := map[string]any{
		"fido_init": &f.init, "fido_strerr": &f.strerr, "fido_dev_info_new": &f.infoNew, "fido_dev_info_free": &f.infoFree, "fido_dev_info_manifest": &f.manifest, "fido_dev_info_ptr": &f.infoPtr, "fido_dev_info_path": &f.path,
		"fido_dev_new": &f.devNew, "fido_dev_free": &f.devFree, "fido_dev_open": &f.open, "fido_dev_close": &f.close, "fido_dev_set_timeout": &f.timeout, "fido_dev_cancel": &f.cancel,
		"fido_assert_new": &f.assertNew, "fido_assert_free": &f.assertFree, "fido_assert_set_rp": &f.setRP, "fido_assert_set_clientdata_hash": &f.setHash, "fido_assert_allow_cred": &f.allow, "fido_assert_set_up": &f.setUP, "fido_dev_get_assert": &f.get,
		"fido_assert_authdata_raw_ptr": &f.authPtr, "fido_assert_authdata_raw_len": &f.authLen, "fido_assert_sig_ptr": &f.sigPtr, "fido_assert_sig_len": &f.sigLen, "fido_assert_id_ptr": &f.idPtr, "fido_assert_id_len": &f.idLen, "fido_assert_user_id_ptr": &f.userPtr, "fido_assert_user_id_len": &f.userLen,
	}
	for name, target := range symbols {
		address, err := purego.Dlsym(f.handle, name)
		if err != nil {
			purego.Dlclose(f.handle)

			return nil, fmt.Errorf("libfido2 is missing %s; upgrade libfido2", name)
		}

		purego.RegisterFunc(target, address)
	}

	f.init(0)

	return f, nil
}

func CheckSupport() error {
	_, err := loadFIDO()

	return err
}

func getAssertion(ctx context.Context, c challenge, data []byte, i Interaction) (assertion, error) {
	f, err := loadFIDO()
	if err != nil {
		return assertion{}, err
	}

	return f.getAssertion(ctx, c, data, i)
}

func (f *fidoLibrary) getAssertion(ctx context.Context, c challenge, data []byte, i Interaction) (assertion, error) {
	path, err := f.waitForDevice(ctx, i)
	if err != nil {
		return assertion{}, err
	}

	dev := f.devNew()
	if dev == 0 {
		return assertion{}, errors.New("cannot allocate security-key device")
	}

	defer f.devFree(&dev)

	if code := f.open(dev, path); code != 0 {
		return assertion{}, fmt.Errorf("open security key: libfido2 code %d", code)
	}

	defer f.close(dev)

	if code := f.timeout(dev, 60000); code != 0 {
		return assertion{}, fmt.Errorf("set security-key timeout: libfido2 code %d", code)
	}

	a := f.assertNew()
	if a == 0 {
		return assertion{}, errors.New("cannot allocate security-key assertion")
	}

	defer f.assertFree(&a)

	hash := sha256.Sum256(data)
	if f.setRP(a, c.RPID) != 0 || f.setHash(a, hash[:], uintptr(len(hash))) != 0 || f.setUP(a, 2) != 0 {
		return assertion{}, errors.New("cannot configure security-key assertion")
	}

	for _, id := range c.KeyHandles {
		raw, err := decodeBase64(id)
		if err != nil {
			return assertion{}, err
		}

		if f.allow(a, raw, uintptr(len(raw))) != 0 {
			return assertion{}, errors.New("cannot set security-key allowed credential")
		}
	}

	call := func(pin *byte) int {
		if ctx.Err() != nil {
			return -1
		}

		done, exited := make(chan struct{}), make(chan struct{})

		go func() {
			defer close(exited)
			select {
			case <-ctx.Done():
				_ = f.timeout(dev, 1000)
				f.cancel(dev)
			case <-done:
			}
		}()

		code := f.get(dev, a, pin)

		close(done)
		<-exited

		return code
	}

	i.status("security-key: checking USB security key (touch if prompted; 60 second timeout)")

	code := call(nil)
	usedPIN := false
	// CTAP2 PIN_REQUIRED. Never retry an incorrect PIN automatically.
	if code == 0x36 {
		if i.PIN == nil {
			return assertion{}, errors.New("security key requires a PIN; interactive login is required")
		}

		pin, err := i.PIN(ctx)
		if err != nil {
			return assertion{}, err
		}

		if len(pin) == 0 || len(pin) > 63 {
			return assertion{}, errors.New("invalid security-key PIN length")
		}

		for _, c := range pin {
			if c == 0 {
				return assertion{}, errors.New("invalid security-key PIN")
			}
		}

		buffer := append([]byte(pin), 0)
		usedPIN = true

		i.status("security-key: touch your USB security key to finish verification")

		code = call(&buffer[0])
		runtime.KeepAlive(buffer)
		clear(buffer)
	}

	if ctx.Err() != nil {
		return assertion{}, fmt.Errorf("security-key assertion cancelled: %w", ctx.Err())
	}

	if code != 0 {
		detail := fmt.Sprintf("libfido2 code %d", code)
		if f.strerr != nil {
			if text := f.strerr(code); text != "" {
				detail = fmt.Sprintf("%s (%s)", text, detail)
			}
		}

		if usedPIN {
			return assertion{}, fmt.Errorf("security-key assertion failed (%s); no PIN retry was attempted", detail)
		}

		return assertion{}, fmt.Errorf("security-key assertion failed (%s)", detail)
	}

	copyField := func(ptr unsafe.Pointer, length uintptr) ([]byte, error) {
		if length > 65536 || (length > 0 && ptr == nil) {
			return nil, errors.New("invalid libfido2 assertion length")
		}

		return append([]byte(nil), unsafe.Slice((*byte)(ptr), int(length))...), nil
	}

	var result assertion

	for _, field := range []struct {
		target *[]byte
		ptr    func(uintptr, uintptr) unsafe.Pointer
		size   func(uintptr, uintptr) uintptr
	}{
		{&result.AuthenticatorData, f.authPtr, f.authLen}, {&result.Signature, f.sigPtr, f.sigLen}, {&result.CredentialID, f.idPtr, f.idLen}, {&result.UserHandle, f.userPtr, f.userLen},
	} {
		value, err := copyField(field.ptr(a, 0), field.size(a, 0))
		if err != nil {
			return assertion{}, err
		}

		*field.target = value
	}

	return result, nil
}

// Each scan owns a fresh libfido2 list, so hot-plug polling does not retain
// stale device pointers or leak enumerations.
func (f *fidoLibrary) devicePath() (string, error) {
	info := f.infoNew(8)
	if info == 0 {
		return "", errors.New("cannot enumerate security keys")
	}

	defer f.infoFree(&info, 8)

	var count uintptr
	if code := f.manifest(info, 8, &count); code != 0 {
		return "", fmt.Errorf("enumerate security keys: libfido2 code %d", code)
	}

	if count == 0 {
		return "", nil
	}

	if count != 1 {
		return "", errors.New("connect only the security key you want to use, then retry")
	}

	path := f.path(f.infoPtr(info, 0))
	if path == "" {
		return "", errors.New("security key has no device path")
	}

	return path, nil
}

func (f *fidoLibrary) waitForDevice(ctx context.Context, i Interaction) (string, error) {
	waitCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	notified := false

	for {
		if err := waitCtx.Err(); err != nil {
			if ctx.Err() != nil {
				return "", fmt.Errorf("security-key discovery cancelled: %w", ctx.Err())
			}

			return "", fmt.Errorf("timed out waiting for USB security key: %w", err)
		}

		path, err := f.devicePath()
		if err != nil || path != "" {
			return path, err
		}

		if !notified {
			i.status("security-key: insert your USB security key (waiting up to 60 seconds; Ctrl-C to cancel)")
			notified = true
		}

		select {
		case <-waitCtx.Done():
		case <-ticker.C:
		}
	}
}
