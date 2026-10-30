package http

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	filelock "github.com/juju/go4/lock"
	persistentjar "github.com/juju/persistent-cookiejar"
)

type PersistentCookieJar struct {
	*persistentjar.Jar
	filename string
}

func NewPersistentCookieJar(filename string) (*PersistentCookieJar, error) {
	jar, err := persistentjar.New(&persistentjar.Options{Filename: filename})
	if err != nil {
		return nil, fmt.Errorf("load persistent cookies: %w", err)
	}

	return &PersistentCookieJar{Jar: jar, filename: filename}, nil
}

// CommitCookies applies updates to the saved cookies and restores the file if saving the account fails.
// update must only set cookies: it runs on the staged jar, then the live jar on success.
// shortcut: rollback covers returned errors; add a durable journal if crash recovery is required.
func (j *PersistentCookieJar) CommitCookies(update func(http.CookieJar), saveAccount func() error) error {
	lock, err := filelock.Lock(j.filename + ".lock")
	if err != nil {
		return errors.New("failed to lock Store cookies")
	}

	defer lock.Close()

	previous, err := os.ReadFile(j.filename)
	existed := err == nil

	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("failed to read Store cookies")
	}

	defer clear(previous)

	backup, err := writeCookieTemp(filepath.Dir(j.filename), previous)
	if err != nil {
		return errors.New("failed to back up Store cookies")
	}

	defer func() {
		if backup != "" {
			os.Remove(backup)
		}
	}()

	staged, err := writeCookieTemp(filepath.Dir(j.filename), previous)
	if err != nil {
		return errors.New("failed to stage Store cookies")
	}

	defer os.Remove(staged)
	defer os.Remove(staged + ".lock")

	candidate, err := persistentjar.New(&persistentjar.Options{Filename: staged})
	if err != nil {
		return errors.New("failed to load staged Store cookies")
	}

	update(candidate)

	if err := candidate.Save(); err != nil {
		return errors.New("failed to save staged Store cookies")
	}

	if err := os.Rename(staged, j.filename); err != nil {
		return errors.New("failed to replace Store cookies")
	}

	if err := saveAccount(); err != nil {
		var restoreErr error
		if existed {
			restoreErr = os.Rename(backup, j.filename)
		} else {
			restoreErr = os.Remove(j.filename)
		}

		if restoreErr != nil {
			recovery := backup
			backup = "" // Keep the previous file available if the filesystem rejects rollback.

			return errors.Join(err, fmt.Errorf("failed to restore Store cookies; backup retained at %s; log in again before using this session", recovery))
		}

		return err
	}

	update(j.Jar)

	return nil
}

func writeCookieTemp(directory string, data []byte) (string, error) {
	f, err := os.CreateTemp(directory, ".ipatool-cookies-*")
	if err != nil {
		return "", fmt.Errorf("create cookie staging file: %w", err)
	}

	_, writeErr := f.Write(data)
	if err := errors.Join(writeErr, f.Close()); err != nil {
		os.Remove(f.Name())

		return "", err
	}

	return f.Name(), nil
}
