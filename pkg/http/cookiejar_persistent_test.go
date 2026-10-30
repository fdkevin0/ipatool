package http

import (
	"bytes"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCookieCommitRetainsBackupIfRollbackFails(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "cookies")

	jar, err := NewPersistentCookieJar(filename)
	if err != nil {
		t.Fatal(err)
	}

	origin, _ := url.Parse("https://buy.itunes.apple.com/")
	jar.SetCookies(origin, []*http.Cookie{{Name: "token", Value: "old", Path: "/", MaxAge: 3600}})

	if err := jar.Save(); err != nil {
		t.Fatal(err)
	}

	before, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}

	failure := errors.New("keychain unavailable")
	err = jar.CommitCookies(func(staged http.CookieJar) {
		staged.SetCookies(origin, []*http.Cookie{{Name: "token", Value: "new", Path: "/", MaxAge: 3600}})
	}, func() error {
		if err := os.Remove(filename); err != nil {
			t.Fatal(err)
		}
		// A directory at the destination makes restoring the file fail.
		if err := os.Mkdir(filename, 0700); err != nil {
			t.Fatal(err)
		}

		return failure
	})

	if !errors.Is(err, failure) || !strings.Contains(err.Error(), "failed to restore Store cookies") {
		t.Fatalf("rollback failure was not reported: %v", err)
	}

	files, err := filepath.Glob(filepath.Join(filepath.Dir(filename), ".ipatool-cookies-*"))
	if err != nil || len(files) != 1 {
		t.Fatalf("expected one recovery file, got %v: %v", files, err)
	}

	backup, err := os.ReadFile(files[0])
	if err != nil || !bytes.Equal(before, backup) {
		t.Fatal("previous cookie file was not retained")
	}

	info, err := os.Stat(files[0])
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("recovery file is not private")
	}

	if cookies := jar.Cookies(origin); len(cookies) != 1 || cookies[0].Value != "old" {
		t.Fatal("failed commit changed the live cookie jar")
	}
}

func TestCookieCommitPreservesScopeAndSessionCookies(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "cookies")

	jar, err := NewPersistentCookieJar(filename)
	if err != nil {
		t.Fatal(err)
	}

	origin, _ := url.Parse("https://buy.itunes.apple.com/private/")
	jar.SetCookies(origin, []*http.Cookie{{Name: "session", Value: "memory-only", Path: "/"}})

	expires := time.Now().Add(time.Hour).Truncate(time.Second)

	err = jar.CommitCookies(func(staged http.CookieJar) {
		staged.SetCookies(origin, []*http.Cookie{{Name: "token", Value: "new", Path: "/private", Secure: true, HttpOnly: true, Expires: expires}})
	}, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}

	if len(jar.Cookies(origin)) != 2 {
		t.Fatal("commit lost an existing in-memory session cookie")
	}

	reloaded, err := NewPersistentCookieJar(filename)
	if err != nil {
		t.Fatal(err)
	}

	cookies := reloaded.AllCookies()
	if len(cookies) != 1 || cookies[0].Name != "token" || !cookies[0].Secure || !cookies[0].HttpOnly || !cookies[0].Expires.Equal(expires) {
		t.Fatal("commit lost cookie attributes or persisted a session cookie")
	}

	for _, raw := range []string{"https://child.buy.itunes.apple.com/private/", "https://buy.itunes.apple.com/", "http://buy.itunes.apple.com/private/"} {
		u, _ := url.Parse(raw)
		if len(reloaded.Cookies(u)) != 0 {
			t.Fatalf("commit widened cookie scope to %s", raw)
		}
	}
}
