package appstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	persistentjar "github.com/juju/persistent-cookiejar"
	"github.com/majd/ipatool/v2/internal/securitykey"
	apphttp "github.com/majd/ipatool/v2/pkg/http"
	"github.com/majd/ipatool/v2/pkg/keychain"
	"go.uber.org/mock/gomock"
	"howett.net/plist"
)

func TestSecurityKeyStoreCookiesSurviveRestart(t *testing.T) {
	for _, reject := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "rejected"}[reject], func(t *testing.T) {
			filename := filepath.Join(t.TempDir(), "cookies")

			saved, err := apphttp.NewPersistentCookieJar(filename)
			if err != nil {
				t.Fatal(err)
			}

			origin, _ := url.Parse(securityKeyTestEndpoint)
			saved.SetCookies(origin, []*http.Cookie{{Name: "X-Token", Value: "old", Path: "/", Domain: ".apple.com", Expires: time.Now().Add(time.Hour)}})

			if err := saved.Save(); err != nil {
				t.Fatal(err)
			}

			ephemeral, _ := cookiejar.New(nil)
			ephemeral.SetCookies(origin, []*http.Cookie{{Name: "GSA-only", Value: "private", Domain: ".apple.com", Path: "/", Expires: time.Now().Add(time.Hour)}})
			staged := &securityKeyStoreCookies{CookieJar: ephemeral}
			calls := 0
			client := &http.Client{Jar: staged, Transport: securityKeyTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				headers := http.Header{}
				status, body := 302, ""
				if calls == 1 {
					headers.Add("Set-Cookie", "store-route=route-value; Domain=.apple.com; Path=/; Secure; HttpOnly; Max-Age=3600")
					headers.Set("Location", "https://p12-buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate/")
				} else {
					if cookie, err := r.Cookie("store-route"); err != nil || cookie.Value != "route-value" {
						t.Fatal("redirect lost Store cookies")
					}
					status = 200
					headers.Add("Set-Cookie", "X-Token=store-cookie; Domain=.apple.com; Path=/; Secure; HttpOnly; Max-Age=3600")
					headers.Set("X-Set-Apple-Store-Front", "143441-1,29")
					value := map[string]any{"dsPersonId": "42", "passwordToken": "store-token"}
					if reject {
						value = map[string]any{"failureType": "-5000"}
					}
					data, _ := plist.Marshal(value, plist.XMLFormat)
					body = string(data)
				}

				return &http.Response{StatusCode: status, Header: headers, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
			})}
			keys := keychain.NewMockKeychain(gomock.NewController(t))
			store := NewAppStore(Args{CookieJar: saved, Keychain: keys}).(*appstore)

			acc, exchangeErr := store.exchangeSecurityKeySession(context.Background(), client, "test@example.test", "guid", securityKeyTestEndpoint, &securitykey.GrandSlamSession{PET: "synthetic-pet", ADSID: "adsid", DSID: 42}, securityKeySigner{}, nil)
			if reject {
				if exchangeErr == nil {
					t.Fatal("accepted rejected exchange")
				}
			} else {
				if exchangeErr != nil {
					t.Fatal(exchangeErr)
				}

				keys.EXPECT().Set("account", gomock.Any()).DoAndReturn(func(_ string, data []byte) error {
					var stored Account
					if err := json.Unmarshal(data, &stored); err != nil {
						return fmt.Errorf("decode saved account: %w", err)
					}

					if !stored.SecurityKey || stored.Password != "" || stored.PasswordToken != "store-token" || strings.Contains(string(data), "synthetic-pet") {
						t.Fatal("unsafe saved account")
					}

					return nil
				})

				acc.Password = "synthetic-pet"
				if _, err := store.saveSecurityKeyAccount(acc, staged); err != nil {
					t.Fatal(err)
				}
			}

			reloaded, err := persistentjar.New(&persistentjar.Options{Filename: filename})
			if err != nil {
				t.Fatal(err)
			}

			download, _ := url.Parse("https://p12-buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/volumeStoreDownloadProduct")
			values := map[string]string{}

			for _, c := range reloaded.Cookies(download) {
				values[c.Name] = c.Value
			}

			if values["GSA-only"] != "" {
				t.Fatal("persisted GSA cookies")
			}

			if reject {
				if values["X-Token"] != "old" || values["store-route"] != "" {
					t.Fatal("failed exchange changed persistent cookies")
				}
			} else if values["X-Token"] != "store-cookie" || values["store-route"] != "route-value" {
				t.Fatal("Store authentication cookies lost on restart")
			}
		})
	}
}

func TestSecurityKeyCookieSaveFailureDoesNotSaveAccount(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "missing", "SECRET-sentinel")

	jar, err := apphttp.NewPersistentCookieJar(filename)
	if err != nil {
		t.Fatal(err)
	}

	store := &appstore{cookieJar: jar, keychain: keychain.NewMockKeychain(gomock.NewController(t))}

	_, err = store.saveSecurityKeyAccount(Account{Password: "SECRET-pet"}, &securityKeyStoreCookies{})
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatal("cookie persistence failure not safely returned")
	}
}

func TestSecurityKeyKeychainFailurePreservesCookies(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(map[bool]string{false: "first login", true: "existing session"}[existing], func(t *testing.T) {
			filename := filepath.Join(t.TempDir(), "cookies")

			jar, err := apphttp.NewPersistentCookieJar(filename)
			if err != nil {
				t.Fatal(err)
			}

			origin, _ := url.Parse(securityKeyTestEndpoint)
			jar.SetCookies(origin, []*http.Cookie{{Name: "session-only", Value: "old", Path: "/", Secure: true, HttpOnly: true}})

			if existing {
				jar.SetCookies(origin, []*http.Cookie{
					{Name: "X-Token", Value: "old-session", Path: "/", Secure: true, HttpOnly: true, Expires: time.Now().Add(time.Hour)},
					{Name: "deleted-by-login", Value: "keep", Domain: ".apple.com", Path: "/", Expires: time.Now().Add(time.Hour)},
				})

				if err := jar.Save(); err != nil {
					t.Fatal(err)
				}
			}

			before := jar.AllCookies()
			beforeFile, _ := os.ReadFile(filename)
			ephemeral, _ := cookiejar.New(nil)
			staged := &securityKeyStoreCookies{CookieJar: ephemeral}
			staged.SetCookies(origin, []*http.Cookie{
				{Name: "X-Token", Value: "new-session", Path: "/", Expires: time.Now().Add(time.Hour)},
				{Name: "new-route", Value: "new", Domain: ".apple.com", Path: "/", Expires: time.Now().Add(time.Hour)},
				{Name: "deleted-by-login", Domain: ".apple.com", Path: "/", MaxAge: -1},
				{Name: "session-only", Value: "new", Path: "/"},
			})

			failure := errors.New("simulated locked keychain")
			keys := keychain.NewMockKeychain(gomock.NewController(t))
			keys.EXPECT().Set("account", gomock.Any()).Return(failure)

			store := &appstore{cookieJar: jar, keychain: keys}
			if _, err := store.saveSecurityKeyAccount(Account{Email: "new@example.test"}, staged); !errors.Is(err, failure) {
				t.Fatalf("expected keychain failure, got %v", err)
			}

			if !reflect.DeepEqual(jar.AllCookies(), before) {
				t.Fatal("failed login changed in-memory cookies")
			}

			afterFile, err := os.ReadFile(filename)
			if existing {
				if err != nil || !bytes.Equal(beforeFile, afterFile) {
					t.Fatal("failed login changed the saved cookie file")
				}
			} else if !errors.Is(err, os.ErrNotExist) {
				t.Fatal("failed first login left a cookie file")
			}

			child, _ := url.Parse("https://child.buy.itunes.apple.com/")
			for _, c := range jar.Cookies(child) {
				if c.Name == "X-Token" {
					t.Fatal("rollback widened host-only cookie scope")
				}
			}

			files, err := filepath.Glob(filepath.Join(filepath.Dir(filename), ".ipatool-cookies-*"))
			if err != nil || len(files) != 0 {
				t.Fatal("staged credentials were not cleaned up")
			}
		})
	}
}
