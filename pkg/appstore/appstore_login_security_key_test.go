package appstore

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	persistentjar "github.com/juju/persistent-cookiejar"
	"github.com/majd/ipatool/v2/internal/securitykey"
	storehttp "github.com/majd/ipatool/v2/pkg/http"
	"github.com/majd/ipatool/v2/pkg/keychain"
	"github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
	"howett.net/plist"
)

const securityKeyTestEndpoint = "https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate/"

type securityKeyTransport func(*http.Request) (*http.Response, error)

func (f securityKeyTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type securityKeySigner struct{}

func (securityKeySigner) Sign([]byte) ([]byte, error) { return []byte("test-signature"), nil }
func (securityKeySigner) Close() error                { return nil }

func TestSecurityKeyStoreExchange(t *testing.T) {
	for _, mode := range []string{"success", "document-envelope", "missing-token", "wrong-account", "missing-storefront", "redirect-evil", "invalid-plist", "failure-secret", "code-required"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			client := &http.Client{Transport: securityKeyTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.String() != securityKeyTestEndpoint {
					t.Fatal("credentials followed untrusted redirect")
				}
				body, _ := io.ReadAll(r.Body)
				var payload map[string]any
				if _, err := plist.Unmarshal(body, &payload); err != nil {
					t.Fatal(err)
				}
				if payload["password"] != "synthetic-pet" || payload["attempt"] != "1" || payload["why"] != "signIn" || payload["credentialSource"] != nil || payload["createSession"] != nil {
					t.Fatalf("wrong Store exchange payload: %#v", payload)
				}
				if r.Header.Get("X-Apple-ActionSignature") == "" || r.Header.Get("User-Agent") != storeAuthenticationUserAgent {
					t.Fatal("missing signature/identity")
				}
				headers := http.Header{"X-Set-Apple-Store-Front": {"143441-1,29"}}
				value := map[string]any{"dsPersonId": "42", "passwordToken": "store-token"}
				status := 200
				switch mode {
				case "missing-token":
					delete(value, "passwordToken")
				case "wrong-account":
					value["dsPersonId"] = "43"
				case "missing-storefront":
					headers = http.Header{}
				case "redirect-evil":
					status = 302
					headers.Set("Location", "https://evil.test/auth/v1/native/fast/")
				case "code-required":
					value["customerMessage"] = CustomerMessageBadLogin
					delete(value, "passwordToken")
				case "failure-secret":
					value["failureType"] = "SECRET-SENTINEL"
					value["customerMessage"] = "SECRET-SENTINEL"
				}
				data, _ := plist.Marshal(value, plist.XMLFormat)
				if mode == "document-envelope" {
					data = []byte("<Document>" + string(data) + "</Document>")
				} else if mode == "invalid-plist" {
					data = []byte("SECRET-SENTINEL")
				}

				return &http.Response{StatusCode: status, Header: headers, Body: io.NopCloser(strings.NewReader(string(data))), Request: r}, nil
			})}

			account, err := (&appstore{}).exchangeSecurityKeySession(context.Background(), client, "test@example.test", "guid", securityKeyTestEndpoint, &securitykey.GrandSlamSession{PET: "synthetic-pet", ADSID: "adsid", DSID: 42}, securityKeySigner{}, nil)
			if mode == "success" || mode == "document-envelope" {
				if err != nil {
					t.Fatal(err)
				}

				if account.PasswordToken != "store-token" || account.Email != "test@example.test" || account.Password != "" {
					t.Fatal("incorrect account")
				}
			} else {
				if err == nil {
					t.Fatal("accepted failed exchange")
				}

				if strings.Contains(err.Error(), "SECRET-SENTINEL") {
					t.Fatal("response secret leaked into error")
				}

				if mode == "code-required" && (errors.Is(err, ErrAuthCodeRequired) || !strings.Contains(err.Error(), "generic Configurator bad-login response")) {
					t.Fatal("generic rejection must not trigger a six-digit-code prompt")
				}

				if account.PasswordToken != "" {
					t.Fatal("failed exchange returned credentials")
				}
			}

			if calls != 1 {
				t.Fatal("unexpected retry")
			}
		})
	}
}

func TestSecurityKeyRefreshRequiresInteractionBeforeSideEffects(t *testing.T) {
	// Nil dependencies ensure automatic refresh never reaches networking or keychain.
	store := &appstore{}

	_, err := store.Login(LoginInput{SecurityKey: true, Email: "test@example.test"})
	if !errors.Is(err, ErrSecurityKeyLoginRequired) {
		t.Fatalf("got %v", err)
	}
}

func TestSecurityKeyStoreTransientRecovery(t *testing.T) {
	for _, transientStatus := range []int{500, 204, 403, 404, 429} {
		t.Run(http.StatusText(transientStatus), func(t *testing.T) {
			calls := 0
			client := &http.Client{Transport: securityKeyTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				code, body := transientStatus, "SECRET-SENTINEL"
				if transientStatus == 404 && calls == 1 {
					code = 204
					body = ""
				}
				if transientStatus == 204 {
					body = ""
				}
				headers := http.Header{"Retry-After": {"0"}, "Content-Type": {"text/html"}}
				if calls == 3 {
					code = 200
					data, _ := plist.Marshal(map[string]any{"dsPersonId": "42", "passwordToken": "store-token"}, plist.XMLFormat)
					body = string(data)
					headers.Set("X-Set-Apple-Store-Front", "143441-1,29")
				}

				return &http.Response{StatusCode: code, Header: headers, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
			})}

			acc, err := (&appstore{}).exchangeSecurityKeySession(context.Background(), client, "test@example.test", "guid", securityKeyTestEndpoint, &securitykey.GrandSlamSession{PET: "synthetic-pet", ADSID: "adsid"}, securityKeySigner{}, nil)
			if err != nil || acc.PasswordToken != "store-token" || calls != 3 {
				t.Fatalf("calls=%d, error=%v, token present=%t", calls, err, acc.PasswordToken != "")
			}
		})
	}
}

func TestSecurityKeyStoreRetryBoundaries(t *testing.T) {
	for _, mode := range []string{"exhausted", "empty-204", "html-404", "plist-404", "long-backoff", "cancel", "credential-error", "invalid-success", "incompatible-plist", "redirect"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			calls := 0

			var logs []string

			client := &http.Client{Transport: securityKeyTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				status, body := 503, "SECRET-BODY"
				headers := http.Header{"Retry-After": {"0"}, "Content-Type": {"text/html; private=SECRET-PARAM"}, "X-Apple-Jingle-Correlation-Key": {"correlation-123"}, "Set-Cookie": {"SECRET-COOKIE"}}
				switch mode {
				case "html-404":
					status = 404
				case "plist-404":
					status = 404
					data, _ := plist.Marshal(map[string]any{"failureType": "SECRET-ERROR"}, plist.XMLFormat)
					body = string(data)
				case "empty-204":
					status, body = 204, ""
				case "long-backoff":
					headers.Set("Retry-After", "31")
				case "credential-error":
					data, _ := plist.Marshal(map[string]any{"failureType": "SECRET-ERROR"}, plist.XMLFormat)
					body = string(data)
				case "invalid-success":
					status = 200
				case "incompatible-plist":
					status = 200
					data, _ := plist.Marshal(map[string]any{"passwordToken": []string{"SECRET-TOKEN"}}, plist.XMLFormat)
					body = string(data)
				case "redirect":
					status = 302
					headers.Set("Location", "https://p42-buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate/?secret=SECRET-QUERY")
				}

				return &http.Response{StatusCode: status, Header: headers, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
			})}
			acc, err := (&appstore{}).exchangeSecurityKeySession(ctx, client, "test@example.test", "guid", securityKeyTestEndpoint, &securitykey.GrandSlamSession{PET: "SECRET-PET", ADSID: "SECRET-ADSID"}, securityKeySigner{}, func(s string) {
				logs = append(logs, s)

				if mode == "cancel" && strings.Contains(s, "retrying") {
					cancel()
				}
			})

			wantCalls := 1
			if mode == "exhausted" || mode == "empty-204" || mode == "html-404" {
				wantCalls = 3
			}

			if mode == "redirect" {
				wantCalls = maxAuthenticationRedirects + 1
			}

			if err == nil || calls != wantCalls || acc.PasswordToken != "" {
				t.Fatalf("calls=%d, error=%v", calls, err)
			}

			all := strings.Join(logs, "\n") + err.Error()
			if strings.Contains(all, "SECRET-") {
				t.Fatal("sensitive data leaked")
			}

			if !strings.Contains(all, "correlation-123") || !strings.Contains(all, "bytes=") || !strings.Contains(all, "endpoint=") {
				t.Fatal("missing diagnostics")
			}

			if mode == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatalf("lost cancellation: %v", err)
			}

			if (mode == "exhausted" || mode == "empty-204" || mode == "html-404") && !strings.Contains(err.Error(), "exhausted 3 attempts") {
				t.Fatal(err)
			}

			if mode == "incompatible-plist" && !strings.Contains(err.Error(), "undecodable-plist") {
				t.Fatal(err)
			}
		})
	}
}

type recordingSecurityKeySigner struct{ bodies [][]byte }

func (s *recordingSecurityKeySigner) Sign(body []byte) ([]byte, error) {
	s.bodies = append(s.bodies, append([]byte(nil), body...))

	return []byte("signature"), nil
}
func (s *recordingSecurityKeySigner) Close() error { return nil }

func TestSecurityKeyLegacyEndpointAndRedirect(t *testing.T) {
	for _, endpoint := range []string{"https://evil.test/WebObjects/MZFinance.woa/wa/authenticate/", "http://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate/", "https://auth.itunes.apple.com/auth/v1/other/"} {
		_, err := (&appstore{}).exchangeSecurityKeySession(context.Background(), nil, "test@example.test", "guid", endpoint, &securitykey.GrandSlamSession{PET: "synthetic-pet", ADSID: "adsid"}, nil, nil)
		if err == nil {
			t.Fatal("accepted untrusted endpoint")
		}
	}

	signer := &recordingSecurityKeySigner{}
	calls := 0
	client := &http.Client{Transport: securityKeyTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		body, _ := io.ReadAll(r.Body)
		if len(signer.bodies) != calls || string(body) != string(signer.bodies[calls-1]) {
			t.Fatal("sent bytes differ from signed bytes")
		}
		if calls > 1 && string(body) != string(signer.bodies[0]) {
			t.Fatal("redirect changed the PET payload")
		}
		if r.Header.Get("X-Apple-ActionSignature") == "" {
			t.Fatal("unsigned request")
		}
		headers := http.Header{}
		status := 302
		response := ""
		if calls == 1 {
			headers.Set("Location", "https://p42-buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate/")
		} else {
			if r.URL.Host != "p42-buy.itunes.apple.com" {
				t.Fatal("wrong pod")
			}
			status = 200
			headers.Set("X-Set-Apple-Store-Front", "143441-1,29")
			data, _ := plist.Marshal(map[string]any{"dsPersonId": "42", "passwordToken": "store-token"}, plist.XMLFormat)
			response = string(data)
		}

		return &http.Response{StatusCode: status, Header: headers, Body: io.NopCloser(strings.NewReader(response)), Request: r}, nil
	})}

	account, err := (&appstore{}).exchangeSecurityKeySession(context.Background(), client, "test@example.test", "guid", securityKeyTestEndpoint, &securitykey.GrandSlamSession{PET: "synthetic-pet", ADSID: "adsid", DSID: 42}, signer, nil)
	if err != nil || calls != 2 || account.Password != "" || account.PasswordToken != "store-token" {
		t.Fatalf("exchange failed: calls=%d err=%v", calls, err)
	}
}

type queuedSecurityKeyTransport struct {
	steps []func(*http.Request) (*http.Response, error)
}

func (q *queuedSecurityKeyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	step := q.steps[0]
	q.steps = q.steps[1:]

	return step(req)
}

func TestSecurityKeyAnisetteHeadersSelection(t *testing.T) {
	g := gomega.NewWithT(t)

	localClient := &http.Client{}
	store := &appstore{
		securityKeyStoreAuth: securityKeyStoreAuth{
			anisetteHeaders: func(ctx context.Context, client *http.Client, state []byte) (http.Header, []byte, error) {
				g.Expect(ctx).NotTo(gomega.BeNil())
				g.Expect(client).To(gomega.BeIdenticalTo(localClient))
				g.Expect(state).To(gomega.Equal([]byte("existing-state")))

				hdr := make(http.Header)
				hdr.Set("X-Apple-I-MD", "local-md")
				hdr.Set("X-Apple-I-MD-M", "local-mdm")

				return hdr, []byte("local-state"), nil
			},
		},
	}

	headers, nextState, err := store.securityKeyAnisetteHeaders(context.Background(), "", localClient, []byte("existing-state"))
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(headers.Get("X-Apple-I-MD")).To(gomega.Equal("local-md"))
	g.Expect(headers.Get("X-Apple-I-MD-M")).To(gomega.Equal("local-mdm"))
	g.Expect(nextState).To(gomega.Equal([]byte("local-state")))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.Expect(r.Method).To(gomega.Equal(http.MethodGet))

		_, writeErr := w.Write([]byte(`{"X-Apple-I-MD":"remote-md","X-Apple-I-MD-M":"remote-mdm","X-Apple-I-MD-LU":"remote-lu","X-Mme-Device-Id":"remote-dev","X-MMe-Client-Info":"remote-client"}`))
		g.Expect(writeErr).NotTo(gomega.HaveOccurred())
	}))
	t.Cleanup(server.Close)

	headers, nextState, err = store.securityKeyAnisetteHeaders(context.Background(), server.URL, nil, []byte("persisted-store-state"))
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(headers.Get("X-Apple-I-MD")).To(gomega.Equal("remote-md"))
	g.Expect(headers.Get("X-Apple-I-MD-M")).To(gomega.Equal("remote-mdm"))
	g.Expect(nextState).To(gomega.Equal([]byte("persisted-store-state")))
}

func TestSecurityKeyStoreAMDProvisioningAndPersistence(t *testing.T) {
	g := gomega.NewWithT(t)

	filename := filepath.Join(t.TempDir(), "cookies")
	jar, err := storehttp.NewPersistentCookieJar(filename)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	ephemeral, err := cookiejar.New(nil)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	staged := &securityKeyStoreCookies{CookieJar: ephemeral}
	transport := &queuedSecurityKeyTransport{
		steps: []func(*http.Request) (*http.Response, error){
			func(r *http.Request) (*http.Response, error) {
				g.Expect(r.Header.Get("User-Agent")).To(gomega.Equal(storeAuthenticationUserAgent))
				g.Expect(r.Header.Get("X-Apple-AMD")).To(gomega.Equal("local-md"))
				g.Expect(r.Header.Get("X-Apple-AMD-M")).To(gomega.Equal("local-mdm"))
				g.Expect(r.Header.Get("X-Apple-I-MD-RINFO")).To(gomega.Equal("17106176"))

				rpHeader := make(http.Header)
				rpHeader.Set("X-Apple-AMD-Action", "RP")

				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     rpHeader,
					Body:       io.NopCloser(strings.NewReader("")),
					Request:    r,
				}, nil
			},
			func(r *http.Request) (*http.Response, error) {
				g.Expect(r.Header.Get("X-Apple-AMD")).To(gomega.BeEmpty())
				g.Expect(r.Header.Get("X-Apple-AMD-M")).To(gomega.BeEmpty())
				g.Expect(r.Header.Get("X-Apple-I-MD-RINFO")).To(gomega.BeEmpty())
				g.Expect(r.Header.Get("X-Mme-Device-Id")).To(gomega.Equal("device-1"))

				spHeader := make(http.Header)
				spHeader.Set("X-Apple-AMD-Action", "SP")
				spHeader.Set("X-Apple-AMD-Data", "sp-challenge")

				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     spHeader,
					Body:       io.NopCloser(strings.NewReader("")),
					Request:    r,
				}, nil
			},
			func(r *http.Request) (*http.Response, error) {
				g.Expect(r.Header.Get("User-Agent")).To(gomega.Equal(storeAuthenticationUserAgent))
				g.Expect(r.Header.Get("X-Apple-AMD")).To(gomega.Equal("store-amd"))
				g.Expect(r.Header.Get("X-Apple-AMD-M")).To(gomega.Equal("store-amd-m"))

				body, marshalErr := plist.Marshal(map[string]any{"passwordToken": "store-token"}, plist.XMLFormat)
				g.Expect(marshalErr).NotTo(gomega.HaveOccurred())

				okHeader := make(http.Header)
				okHeader.Set(HTTPHeaderStoreFront, "143441-1,29")
				okHeader.Add("Set-Cookie", "mz_at0-42=cookie-val; Domain=.apple.com; Path=/; Secure; HttpOnly; Max-Age=3600")

				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     okHeader,
					Body:       io.NopCloser(strings.NewReader(string(body))),
					Request:    r,
				}, nil
			},
		},
	}

	storeClient := &http.Client{Jar: staged, Transport: transport}
	localHeaders := make(http.Header)
	localHeaders.Set("X-Apple-I-MD", "local-md")
	localHeaders.Set("X-Apple-I-MD-M", "local-mdm")
	localHeaders.Set("X-Apple-I-MD-RINFO", "17106176")
	localHeaders.Set("X-Mme-Device-Id", "device-1")

	mockKeychain := keychain.NewMockKeychain(gomock.NewController(t))
	mockKeychain.EXPECT().Set(anisetteKeychainKey, []byte("amd-state")).Return(nil)
	mockKeychain.EXPECT().Set("account", gomock.Any()).DoAndReturn(func(_ string, data []byte) error {
		var saved Account

		g.Expect(json.Unmarshal(data, &saved)).To(gomega.Succeed())
		g.Expect(saved.SecurityKey).To(gomega.BeTrue())
		g.Expect(saved.Password).To(gomega.BeEmpty())
		g.Expect(saved.PasswordToken).To(gomega.Equal("store-token"))
		g.Expect(saved.DirectoryServicesID).To(gomega.Equal("42"))
		g.Expect(saved.StoreFront).To(gomega.Equal("143441-1,29"))

		return nil
	})

	machineID := []byte{0, 1, 2, 3, 4, 5}
	store := &appstore{
		keychain:        mockKeychain,
		cookieJar:       jar,
		kbsyncGenerator: func(context.Context, []byte, uint64) ([]byte, error) { return []byte("test-kbsync"), nil },
		securityKeyStoreAuth: securityKeyStoreAuth{
			provisionStoreAnisette: func(ctx context.Context, client *http.Client, state []byte, challenge, endpoint, userAgent, kbsync string, hardwareID []byte, identity http.Header) ([]byte, error) {
				g.Expect(ctx).NotTo(gomega.BeNil())
				g.Expect(client).To(gomega.BeIdenticalTo(storeClient))
				g.Expect(state).To(gomega.Equal([]byte("identity-state")))
				g.Expect(challenge).To(gomega.Equal("sp-challenge"))
				g.Expect(endpoint).To(gomega.Equal(privateAppStoreProvisioningURL))
				g.Expect(userAgent).To(gomega.Equal(storeAuthenticationUserAgent))
				g.Expect(kbsync).To(gomega.Equal(base64.StdEncoding.EncodeToString([]byte("test-kbsync"))))
				g.Expect(hardwareID).To(gomega.Equal(machineID))
				g.Expect(identity.Get("X-Apple-I-MD")).To(gomega.Equal("local-md"))

				return []byte("provisioned-state"), nil
			},
			storeAMDHeaders: func(ctx context.Context, state []byte, endpoint string, hardwareID []byte) (map[string]string, []byte, error) {
				g.Expect(ctx).NotTo(gomega.BeNil())
				g.Expect(state).To(gomega.Equal([]byte("provisioned-state")))
				g.Expect(endpoint).To(gomega.Equal(securityKeyTestEndpoint))
				g.Expect(hardwareID).To(gomega.Equal(machineID))

				return map[string]string{
					"X-Apple-AMD":   "store-amd",
					"X-Apple-AMD-M": "store-amd-m",
				}, []byte("amd-state"), nil
			},
		},
	}

	acc, nextState, err := store.exchangeSecurityKeyStoreSession(
		context.Background(),
		storeClient,
		"test@example.test",
		"000102030405",
		machineID,
		securityKeyTestEndpoint,
		&securitykey.GrandSlamSession{PET: "synthetic-pet", ADSID: "adsid", DSID: 42},
		securityKeySigner{},
		nil,
		localHeaders,
		[]byte("identity-state"),
		nil,
	)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(nextState).To(gomega.Equal([]byte("amd-state")))
	g.Expect(transport.steps).To(gomega.BeEmpty())
	g.Expect(acc.DirectoryServicesID).To(gomega.Equal("42"))
	g.Expect(acc.PasswordToken).To(gomega.Equal("store-token"))

	savedAcc, err := store.saveSecurityKeySession(acc, staged, nextState)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(savedAcc.SecurityKey).To(gomega.BeTrue())
	g.Expect(savedAcc.Password).To(gomega.BeEmpty())

	reloaded, err := persistentjar.New(&persistentjar.Options{Filename: filename})
	g.Expect(err).NotTo(gomega.HaveOccurred())

	target, err := url.Parse("https://buy.itunes.apple.com/")
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(reloaded.Cookies(target)).To(gomega.ContainElement(gomega.HaveField("Name", "mz_at0-42")))
}
