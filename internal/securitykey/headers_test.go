package securitykey

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAnisetteRequiresServiceURL(t *testing.T) {
	headers, err := Headers(context.Background(), "")
	if err == nil || err.Error() != "anisette service URL is required" || headers != nil {
		t.Fatalf("expected missing service URL error, got %v", err)
	}
}

func TestLocalAnisetteTrustBoundary(t *testing.T) {
	for _, endpoint := range []string{"http://example.test", "https:///missing-host", "https://u:p@example.test", "https://example.test/?token=secret", "https://example.test/#fragment", "ftp://example.test", "http://localhost:1234", "http://127.0.0.1.evil.test", "http://u:p@127.0.0.1", "http://127.0.0.1/?token=secret"} {
		if _, err := Headers(context.Background(), endpoint); err == nil {
			t.Fatalf("accepted %s", endpoint)
		}
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.RequestURI() != "/" || r.ContentLength != 0 {
			t.Error("expected anisette-v1 GET / without a body")
		}

		if r.Header.Get("Authorization") != "" || r.Header.Get("X-Apple-Identity-Token") != "" {
			t.Error("account credentials sent to local service")
		}

		if err := json.NewEncoder(w).Encode(map[string]string{"X-Apple-I-MD": "otp", "X-Apple-I-MD-M": "machine", "X-Apple-I-MD-LU": "local-user", "X-Mme-Device-Id": "device", "X-MMe-Client-Info": "client", "Authorization": "untrusted", "User-Agent": "akd/provider-test"}); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()

	headers, err := Headers(context.Background(), server.URL)
	if err != nil {
		t.Fatal(err)
	}

	if headers.Get("Authorization") != "" || headers.Get("X-Apple-I-MD") != "otp" || headers.Get("User-Agent") != "akd/provider-test" {
		t.Fatal("header allowlist failed")
	}

	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://example.test", http.StatusFound)
	}))
	defer redirect.Close()

	if _, err := Headers(context.Background(), redirect.URL); err == nil {
		t.Fatal("followed redirect")
	}
}

func TestAnisetteV1WithoutUserAgent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewEncoder(w).Encode(map[string]string{"X-Apple-I-MD": "otp", "X-Apple-I-MD-M": "machine", "X-Apple-I-MD-LU": "local-user", "X-Mme-Device-Id": "device", "X-MMe-Client-Info": "client"}); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()

	headers, err := Headers(context.Background(), server.URL)
	if err != nil {
		t.Fatal(err)
	}

	if headers.Get("X-Apple-I-MD") != "otp" || headers.Get("User-Agent") != "" {
		t.Fatal("v1 headers should not require a provider User-Agent extension")
	}
}

func TestAnisetteCancellation(t *testing.T) {
	for _, body := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if body {
				w.WriteHeader(http.StatusOK)
				w.(http.Flusher).Flush()
			}

			time.AfterFunc(20*time.Millisecond, cancel)
			<-r.Context().Done()
		}))
		_, err := Headers(ctx, server.URL)

		cancel()
		server.Close()

		if !errors.Is(err, context.Canceled) {
			t.Fatalf("body=%v: lost cancellation: %v", body, err)
		}
	}
}

func TestAnisetteTruncatedBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")

		if _, err := w.Write([]byte("{")); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()

	_, err := Headers(context.Background(), server.URL)
	if err == nil || err.Error() != "cannot read anisette response" {
		t.Fatalf("wrong read error: %v", err)
	}
}

func TestAnisetteAcceptsHTTPS(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// A canceled request proves a remote URL passed validation, without using the network.
	if _, err := Headers(ctx, "https://ani.sidestore.io"); !errors.Is(err, context.Canceled) {
		t.Fatalf("HTTPS rejected before request: %v", err)
	}
}

func TestAnisetteRequiresTrustedTLS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("accepted an untrusted certificate")
	}))
	defer server.Close()

	_, err := Headers(context.Background(), server.URL)
	if err == nil || err.Error() != "cannot reach anisette service; check the URL and retry" {
		t.Fatalf("expected TLS request failure, got %v", err)
	}
}
