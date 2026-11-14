package securitykey

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
)

func TestSecurityKeyChallengeAndAssertion(t *testing.T) {
	raw := bytes.Repeat([]byte{0xfb}, 32)
	encoded := base64.StdEncoding.EncodeToString(raw)
	body := []byte(`<script>{"fsaVerification":{"fsaChallenge":{"challenge":"` + encoded + `","rpId":"apple.com","allowedCredentials":"Y3JlZA=="}}}</script>`)

	c, err := parseChallenge(body)
	if err != nil {
		t.Fatal(err)
	}

	data, err := clientData(c)
	if err != nil {
		t.Fatal(err)
	}

	var client map[string]any
	if err = json.Unmarshal(data, &client); err != nil {
		t.Fatal(err)
	}

	if client["challenge"] != base64.RawURLEncoding.EncodeToString(raw) || client["origin"] != "https://idmsa.apple.com" {
		t.Fatal("incorrect clientData encoding")
	}

	hash := sha256.Sum256([]byte("apple.com"))
	auth := append(hash[:], 1, 0, 0, 0, 0)
	a := assertion{AuthenticatorData: auth, CredentialID: []byte("cred"), Signature: []byte("signature")}

	payload, err := assertionPayload(c, data, a)
	if err != nil {
		t.Fatal(err)
	}

	if payload["clientData"] != base64.StdEncoding.EncodeToString(data) || payload["challenge"] != encoded {
		t.Fatal("transport encoding mismatch")
	}

	if _, exists := payload["userHandle"]; exists {
		t.Fatal("empty userHandle should be omitted")
	}

	a.CredentialID = []byte("other")
	if _, err = assertionPayload(c, data, a); err == nil {
		t.Fatal("accepted unrequested credential")
	}

	a.CredentialID = []byte("cred")
	a.AuthenticatorData[32] = 0

	if _, err = assertionPayload(c, data, a); err == nil {
		t.Fatal("accepted assertion without user presence")
	}

	a.AuthenticatorData[32] = 1
	a.AuthenticatorData[0] ^= 1

	if _, err = assertionPayload(c, data, a); err == nil {
		t.Fatal("accepted wrong RP hash")
	}

	for _, invalid := range []string{
		strings.ReplaceAll(string(body), "apple.com", "evil.test"),
		strings.ReplaceAll(string(body), encoded, "!bad!"),
		strings.ReplaceAll(string(body), "Y3JlZA==", ""),
		`{"fsaChallenge":"not-an-object"}`,
	} {
		if _, err := parseChallenge([]byte(invalid)); err == nil {
			t.Fatal("accepted invalid challenge")
		}
	}
}

func TestSecurityKeySecondaryAuthChallenge(t *testing.T) {
	server := newGrandSlamTestServer(t, "s2k", "secondary-auth")

	client, err := NewGrandSlamClient(&http.Client{Transport: server}, nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Login(context.Background(), "synthetic@example.test", "synthetic-password")

	var challenge *GrandSlamChallenge

	if !errors.As(err, &challenge) {
		t.Fatalf("expected FIDO-capable secondary challenge, got %v", err)
	}
}

func TestSecurityKeyHTTPFlow(t *testing.T) {
	steps := []string{}
	jar, _ := cookiejar.New(nil)
	client, _ := NewGrandSlamClient(&http.Client{Jar: jar, Transport: grandSlamRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		steps = append(steps, r.Method+" "+r.URL.Path)
		if r.Header.Get("X-Apple-Identity-Token") != base64.StdEncoding.EncodeToString([]byte("dsid:idms")) || r.Header.Get("X-Apple-App-Info") != "com.apple.gs.xcode.auth" {
			t.Fatal("missing identity headers")
		}
		headers := http.Header{}
		body := "{}"
		if r.URL.Path == "/auth" {
			headers.Add("Set-Cookie", "aa=synthetic; Path=/; Secure")
		} else {
			if cookie, err := r.Cookie("aa"); err != nil || cookie.Value != "synthetic" {
				t.Fatal("session cookie not retained")
			}
			if r.Method == http.MethodGet {
				body = `{"fsaChallenge":{"challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","rpId":"apple.com","keyHandles":["Y3JlZA=="]}}`
			} else {
				data, _ := io.ReadAll(r.Body)
				if strings.Contains(string(data), "LOCAL-PIN") {
					t.Fatal("PIN leaked into HTTP request")
				}
				var payload map[string]string
				if err := json.Unmarshal(data, &payload); err != nil || payload["credentialID"] != "Y3JlZA==" {
					t.Fatal("invalid assertion request")
				}
			}
		}

		return &http.Response{StatusCode: http.StatusOK, Header: headers, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	})}, nil)

	err := client.verifySecurityKey(context.Background(), &GrandSlamChallenge{ADSID: "dsid", IDMSToken: "idms"}, Interaction{}, func(context.Context, challenge, []byte, Interaction) (assertion, error) {
		hash := sha256.Sum256([]byte("apple.com"))

		return assertion{AuthenticatorData: append(hash[:], 1, 0, 0, 0, 0), CredentialID: []byte("cred"), Signature: []byte("synthetic-signature")}, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if strings.Join(steps, ",") != "GET /auth,GET /auth/verify/security/key,POST /auth/verify/security/key" {
		t.Fatal(steps)
	}
}
