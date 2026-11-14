package securitykey

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

const securityKeyEndpoint = "https://gsa.apple.com/auth/verify/security/key"

type Interaction struct {
	PIN    func(context.Context) (string, error)
	Status func(string)
}

func (i Interaction) status(message string) {
	if i.Status != nil {
		i.Status(message)
	}
}

type challenge struct {
	Challenge          string   `json:"challenge"`
	RPID               string   `json:"rpId"`
	KeyHandles         []string `json:"keyHandles"`
	AllowedCredentials string   `json:"allowedCredentials"`
}

func decodeBase64(value string) ([]byte, error) {
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if data, err := encoding.Strict().DecodeString(value); err == nil {
			return data, nil
		}
	}

	return nil, errors.New("invalid base64 in security-key challenge")
}

func parseChallenge(body []byte) (challenge, error) {
	var result challenge
	// GSA can return JSON embedded in its sign-in HTML. Decode exactly one JSON
	// value after the key; the decoder handles escaped strings and nested braces.
	marker := []byte(`"fsaChallenge"`)

	if len(body) > grandSlamBodyLimit {
		return result, errors.New("security-key response exceeds limit")
	}

	index := bytes.Index(body, marker)
	if index < 0 {
		return result, errors.New("server returned no fsaChallenge; security-key protocol may have changed")
	}

	rest := bytes.TrimSpace(body[index+len(marker):])
	if len(rest) == 0 || rest[0] != ':' {
		return result, errors.New("invalid security-key challenge")
	}

	if err := json.NewDecoder(bytes.NewReader(rest[1:])).Decode(&result); err != nil {
		return result, errors.New("invalid security-key challenge JSON")
	}

	if result.RPID != "apple.com" {
		return result, errors.New("security-key challenge has unexpected RP ID")
	}

	raw, err := decodeBase64(result.Challenge)
	if err != nil || len(raw) < 16 || len(raw) > 1024 {
		return result, errors.New("invalid security-key challenge bytes")
	}

	if len(result.KeyHandles) == 0 && result.AllowedCredentials != "" {
		result.KeyHandles = strings.Split(result.AllowedCredentials, ",")
	}

	if len(result.KeyHandles) == 0 || len(result.KeyHandles) > 64 {
		return result, errors.New("invalid security-key credential count")
	}

	for i, id := range result.KeyHandles {
		id = strings.TrimSpace(id)
		result.KeyHandles[i] = id

		raw, err := decodeBase64(id)
		if err != nil || len(raw) == 0 || len(raw) > 1024 {
			return result, errors.New("invalid security-key credential ID")
		}
	}

	return result, nil
}

func clientData(c challenge) ([]byte, error) {
	raw, err := decodeBase64(c.Challenge)
	if err != nil {
		return nil, err
	}
	// Match the IDMSA iframe ceremony observed by the GSA reference implementation.
	data, err := json.Marshal(struct {
		Type        string `json:"type"`
		Challenge   string `json:"challenge"`
		Origin      string `json:"origin"`
		CrossOrigin bool   `json:"crossOrigin"`
		TopOrigin   string `json:"topOrigin"`
	}{"webauthn.get", base64.RawURLEncoding.EncodeToString(raw), "https://idmsa.apple.com", true, "https://account.apple.com"})
	if err != nil {
		return nil, fmt.Errorf("encode client data: %w", err)
	}

	return data, nil
}

type assertion struct{ AuthenticatorData, Signature, CredentialID, UserHandle []byte }

func assertionPayload(c challenge, data []byte, a assertion) (map[string]string, error) {
	expected := sha256.Sum256([]byte(c.RPID))
	if len(a.AuthenticatorData) < 37 || !bytes.Equal(a.AuthenticatorData[:32], expected[:]) || a.AuthenticatorData[32]&1 == 0 || len(a.Signature) == 0 {
		return nil, errors.New("security key returned invalid RP hash, presence flag, or signature")
	}

	allowed := false

	for _, id := range c.KeyHandles {
		raw, _ := decodeBase64(id)
		if bytes.Equal(raw, a.CredentialID) {
			allowed = true
		}
	}

	if !allowed {
		return nil, errors.New("security key returned an unrequested credential")
	}

	b64 := base64.StdEncoding.EncodeToString
	payload := map[string]string{"challenge": c.Challenge, "rpId": c.RPID, "clientData": b64(data), "signatureData": b64(a.Signature), "authenticatorData": b64(a.AuthenticatorData), "credentialID": b64(a.CredentialID)}

	if len(a.UserHandle) > 0 {
		payload["userHandle"] = b64(a.UserHandle)
	}

	return payload, nil
}

func (c *GrandSlamClient) VerifySecurityKey(ctx context.Context, auth *GrandSlamChallenge, interaction Interaction) error {
	return c.verifySecurityKey(ctx, auth, interaction, getAssertion)
}

func (c *GrandSlamClient) verifySecurityKey(ctx context.Context, auth *GrandSlamChallenge, interaction Interaction, assertionFunc func(context.Context, challenge, []byte, Interaction) (assertion, error)) error {
	headers, err := c.twoFactorHeaders(auth)
	if err != nil {
		return err
	}

	headers.Set("Accept", "application/json, text/html")
	headers.Set("Accept-Language", "en-us")
	headers.Set("X-Apple-App-Info", "com.apple.gs.xcode.auth")
	headers.Set("X-Xcode-Version", "11.2 (11B41)")
	interaction.status("security-key: establishing GSA verification session")

	if _, err := c.request(ctx, http.MethodGet, "https://gsa.apple.com/auth", headers, nil); err != nil {
		return fmt.Errorf("establish security-key session: %w", err)
	}

	interaction.status("security-key: fetching Apple challenge")

	body, err := c.request(ctx, http.MethodGet, securityKeyEndpoint, headers, nil)
	if err != nil {
		return fmt.Errorf("fetch security-key challenge: %w", err)
	}

	challenge, err := parseChallenge(body)
	if err != nil {
		return err
	}

	data, err := clientData(challenge)
	if err != nil {
		return err
	}

	a, err := assertionFunc(ctx, challenge, data, interaction)
	if err != nil {
		return err
	}

	payload, err := assertionPayload(challenge, data, a)
	if err != nil {
		return err
	}

	body, err = json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode security-key assertion: %w", err)
	}

	headers.Set("Content-Type", "application/json")
	headers.Set("Accept", "application/json")
	interaction.status("security-key: submitting assertion to Apple")

	_, err = c.request(ctx, http.MethodPost, securityKeyEndpoint, headers, body)
	// Do not infer a usable session from HTTP 200. The caller must repeat SRP
	// and obtain a PET before attempting Store authentication.
	if err != nil {
		return fmt.Errorf("verify security-key assertion: %w", err)
	}

	return nil
}
