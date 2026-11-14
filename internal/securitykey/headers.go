package securitykey

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Headers fetches anisette-v1 headers from an explicitly selected HTTPS or local HTTP service.
func Headers(ctx context.Context, endpoint string) (http.Header, error) {
	if endpoint == "" {
		return nil, errors.New("anisette service URL is required")
	}

	u, err := url.Parse(endpoint)
	if err != nil || u.Hostname() == "" || (u.Scheme != "https" && (u.Scheme != "http" || (u.Hostname() != "127.0.0.1" && u.Hostname() != "::1"))) || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("anisette URL must use HTTPS or HTTP loopback (127.0.0.1 or [::1]), without credentials, query or fragment")
	}

	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, errors.New("invalid anisette request")
	}

	res, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("anisette request cancelled: %w", ctx.Err())
		}

		return nil, errors.New("cannot reach anisette service; check the URL and retry")
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("anisette service returned HTTP %d", res.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(res.Body, 32769))
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("anisette response cancelled: %w", ctx.Err())
		}

		return nil, errors.New("cannot read anisette response")
	}

	if len(data) > 32768 {
		return nil, errors.New("invalid anisette response size")
	}

	var values map[string]string
	if err = json.Unmarshal(data, &values); err != nil {
		return nil, errors.New("anisette service returned invalid JSON")
	}

	result := make(http.Header)
	// Never forward arbitrary service-provided headers into authenticated requests.
	for _, name := range []string{"User-Agent", "X-Apple-I-MD", "X-Apple-I-MD-M", "X-Apple-I-MD-RINFO", "X-Apple-I-MD-LU", "X-Apple-I-Client-Time", "X-Apple-I-TimeZone", "X-Apple-Locale", "X-Mme-Device-Id", "X-Apple-I-SRL-NO", "X-MMe-Client-Info"} {
		for key, value := range values {
			if strings.EqualFold(name, key) {
				if len(value) > 8192 || strings.ContainsAny(value, "\r\n\x00") {
					return nil, errors.New("invalid anisette header value")
				}

				result.Set(name, value)
			}
		}
	}

	for _, name := range []string{"X-Apple-I-MD", "X-Apple-I-MD-M", "X-Apple-I-MD-LU", "X-Mme-Device-Id", "X-MMe-Client-Info"} {
		if result.Get(name) == "" {
			return nil, fmt.Errorf("anisette service omitted %s", name)
		}
	}

	result.Set("X-Apple-I-Client-Time", time.Now().UTC().Format(time.RFC3339))

	if result.Get("X-Apple-I-TimeZone") == "" {
		result.Set("X-Apple-I-TimeZone", "UTC")
	}

	if result.Get("X-Apple-Locale") == "" {
		result.Set("X-Apple-Locale", "en_US")
	}

	return result, nil
}
