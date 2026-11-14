package appstore

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/majd/ipatool/v2/internal/securitykey"
	"github.com/majd/ipatool/v2/internal/storeauth"
	storehttp "github.com/majd/ipatool/v2/pkg/http"
	"howett.net/plist"
)

var ErrSecurityKeyLoginRequired = errors.New("security-key session requires interactive login; run 'ipatool auth login --security-key'")

type SecurityKeyInteraction struct {
	AnisetteURL string
	Context     context.Context
	PIN         func(context.Context) (string, error)
	Status      func(string)
}

type securityKeyStoreAuth struct {
	anisetteHeaders        func(ctx context.Context, client *http.Client, state []byte) (http.Header, []byte, error)
	storeAMDHeaders        func(ctx context.Context, state []byte, endpoint string, hardwareID []byte) (map[string]string, []byte, error)
	provisionStoreAnisette func(ctx context.Context, client *http.Client, state []byte, challenge, endpoint, userAgent, kbsync string, hardwareID []byte, identity http.Header) ([]byte, error)
}

func (t *appstore) securityKeyAuth() securityKeyStoreAuth {
	auth := t.securityKeyStoreAuth
	if auth.anisetteHeaders == nil {
		auth.anisetteHeaders = storeauth.AnisetteHeaders
	}

	if auth.storeAMDHeaders == nil {
		auth.storeAMDHeaders = storeauth.StoreAMDHeaders
	}

	if auth.provisionStoreAnisette == nil {
		auth.provisionStoreAnisette = storeauth.ProvisionStoreAnisette
	}

	return auth
}

func (t *appstore) hasSecurityKeyStoreAMD() bool {
	return t.authBackend != nil ||
		t.securityKeyStoreAuth.anisetteHeaders != nil ||
		t.securityKeyStoreAuth.storeAMDHeaders != nil ||
		t.securityKeyStoreAuth.provisionStoreAnisette != nil
}

func (t *appstore) securityKeyAnisetteHeaders(ctx context.Context, anisetteURL string, client *http.Client, state []byte) (http.Header, []byte, error) {
	if anisetteURL != "" {
		headers, err := securitykey.Headers(ctx, anisetteURL)
		if err != nil {
			return nil, nil, fmt.Errorf("fetch anisette headers: %w", err)
		}

		return headers, state, nil
	}

	headers, updated, err := t.securityKeyAuth().anisetteHeaders(ctx, client, state)
	if err != nil {
		return nil, nil, fmt.Errorf("prepare local anisette headers: %w", err)
	}

	return headers, updated, nil
}

func (t *appstore) loginSecurityKey(input LoginInput) (LoginOutput, error) {
	if input.AuthCode != "" {
		return LoginOutput{}, errors.New("security-key login cannot be combined with an auth code")
	}

	if input.SecurityKeyInteraction == nil {
		return LoginOutput{}, ErrSecurityKeyLoginRequired
	}

	if t.cookieJar == nil {
		return LoginOutput{}, errors.New("store cookie storage is not configured")
	}

	if err := securitykey.CheckSupport(); err != nil {
		return LoginOutput{}, fmt.Errorf("check security-key support: %w", err)
	}

	interaction := input.SecurityKeyInteraction

	ctx := interaction.Context
	if ctx == nil {
		ctx = context.Background()
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	status := func(message string) {
		if interaction.Status != nil {
			interaction.Status(message)
		}
	}

	t.authStateMu.Lock()
	defer t.authStateMu.Unlock()

	persistedState := t.anisetteState
	if len(persistedState) == 0 && t.keychain != nil {
		persistedState, _ = t.keychain.Get(anisetteKeychainKey)
	}

	gsaJar, err := cookiejar.New(nil)
	if err != nil {
		return LoginOutput{}, fmt.Errorf("create authentication cookie jar: %w", err)
	}

	gsaClient := storeauth.NewHTTPClient(gsaJar)

	if interaction.AnisetteURL != "" {
		status("security-key: fetching anisette headers from service")
	} else {
		status("security-key: preparing local anisette headers")
	}

	identityState := persistedState

	var localHeaders http.Header

	headers, identityState, err := t.securityKeyAnisetteHeaders(ctx, interaction.AnisetteURL, gsaClient, identityState)
	if err != nil {
		return LoginOutput{}, err
	}

	if interaction.AnisetteURL == "" {
		localHeaders = headers
	}

	gsa, err := securitykey.NewGrandSlamClient(gsaClient, headers)
	if err != nil {
		return LoginOutput{}, fmt.Errorf("create GrandSlam client: %w", err)
	}

	status("security-key: authenticating with GrandSlam")

	session, err := gsa.Login(ctx, input.Email, input.Password)

	var challenge *securitykey.GrandSlamChallenge

	if errors.As(err, &challenge) {
		err = gsa.VerifySecurityKey(ctx, challenge, securitykey.Interaction{PIN: interaction.PIN, Status: interaction.Status})
		if err != nil {
			return LoginOutput{}, fmt.Errorf("security-key verification: %w", err)
		}

		// Anisette OTPs are short-lived; regenerate after the user's touch/PIN.
		headers, identityState, err = t.securityKeyAnisetteHeaders(ctx, interaction.AnisetteURL, gsaClient, identityState)
		if err != nil {
			return LoginOutput{}, fmt.Errorf("refresh anisette headers: %w", err)
		}

		if interaction.AnisetteURL == "" {
			localHeaders = headers
		}

		gsa, err = securitykey.NewGrandSlamClient(gsaClient, headers)
		if err != nil {
			return LoginOutput{}, fmt.Errorf("create GrandSlam client: %w", err)
		}

		status("security-key: obtaining GrandSlam PET after verification")

		session, err = gsa.LoginAfterVerification(ctx, input.Email, input.Password, securitykey.Interaction{Status: interaction.Status})
	}

	if err != nil {
		return LoginOutput{}, fmt.Errorf("security-key GrandSlam login: %w", err)
	}

	if countryCode := phoneNumberStorefrontCountryCode(input.Email); countryCode != "" {
		if _, err = t.discoverStorefrontID(countryCode); err != nil {
			return LoginOutput{}, fmt.Errorf("failed to discover storefronts: %w", err)
		}
	}

	status("security-key: preparing signed Store PET exchange")

	mac, err := t.machine.MacAddress()
	if err != nil {
		return LoginOutput{}, fmt.Errorf("get machine address: %w", err)
	}

	guid, machineID, err := machineIdentity(mac)
	if err != nil {
		return LoginOutput{}, err
	}

	bag, err := t.bag(ctx, guid)
	if err != nil {
		return LoginOutput{}, fmt.Errorf("security-key Store bag: %w", err)
	}

	if t.actionSignerFactory == nil {
		return LoginOutput{}, errors.New("SAP action signer is not configured")
	}

	signer, err := t.actionSignerFactory(ctx, bag.SAPConfig, machineID)
	if err != nil {
		return LoginOutput{}, fmt.Errorf("security-key SAP setup: %w", err)
	}

	if signer == nil {
		return LoginOutput{}, errors.New("SAP action signer factory returned nil")
	}

	// Isolate Store cookies from GSA cookies so GSA session cookies are neither sent to Store nor persisted.
	storeJar, err := cookiejar.New(nil)
	if err != nil {
		return LoginOutput{}, fmt.Errorf("create Store cookie jar: %w", err)
	}

	cookies := &securityKeyStoreCookies{CookieJar: storeJar}
	storeClient := storeauth.NewHTTPClient(cookies)
	acc, nextAnisetteState, exchangeErr := t.exchangeSecurityKeyStoreSession(ctx, storeClient, input.Email, guid, machineID, bag.AuthEndpoint, session, signer, persistedState, localHeaders, identityState, status)
	closeErr := signer.Close()

	if exchangeErr != nil {
		return LoginOutput{}, errors.Join(fmt.Errorf("security-key Store exchange: %w", exchangeErr), closeErr)
	}

	if closeErr != nil {
		return LoginOutput{}, fmt.Errorf("security-key SAP close: %w", closeErr)
	}

	if err := ctx.Err(); err != nil {
		return LoginOutput{}, fmt.Errorf("security-key login cancelled: %w", err)
	}

	acc, err = t.saveSecurityKeySession(acc, cookies, nextAnisetteState)
	if err != nil {
		return LoginOutput{}, err
	}

	if len(nextAnisetteState) > 0 {
		t.anisetteState = nextAnisetteState
	}

	status("security-key: Store credentials and cookies saved")

	return LoginOutput{Account: acc}, nil
}

func (t *appstore) exchangeSecurityKeyStoreSession(
	ctx context.Context,
	storeClient *http.Client,
	email string,
	guid string,
	machineID []byte,
	authEndpoint string,
	session *securitykey.GrandSlamSession,
	signer ActionSigner,
	persistedState []byte,
	localHeaders http.Header,
	identityState []byte,
	status func(string),
) (Account, []byte, error) {
	if !t.hasSecurityKeyStoreAMD() {
		acc, err := t.exchangeSecurityKeySession(ctx, storeClient, email, guid, authEndpoint, session, signer, status)

		return acc, nil, err
	}

	auth := t.securityKeyAuth()

	sendWithHeaders := func(headers http.Header) (Account, error) {
		t.authenticationHeaders = headers.Clone()

		defer func() { t.authenticationHeaders = nil }()

		return t.exchangeSecurityKeySession(ctx, storeClient, email, guid, authEndpoint, session, signer, status)
	}

	if len(persistedState) != 0 {
		proof, nextState, proofErr := auth.storeAMDHeaders(ctx, persistedState, authEndpoint, machineID)
		if proofErr == nil {
			proofHeaders := make(http.Header, len(proof))

			for key, value := range proof {
				proofHeaders.Set(key, value)
			}

			acc, err := sendWithHeaders(proofHeaders)
			if err == nil {
				return acc, nextState, nil
			}

			var action *authenticationMachineActionError
			if !errors.As(err, &action) {
				return Account{}, nil, err
			}
		}
	}

	if localHeaders == nil || len(identityState) == 0 {
		var err error

		localHeaders, identityState, err = auth.anisetteHeaders(ctx, storeClient, persistedState)
		if err != nil {
			return Account{}, nil, fmt.Errorf("prepare Apple authentication: %w", err)
		}
	}

	acc, err := sendWithHeaders(localHeaders)
	if err == nil {
		return acc, identityState, nil
	}

	var action *authenticationMachineActionError
	if errors.As(err, &action) && action.action == "RP" {
		stripped := localHeaders.Clone()

		for _, key := range []string{"X-Apple-I-MD", "X-Apple-I-MD-M", "X-Apple-I-MD-RINFO"} {
			stripped.Del(key)
		}

		acc, err = sendWithHeaders(stripped)
		if err == nil {
			return acc, identityState, nil
		}
	}

	if !errors.As(err, &action) || action.action != "SP" {
		return Account{}, nil, err
	}

	kbsync, err := t.generateKBSync(ctx, machineID, ^uint64(1))
	if err != nil {
		return Account{}, nil, fmt.Errorf("generate Apple Store provisioning kbsync: %w", err)
	}

	provisioned, err := auth.provisionStoreAnisette(ctx, storeClient, identityState, action.data, privateAppStoreProvisioningURL, storeAuthenticationUserAgent, kbsync, machineID, localHeaders)
	if err != nil {
		return Account{}, nil, fmt.Errorf("complete Apple Store provisioning: %w", err)
	}

	proof, nextState, err := auth.storeAMDHeaders(ctx, provisioned, authEndpoint, machineID)
	if err != nil {
		return Account{}, nil, fmt.Errorf("prepare Store AMD proof: %w", err)
	}

	proofHeaders := make(http.Header, len(proof))

	for key, value := range proof {
		proofHeaders.Set(key, value)
	}

	acc, err = sendWithHeaders(proofHeaders)
	if err != nil {
		return Account{}, nil, err
	}

	return acc, nextState, nil
}

type securityKeyStoreCookies struct {
	http.CookieJar
	responses []struct {
		origin  url.URL
		cookies []*http.Cookie
	}
}

func (j *securityKeyStoreCookies) SetCookies(origin *url.URL, cookies []*http.Cookie) {
	j.CookieJar.SetCookies(origin, cookies)
	j.responses = append(j.responses, struct {
		origin  url.URL
		cookies []*http.Cookie
	}{*origin, cookies})
}

func (t *appstore) saveSecurityKeyAccount(acc Account, cookies *securityKeyStoreCookies) (Account, error) {
	return t.saveSecurityKeySession(acc, cookies, nil)
}

func (t *appstore) saveSecurityKeySession(acc Account, cookies *securityKeyStoreCookies, anisetteState []byte) (Account, error) {
	if t.keychain == nil {
		return Account{}, errors.New("keychain is not configured")
	}

	// Hardware-key accounts never silently fall back to password/OTP on expiry.
	acc.SecurityKey = true
	acc.Password = ""

	data, err := json.Marshal(acc)
	if err != nil {
		return Account{}, fmt.Errorf("encode security-key account: %w", err)
	}

	jar, ok := t.cookieJar.(interface {
		CommitCookies(func(http.CookieJar), func() error) error
	})
	if !ok {
		return Account{}, errors.New("store cookie storage does not support transactional login")
	}

	err = jar.CommitCookies(func(jar http.CookieJar) {
		for _, response := range cookies.responses {
			jar.SetCookies(&response.origin, response.cookies)
		}
	}, func() error {
		if len(anisetteState) > 0 {
			if err := t.keychain.Set(anisetteKeychainKey, anisetteState); err != nil {
				return fmt.Errorf("save Apple authentication state: %w", err)
			}
		}

		if err := t.keychain.Set("account", data); err != nil {
			return fmt.Errorf("save security-key account: %w", err)
		}

		return nil
	})
	if err != nil {
		return Account{}, fmt.Errorf("commit security-key account: %w", err)
	}

	return acc, nil
}

func (t *appstore) exchangeSecurityKeySession(ctx context.Context, client *http.Client, email, guid, authEndpoint string, session *securitykey.GrandSlamSession, signer ActionSigner, status func(string)) (Account, error) {
	if session == nil || session.PET == "" || session.ADSID == "" {
		return Account{}, errors.New("GrandSlam returned no PET or ADSID")
	}

	if err := validateAuthenticationEndpoint(authEndpoint); err != nil {
		return Account{}, err
	}

	// Use the ordinary Store request shape, but only the GSA PET as its password.
	request := t.loginRequest(email, session.PET, "", guid, authEndpoint, 1, signer)

	body, err := plist.Marshal(request.Payload.(*storehttp.XMLPayload).Content, plist.XMLFormat)
	if err != nil {
		return Account{}, fmt.Errorf("encode Store request: %w", err)
	}

	defer clear(body)

	endpoint, _ := url.Parse(authEndpoint)
	bounded := *client
	bounded.Timeout = 30 * time.Second
	bounded.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	if status == nil {
		status = func(string) {}
	}

	redirects, attempt := 0, 1
	for redirects <= maxAuthenticationRedirects {
		if err := ctx.Err(); err != nil {
			return Account{}, fmt.Errorf("store exchange cancelled: %w", err)
		}

		signature, err := signer.Sign(body)
		if err != nil {
			return Account{}, errors.New("store request signing failed")
		}

		if len(signature) == 0 {
			return Account{}, errors.New("store request signature is empty")
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
		if err != nil {
			return Account{}, fmt.Errorf("create Store request: %w", err)
		}

		for key, value := range request.Headers {
			req.Header.Set(key, value)
		}

		req.Header.Set("X-Apple-ActionSignature", base64.StdEncoding.EncodeToString(signature))

		res, err := bounded.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return Account{}, fmt.Errorf("store exchange cancelled: %w", ctx.Err())
			}

			return Account{}, errors.New("store credential exchange transport failed")
		}

		data, readErr := io.ReadAll(io.LimitReader(res.Body, (1<<20)+1))
		res.Body.Close()

		contentType, _, mimeErr := mime.ParseMediaType(res.Header.Get("Content-Type"))
		if mimeErr != nil {
			contentType = "unknown"
		}

		correlation := res.Header.Get("X-Apple-Jingle-Correlation-Key")
		if len(correlation) > 128 || strings.IndexFunc(correlation, func(r rune) bool {
			return (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && !strings.ContainsRune("-_:.", r)
		}) >= 0 {
			correlation = "redacted"
		}

		metadata := fmt.Sprintf("HTTP %d, content-type=%q, bytes=%d, correlation-id=%q, endpoint=%s%s, redirects=%d, attempt=%d/%d", res.StatusCode, contentType, len(data), correlation, endpoint.Hostname(), endpoint.Path, redirects, attempt, maxAuthenticationRequestAttempts)
		status("security-key: Store response: " + metadata)

		if readErr != nil || len(data) > 1<<20 {
			return Account{}, errors.New("store credential response unreadable or too large")
		}

		if action := strings.TrimSpace(res.Header.Get("X-Apple-AMD-Action")); action != "" {
			return Account{}, &authenticationMachineActionError{
				action: action,
				data:   strings.TrimSpace(res.Header.Get("X-Apple-AMD-Data")),
			}
		}

		if res.StatusCode >= 300 && res.StatusCode < 400 {
			if !storehttp.IsAuthenticationRedirect(res.StatusCode) {
				return Account{}, errors.New("unsupported legacy Store redirect status")
			}

			destination, redirectErr := resolveAuthenticationRedirect(endpoint.String(), res.Header.Get("Location"))
			if redirectErr != nil {
				return Account{}, errors.New("refusing untrusted legacy Store redirect")
			}

			endpoint, _ = url.Parse(destination)
			redirects++

			continue
		}

		var result loginResult
		parseErr := storehttp.DecodePropertyList(data, &result)

		format := "plist"
		if len(bytes.TrimSpace(data)) == 0 {
			format = "empty"
		} else if parseErr != nil {
			format = "undecodable-plist"
		}

		responseErr := &storehttp.UnexpectedResponseError{StatusCode: res.StatusCode, ContentType: contentType, BodyLength: len(data), CorrelationID: correlation, Reason: "Store PET exchange response: " + format, RetryAfter: res.Header.Get("Retry-After")}
		_, retryable := retryableAuthenticationError(responseErr)
		// Share the ordinary login's status policy, without replaying decoded credential errors.
		unexpected := parseErr != nil || len(data) == 0 || res.StatusCode/100 == 5
		if unexpected && retryable && result.FailureType == "" && result.PasswordToken == "" {
			status("security-key: Store response format: " + format)

			if attempt == maxAuthenticationRequestAttempts {
				return Account{}, fmt.Errorf("store exchange exhausted %d attempts (%s): %w", attempt, metadata, responseErr)
			}

			delay := min(authenticationRetryDelay<<(attempt-1), maxAuthenticationRetryDelay)

			if requested, ok := authenticationRetryAfter(responseErr.RetryAfter, time.Now()); ok {
				if requested > maxAuthenticationRetryDelay {
					return Account{}, fmt.Errorf("server requested a wait longer than %s; try again later (%s): %w", maxAuthenticationRetryDelay, metadata, responseErr)
				}

				delay = max(requested, time.Second)
			}

			status(fmt.Sprintf("security-key: retrying Store exchange in %s (attempt %d/%d; no new key touch)", delay, attempt+1, maxAuthenticationRequestAttempts))
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()

				return Account{}, fmt.Errorf("store retry cancelled: %w", ctx.Err())
			case <-timer.C:
			}

			attempt++

			continue
		}

		if parseErr != nil {
			return Account{}, fmt.Errorf("store response could not be decoded (%s): %w", metadata, responseErr)
		}

		if dialogErr := authenticationDialogError(result); dialogErr != nil {
			return Account{}, dialogErr
		}

		if result.CustomerMessage == CustomerMessageBadLogin && result.FailureType == "" {
			return Account{}, fmt.Errorf("store returned generic Configurator bad-login response after PET exchange (%s); no Store credentials issued", metadata)
		}

		directoryServicesID := securityKeyResponseDSID(result, res.Header)
		if res.StatusCode != http.StatusOK || result.FailureType != "" || result.PasswordToken == "" || directoryServicesID == "" {
			return Account{}, fmt.Errorf("store rejected PET exchange (%s, failure present: %t, token present: %t)", metadata, result.FailureType != "", result.PasswordToken != "")
		}

		if session.DSID > 0 && directoryServicesID != strconv.FormatInt(session.DSID, 10) {
			return Account{}, errors.New("store account identity does not match GrandSlam")
		}

		storefront := res.Header.Get(HTTPHeaderStoreFront)
		if storefront == "" {
			storefront = res.Header.Get(HTTPHeaderRequestStoreFront)
		}

		if storefront == "" {
			return Account{}, errors.New("store credential response has no storefront")
		}

		accountEmail := result.Account.Email
		if accountEmail == "" {
			accountEmail = email
		}

		return Account{Email: accountEmail, Name: strings.TrimSpace(result.Account.Address.FirstName + " " + result.Account.Address.LastName), PasswordToken: result.PasswordToken, DirectoryServicesID: directoryServicesID, StoreFront: storefront, Pod: res.Header.Get(HTTPHeaderPod)}, nil
	}

	return Account{}, errors.New("too many legacy Store authentication redirects")
}

func securityKeyResponseDSID(result loginResult, headers http.Header) string {
	if result.DirectoryServicesID != "" {
		return result.DirectoryServicesID
	}

	if dsid := strings.TrimSpace(headers.Get("X-Dsid")); dsid != "" {
		return dsid
	}

	for _, cookie := range headers.Values("Set-Cookie") {
		match := storeCookieDSIDPattern.FindStringSubmatch(cookie)
		if len(match) == 2 {
			return match[1]
		}
	}

	return ""
}
