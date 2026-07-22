package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	accountdomain "github.com/chenyme/grok2api/backend/internal/domain/account"
	egressdomain "github.com/chenyme/grok2api/backend/internal/domain/egress"
	infraegress "github.com/chenyme/grok2api/backend/internal/infra/egress"
	"github.com/chenyme/grok2api/backend/internal/infra/provider"
	"github.com/chenyme/grok2api/backend/internal/infra/provider/xaiauth"
	"github.com/chenyme/grok2api/backend/internal/infra/security"
)

const (
	ssoBuildClientID = xaiauth.ClientID
	ssoBuildScope    = xaiauth.DefaultScope
	ssoAccountsURL   = "https://accounts.x.ai/"
	ssoDeviceURL     = xaiauth.DeviceCodeURL
	ssoVerifyURL     = xaiauth.VerifyURL
	ssoApproveURL    = xaiauth.ApproveURL
	ssoTokenURL      = xaiauth.TokenURL
	maxAuthBody      = 2 << 20
)

// ErrBuildTokenBotContaminated is returned when access_token bot_flag_source is non-NP pollution.
var ErrBuildTokenBotContaminated = errors.New("build token bot_flag contaminated")

type ssoBuildHTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

type ssoBuildFlow struct {
	client     ssoBuildHTTPClient
	userAgent  string // browser UA for HTML steps (from egress lease when set)
	cliVersion string
	cookies    map[string]string
	userCode   string
	consentURL string
}

func (a *Adapter) ConvertToBuild(ctx context.Context, credential accountdomain.Credential) (provider.CredentialSeed, error) {
	if credential.Provider != accountdomain.ProviderWeb || credential.AuthType != accountdomain.AuthTypeSSO {
		return provider.CredentialSeed{}, fmt.Errorf("仅 Grok Web SSO 账号支持转换")
	}
	token, err := a.cipher.Decrypt(credential.EncryptedAccessToken)
	if err != nil {
		return provider.CredentialSeed{}, fmt.Errorf("解密 Grok Web SSO: %w", err)
	}
	token = normalizeSSOToken(token)
	if token == "" {
		return provider.CredentialSeed{}, provider.ErrUnauthorized
	}
	lease, err := a.egress.AcquireCredential(ctx, egressdomain.ScopeWeb, credential)
	if err != nil {
		return provider.CredentialSeed{}, err
	}
	defer lease.Release()
	requestCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	browserUA := strings.TrimSpace(lease.UserAgent)
	if browserUA == "" {
		browserUA = xaiauth.DefaultBrowserUA
	}
	flow := &ssoBuildFlow{
		client: lease, userAgent: browserUA, cliVersion: xaiauth.DefaultCLIVersion,
		cookies: map[string]string{"sso": token, "sso-rw": token},
	}
	seed, err := flow.convert(requestCtx, credential)
	if err != nil {
		a.egress.Feedback(context.WithoutCancel(ctx), lease.NodeID, conversionStatus(err), err)
		return provider.CredentialSeed{}, err
	}
	a.egress.Feedback(context.WithoutCancel(ctx), lease.NodeID, http.StatusOK, nil)
	return seed, nil
}

func (f *ssoBuildFlow) convert(ctx context.Context, credential accountdomain.Credential) (provider.CredentialSeed, error) {
	status, finalURL, _, err := f.do(ctx, http.MethodGet, ssoAccountsURL, nil, xaiauth.BrowserAccounts)
	if err != nil {
		return provider.CredentialSeed{}, err
	}
	if status == http.StatusUnauthorized || strings.Contains(finalURL, "sign-in") || strings.Contains(finalURL, "sign-up") {
		return provider.CredentialSeed{}, provider.ErrUnauthorized
	}
	if status < 200 || status >= 400 {
		return provider.CredentialSeed{}, fmt.Errorf("校验 Grok Web SSO 失败: %w", conversionHTTPError{status: status})
	}

	form := xaiauth.DeviceCodeForm(ssoBuildClientID, ssoBuildScope)
	status, _, body, err := f.do(ctx, http.MethodPost, ssoDeviceURL, form, "")
	if err != nil {
		return provider.CredentialSeed{}, err
	}
	if status < 200 || status >= 300 {
		return provider.CredentialSeed{}, fmt.Errorf("xAI Device Flow 启动失败: %w", conversionHTTPError{status: status})
	}
	var device struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURIComplete string `json:"verification_uri_complete"`
		Interval                int    `json:"interval"`
		ExpiresIn               int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &device); err != nil {
		return provider.CredentialSeed{}, fmt.Errorf("解析 xAI Device Flow: %w", err)
	}
	if device.DeviceCode == "" || device.UserCode == "" || !safeXAIURL(device.VerificationURIComplete) {
		return provider.CredentialSeed{}, fmt.Errorf("xAI Device Flow 返回字段不完整")
	}
	if device.Interval <= 0 {
		device.Interval = 5
	}
	if device.ExpiresIn <= 0 {
		device.ExpiresIn = 1800
	}
	f.userCode = device.UserCode

	status, finalURL, _, err = f.do(ctx, http.MethodGet, device.VerificationURIComplete, nil, xaiauth.BrowserVerifyPage)
	if err != nil {
		return provider.CredentialSeed{}, err
	}
	if status < 200 || status >= 400 {
		return provider.CredentialSeed{}, fmt.Errorf("打开 Device Flow 验证页失败: %w", conversionHTTPError{status: status})
	}
	status, finalURL, _, err = f.do(ctx, http.MethodPost, ssoVerifyURL, url.Values{"user_code": {device.UserCode}}, xaiauth.BrowserVerify)
	if err != nil {
		return provider.CredentialSeed{}, err
	}
	if status < 200 || status >= 400 {
		return provider.CredentialSeed{}, fmt.Errorf("SSO 自动验证 Device Flow 失败: %w", conversionHTTPError{status: status})
	}
	if !strings.Contains(finalURL, "consent") {
		return provider.CredentialSeed{}, fmt.Errorf("SSO 自动验证 Device Flow 失败")
	}
	f.consentURL = finalURL
	status, finalURL, _, err = f.do(ctx, http.MethodPost, ssoApproveURL, url.Values{
		"user_code": {device.UserCode}, "action": {"allow"}, "principal_type": {"User"}, "principal_id": {""},
	}, xaiauth.BrowserApprove)
	if err != nil {
		return provider.CredentialSeed{}, err
	}
	if status < 200 || status >= 400 {
		return provider.CredentialSeed{}, fmt.Errorf("SSO 自动批准 Device Flow 失败: %w", conversionHTTPError{status: status})
	}
	if !strings.Contains(finalURL, "done") {
		return provider.CredentialSeed{}, fmt.Errorf("SSO 自动批准 Device Flow 失败")
	}

	token, err := f.pollToken(ctx, device.DeviceCode, time.Duration(device.Interval)*time.Second, time.Duration(device.ExpiresIn)*time.Second)
	if err != nil {
		return provider.CredentialSeed{}, err
	}
	userID, email, teamID, accessClaims := xaiauth.IdentityFromTokens(token.AccessToken, token.IDToken)
	botClass, botRaw := xaiauth.ClassifyConvertBot(accessClaims)
	if botClass == xaiauth.ConvertBotContaminated {
		return provider.CredentialSeed{}, fmt.Errorf("%w: %s", ErrBuildTokenBotContaminated, botRaw)
	}
	// Prefer live /v1/user identity when reachable (C0-5 minimal enrichment).
	if uid, em, tid, userErr := f.fetchCLIUser(ctx, token.AccessToken); userErr == nil {
		if uid != "" {
			userID = uid
		}
		if em != "" {
			email = em
		}
		if tid != "" {
			teamID = tid
		}
	}
	name := strings.TrimSpace(credential.Name)
	if name == "" {
		name = "Grok Web account"
	}
	return provider.CredentialSeed{
		Provider: accountdomain.ProviderBuild, AuthType: accountdomain.AuthTypeOAuth,
		Name: firstValue(email, name+" Build", userID, "Grok Build account"), Email: email, UserID: userID, TeamID: teamID,
		SourceKey: "sso-build:" + security.HashToken(token.AccessToken), OIDCClientID: ssoBuildClientID,
		AccessToken: token.AccessToken, RefreshToken: token.RefreshToken, ExpiresAt: token.ExpiresAt,
	}, nil
}

type ssoBuildToken struct {
	AccessToken  string
	RefreshToken string
	IDToken      string
	ExpiresAt    time.Time
}

func (f *ssoBuildFlow) pollToken(ctx context.Context, deviceCode string, interval, expiresIn time.Duration) (ssoBuildToken, error) {
	if interval < time.Second {
		interval = time.Second
	}
	deadline := time.Now().Add(min(expiresIn, 75*time.Second))
	for time.Now().Before(deadline) {
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ssoBuildToken{}, ctx.Err()
		case <-timer.C:
		}
		status, _, body, err := f.do(ctx, http.MethodPost, ssoTokenURL, url.Values{
			"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "client_id": {ssoBuildClientID}, "device_code": {deviceCode},
		}, "")
		if err != nil {
			return ssoBuildToken{}, err
		}
		var payload struct {
			AccessToken      string `json:"access_token"`
			RefreshToken     string `json:"refresh_token"`
			IDToken          string `json:"id_token"`
			ExpiresIn        int    `json:"expires_in"`
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			return ssoBuildToken{}, fmt.Errorf("解析 xAI OAuth Token: %w", err)
		}
		if status >= 200 && status < 300 && payload.AccessToken != "" {
			if payload.ExpiresIn <= 0 {
				payload.ExpiresIn = 3600
			}
			return ssoBuildToken{AccessToken: payload.AccessToken, RefreshToken: payload.RefreshToken, IDToken: payload.IDToken, ExpiresAt: time.Now().UTC().Add(time.Duration(payload.ExpiresIn) * time.Second)}, nil
		}
		switch payload.Error {
		case "authorization_pending":
			continue
		case "slow_down":
			interval += 5 * time.Second
			continue
		case "access_denied", "expired_token":
			return ssoBuildToken{}, provider.ErrAuthorizationDenied
		default:
			if status >= 400 {
				return ssoBuildToken{}, fmt.Errorf("xAI OAuth Token 失败 (%s): %w", firstValue(payload.ErrorDescription, payload.Error), conversionHTTPError{status: status})
			}
			return ssoBuildToken{}, fmt.Errorf("xAI OAuth Token 失败: %s", firstValue(payload.ErrorDescription, payload.Error, strconv.Itoa(status)))
		}
	}
	return ssoBuildToken{}, fmt.Errorf("xAI Device Flow 轮询超时")
}

func (f *ssoBuildFlow) fetchCLIUser(ctx context.Context, accessToken string) (userID, email, teamID string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, xaiauth.UserURL, nil)
	if err != nil {
		return "", "", "", err
	}
	xaiauth.ApplyCLIApiMeta(req, accessToken, f.cliVersion)
	resp, err := f.client.Do(req)
	if err != nil {
		return "", "", "", err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxAuthBody))
	if err != nil {
		return "", "", "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", "", "", conversionHTTPError{status: resp.StatusCode}
	}
	var payload struct {
		UserID string `json:"userId"`
		Email  string `json:"email"`
		TeamID string `json:"teamId"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return "", "", "", err
	}
	return strings.TrimSpace(payload.UserID), strings.TrimSpace(payload.Email), strings.TrimSpace(payload.TeamID), nil
}

// do performs one Convert step. browserStep empty means CLIAuthForm when endpoint is device/token;
// otherwise BrowserAuthHTML with the given step (and Cookie jar).
func (f *ssoBuildFlow) do(ctx context.Context, method, endpoint string, form url.Values, browserStep xaiauth.BrowserStep) (int, string, []byte, error) {
	if !safeXAIURL(endpoint) {
		return 0, "", nil, fmt.Errorf("xAI OAuth URL 不安全")
	}
	currentURL := endpoint
	currentMethod := method
	currentForm := form
	currentStep := browserStep
	for redirects := 0; redirects <= 8; redirects++ {
		var body io.Reader
		if currentForm != nil {
			body = strings.NewReader(currentForm.Encode())
		}
		request, err := http.NewRequestWithContext(ctx, currentMethod, currentURL, body)
		if err != nil {
			return 0, "", nil, err
		}
		cliForm := xaiauth.IsCLIAuthFormURL(currentURL) && currentForm != nil
		if cliForm {
			opts := xaiauth.FormOptions{Version: f.cliVersion, Surface: xaiauth.SurfaceUI}
			xaiauth.ApplyCLIAuthForm(request, opts)
			// Capture: device/token form does not attach SSO cookies.
		} else {
			step := currentStep
			if step == "" {
				step = xaiauth.BrowserDocument
			}
			// On redirect after verify, treat as consent document navigation.
			if redirects > 0 && step == xaiauth.BrowserVerify {
				step = xaiauth.BrowserConsent
			}
			if redirects > 0 && step == xaiauth.BrowserApprove {
				step = xaiauth.BrowserDocument
			}
			xaiauth.ApplyBrowserAuthHTML(request, f.userAgent, step, f.userCode, f.consentURL)
			if cookie := f.cookieHeader(); cookie != "" {
				request.Header.Set("Cookie", cookie)
			}
		}
		response, err := f.client.Do(request)
		if err != nil {
			return 0, "", nil, err
		}
		f.captureCookies(response)
		data, readErr := io.ReadAll(io.LimitReader(response.Body, maxAuthBody+1))
		_ = response.Body.Close()
		if readErr != nil {
			return response.StatusCode, currentURL, nil, readErr
		}
		if len(data) > maxAuthBody {
			return response.StatusCode, currentURL, nil, fmt.Errorf("xAI OAuth 响应超过 2 MiB")
		}
		if response.StatusCode < 300 || response.StatusCode > 399 {
			return response.StatusCode, currentURL, data, nil
		}
		location := strings.TrimSpace(response.Header.Get("Location"))
		if location == "" {
			return response.StatusCode, currentURL, data, fmt.Errorf("xAI OAuth 重定向缺少 Location")
		}
		base, _ := url.Parse(currentURL)
		next, err := url.Parse(location)
		if err != nil {
			return response.StatusCode, currentURL, data, err
		}
		currentURL = base.ResolveReference(next).String()
		if !safeXAIURL(currentURL) {
			return response.StatusCode, currentURL, data, fmt.Errorf("xAI OAuth 重定向到非受信域名")
		}
		if response.StatusCode == http.StatusSeeOther || ((response.StatusCode == http.StatusMovedPermanently || response.StatusCode == http.StatusFound) && currentMethod != http.MethodGet && currentMethod != http.MethodHead) {
			currentMethod = http.MethodGet
			currentForm = nil
		}
	}
	return 0, currentURL, nil, fmt.Errorf("xAI OAuth 重定向次数过多")
}

func (f *ssoBuildFlow) captureCookies(response *http.Response) {
	for _, cookie := range response.Cookies() {
		name := strings.TrimSpace(cookie.Name)
		value := strings.TrimSpace(cookie.Value)
		if name == "" || len(name) > 128 || len(value) > 16384 || strings.ContainsAny(name+value, "\r\n\x00") {
			continue
		}
		if cookie.MaxAge < 0 {
			delete(f.cookies, name)
			continue
		}
		f.cookies[name] = value
	}
}

func (f *ssoBuildFlow) cookieHeader() string {
	keys := make([]string, 0, len(f.cookies))
	for key := range f.cookies {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+f.cookies[key])
	}
	return strings.Join(parts, "; ")
}

func safeXAIURL(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Hostname() == "" {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	return host == "x.ai" || strings.HasSuffix(host, ".x.ai")
}

func normalizeSSOToken(value string) string {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(strings.ToLower(value), "sso=") {
		value = strings.TrimSpace(value[len("sso="):])
	}
	if token, _, found := strings.Cut(value, ";"); found {
		value = strings.TrimSpace(token)
	}
	return strings.NewReplacer("\r", "", "\n", "", "\x00", "").Replace(value)
}

func firstValue(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

type conversionHTTPError struct{ status int }

func (e conversionHTTPError) Error() string { return fmt.Sprintf("xAI OAuth HTTP %d", e.status) }

func (e conversionHTTPError) HTTPStatusCode() int { return e.status }

func conversionStatus(err error) int {
	if status, ok := provider.ErrorHTTPStatus(err); ok {
		return status
	}
	if errors.Is(err, provider.ErrUnauthorized) {
		return http.StatusUnauthorized
	}
	return 0
}

// ConversionErrorClass is a stable code for batch convert UI and retry policy.
type ConversionErrorClass string

const (
	ConversionClassSSODead      ConversionErrorClass = "sso_dead"
	ConversionClassRateLimited  ConversionErrorClass = "rate_limited"
	ConversionClassNetworkRetry ConversionErrorClass = "network_retry"
	ConversionClassPermanent    ConversionErrorClass = "permanent"
	ConversionClassBotFlag      ConversionErrorClass = "bot_contaminated"
	ConversionClassUnknown      ConversionErrorClass = "unknown"
)

// ClassifyConversionError maps ConvertToBuild failures for ops and batch backoff.
func ClassifyConversionError(err error) ConversionErrorClass {
	if err == nil {
		return ConversionClassUnknown
	}
	if errors.Is(err, ErrBuildTokenBotContaminated) {
		return ConversionClassBotFlag
	}
	if errors.Is(err, provider.ErrUnauthorized) {
		return ConversionClassSSODead
	}
	if status, ok := provider.ErrorHTTPStatus(err); ok {
		switch status {
		case http.StatusUnauthorized, http.StatusForbidden:
			return ConversionClassSSODead
		case http.StatusTooManyRequests:
			return ConversionClassRateLimited
		case http.StatusRequestTimeout, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
			return ConversionClassNetworkRetry
		default:
			if status >= 500 {
				return ConversionClassNetworkRetry
			}
			if status >= 400 {
				return ConversionClassPermanent
			}
		}
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "bot_flag") || strings.Contains(msg, "contaminated"):
		return ConversionClassBotFlag
	case strings.Contains(msg, "timeout") || strings.Contains(msg, "connection reset") || strings.Contains(msg, "connection refused") || strings.Contains(msg, "temporary"):
		return ConversionClassNetworkRetry
	case strings.Contains(msg, "too many") || strings.Contains(msg, "rate limit") || strings.Contains(msg, "429"):
		return ConversionClassRateLimited
	default:
		return ConversionClassUnknown
	}
}

// ConversionErrorRetriable reports whether batch convert should backoff and retry once more.
func ConversionErrorRetriable(err error) bool {
	switch ClassifyConversionError(err) {
	case ConversionClassRateLimited, ConversionClassNetworkRetry:
		return true
	default:
		return false
	}
}

var _ provider.BuildCredentialConverter = (*Adapter)(nil)
var _ ssoBuildHTTPClient = (*infraegress.Lease)(nil)
