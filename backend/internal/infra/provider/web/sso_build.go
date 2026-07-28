package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	accountdomain "github.com/chenyme/grok2api/backend/internal/domain/account"
	egressdomain "github.com/chenyme/grok2api/backend/internal/domain/egress"
	infraegress "github.com/chenyme/grok2api/backend/internal/infra/egress"
	"github.com/chenyme/grok2api/backend/internal/infra/provider"
	cliprovider "github.com/chenyme/grok2api/backend/internal/infra/provider/cli"
	"github.com/chenyme/grok2api/backend/internal/infra/provider/xaiauth"
	"github.com/chenyme/grok2api/backend/internal/infra/security"
	"github.com/chenyme/grok2api/backend/internal/infra/sso2oauth"
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
	agentID    string // stable from SSO session_id / hash

	softPreflight        bool
	skipConvertInitUser  bool
	skipConvertBotReject bool
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

	// §16 daemon switch: if the Python sso2oauth daemon is running,
	// route through curl_cffi chrome136 (BoringSSL TLS fingerprint,
	// CF JS challenge bypass). Otherwise fall back to Go tls-client
	// (uTLS) with a warning — CF interception probability is high.
	a.mu.RLock()
	daemonClient := a.sso2oauthClient
	a.mu.RUnlock()

	var seed provider.CredentialSeed
	if daemonClient != nil {
		seed, err = a.convertViaDaemon(requestCtx, credential, token, lease, daemonClient)
	} else {
		a.log().Warn("sso2oauth_daemon_unavailable_fallback",
			"warning", "Go tls-client impersonate 精度不足 (uTLS vs BoringSSL)，CF 拦截概率高")
		cfg := a.config()
		browserUA := strings.TrimSpace(lease.UserAgent)
		if browserUA == "" {
			browserUA = xaiauth.DefaultBrowserUA
		}
		cliVersion := strings.TrimSpace(cfg.BuildClientVersion)
		if cliVersion == "" {
			cliVersion = xaiauth.DefaultCLIVersion
		}
		flow := &ssoBuildFlow{
			client: lease, userAgent: browserUA, cliVersion: cliVersion,
			cookies:              map[string]string{"sso": token, "sso-rw": token},
			agentID:              xaiauth.StableAgentIDFromSSO(token),
			softPreflight:        cfg.ConvertSoftPreflight,
			skipConvertInitUser:  cfg.SkipConvertInitUser,
			skipConvertBotReject: cfg.SkipConvertBotReject,
		}
		// Seed the flow cookie jar with Cloudflare clearance cookies from the lease
		// so HTML steps on accounts.x.ai / auth.x.ai carry the same cf_clearance /
		// __cf_bm the rest of the Web egress uses. Without this, the SSO2OAUTH flow
		// hits Cloudflare JS challenges that the Go TLS client cannot solve.
		for part := range strings.SplitSeq(strings.TrimSpace(lease.CFCookies), ";") {
			name, value, ok := strings.Cut(strings.TrimSpace(part), "=")
			if !ok {
				continue
			}
			name = strings.TrimSpace(name)
			value = strings.TrimSpace(value)
			if name != "" && value != "" && flow.cookies[name] == "" {
				flow.cookies[name] = value
			}
		}
		seed, err = flow.convert(requestCtx, credential)
	}
	if err != nil {
		a.egress.Feedback(context.WithoutCancel(ctx), lease.NodeID, conversionStatus(err), err)
		return provider.CredentialSeed{}, err
	}
	a.egress.Feedback(context.WithoutCancel(ctx), lease.NodeID, http.StatusOK, nil)
	return seed, nil
}

// convertViaDaemon routes the SSO→OAuth conversion through the Python
// daemon (curl_cffi chrome136). The daemon handles the full 9-phase
// flow with BoringSSL TLS fingerprinting that Go's tls-client cannot
// replicate. Errors are wrapped in the same types as the Go path so
// ClassifyConversionError and conversionStatus work uniformly.
func (a *Adapter) convertViaDaemon(ctx context.Context, credential accountdomain.Credential, token string, lease *infraegress.Lease, client *sso2oauth.Client) (provider.CredentialSeed, error) {
	cfg := a.config()
	cliVersion := strings.TrimSpace(cfg.BuildClientVersion)
	if cliVersion == "" {
		cliVersion = xaiauth.DefaultCLIVersion
	}
	browserUA := strings.TrimSpace(lease.UserAgent)
	if browserUA == "" {
		browserUA = xaiauth.DefaultBrowserUA
	}
	req := sso2oauth.ConvertRequest{
		SsoToken:   token,
		ProxyURL:   lease.ProxyURL,
		UserAgent:  browserUA,
		CFCookies:  lease.CFCookies,
		CLIVersion: cliVersion,
		Options: sso2oauth.ConvertOptions{
			SoftPreflight: cfg.ConvertSoftPreflight,
			SkipInitUser:  cfg.SkipConvertInitUser,
			SkipBotReject: cfg.SkipConvertBotReject,
		},
	}
	resp, err := client.Convert(ctx, req)
	if err != nil {
		return provider.CredentialSeed{}, fmt.Errorf("sso2oauth daemon 不可达: %w", err)
	}
	if !resp.OK {
		return provider.CredentialSeed{}, a.classifyDaemonError(resp)
	}
	return a.buildSeedFromDaemon(resp, credential)
}

// classifyDaemonError maps the daemon's ConvertResponse error fields
// to the same error types the Go path uses, so ClassifyConversionError
// and conversionStatus can classify both paths uniformly.
func (a *Adapter) classifyDaemonError(resp *sso2oauth.ConvertResponse) error {
	phase := resp.ErrorPhase
	msg := resp.ErrorMessage
	status := resp.ErrorStatus
	var wrapped error
	switch {
	case status == http.StatusUnauthorized && strings.Contains(phase, "probe_accounts"):
		wrapped = provider.ErrUnauthorized
	case status == http.StatusTooManyRequests:
		wrapped = conversionHTTPError{status: status}
	case status >= 500 && status < 600:
		wrapped = conversionHTTPError{status: status}
	case status == http.StatusBadRequest && strings.Contains(msg, "access_denied"):
		wrapped = provider.ErrAuthorizationDenied
	case strings.Contains(msg, "bot_flag"):
		wrapped = ErrBuildTokenBotContaminated
	default:
		wrapped = conversionHTTPError{status: status}
	}
	return fmt.Errorf("sso2oauth[%s] %s: %w", phase, msg, wrapped)
}

// buildSeedFromDaemon constructs a CredentialSeed from the daemon's
// successful response. The daemon returns parsed identity/bot_flag, but
// Go independently re-parses the JWT claims (defense in depth — does
// not trust Python-side parsing for security-critical fields).
func (a *Adapter) buildSeedFromDaemon(resp *sso2oauth.ConvertResponse, credential accountdomain.Credential) (provider.CredentialSeed, error) {
	if resp.Tokens == nil {
		return provider.CredentialSeed{}, fmt.Errorf("sso2oauth daemon 返回成功但无 tokens")
	}
	// Go 端独立解析 JWT（不信任 Python 的 identity）
	userID, email, teamID, accessClaims := xaiauth.IdentityFromTokens(resp.Tokens.AccessToken, resp.Tokens.IDToken)
	botClass, botRaw := xaiauth.ClassifyConvertBot(accessClaims)
	cfg := a.config()
	if botClass == xaiauth.ConvertBotContaminated && !cfg.SkipConvertBotReject {
		return provider.CredentialSeed{}, fmt.Errorf("%w: %s", ErrBuildTokenBotContaminated, botRaw)
	}
	// 记录 phase trace 到 Debug 日志
	if a.log().Enabled(context.Background(), slog.LevelDebug) {
		a.log().Debug("sso2oauth_daemon_trace", "phases", resp.Phases)
	}
	name := strings.TrimSpace(credential.Name)
	if name == "" {
		name = "Grok Web account"
	}
	return provider.CredentialSeed{
		Provider:     accountdomain.ProviderBuild,
		AuthType:     accountdomain.AuthTypeOAuth,
		Name:         firstValue(email, name+" Build", userID, "Grok Build account"),
		Email:        email,
		UserID:       userID,
		TeamID:       teamID,
		SourceKey:    "sso-build:" + security.HashToken(resp.Tokens.AccessToken),
		OIDCClientID: ssoBuildClientID,
		AccessToken:  resp.Tokens.AccessToken,
		RefreshToken: resp.Tokens.RefreshToken,
		ExpiresAt:    time.Now().Add(time.Duration(resp.Tokens.ExpiresIn) * time.Second),
		PreloadedBilling: parseDaemonEnrichmentBilling(resp),
		PreloadedModels:  parseDaemonEnrichmentModels(resp),
	}, nil
}

// parseDaemonEnrichmentBilling parses the daemon's enrichment billing and
// subscription data into an account.Billing. Mirrors the logic in
// cli.Adapter.GetBilling: ParseBilling from /v1/billing?format=credits,
// then ParseSubscriptionTier from /v1/user?include=subscription overrides
// PlanName, with SubscriptionTierFromJWT as the final fallback. Returns
// nil when no billing data was preloaded (caller skips preload).
func parseDaemonEnrichmentBilling(resp *sso2oauth.ConvertResponse) *accountdomain.Billing {
	if resp.Enrichment == nil || len(resp.Enrichment.BillingRaw) == 0 {
		return nil
	}
	billing, err := cliprovider.ParseBilling(resp.Enrichment.BillingRaw)
	if err != nil {
		return nil
	}
	if len(resp.Enrichment.SubscriptionRaw) > 0 {
		if tier, tErr := cliprovider.ParseSubscriptionTier(resp.Enrichment.SubscriptionRaw); tErr == nil && tier != "" {
			billing.PlanName = tier
		}
	}
	if billing.PlanCode == "" && billing.PlanName == "" {
		billing.PlanName = cliprovider.SubscriptionTierFromJWT(resp.Tokens.AccessToken)
	}
	return &billing
}

// parseDaemonEnrichmentModels extracts the model ID list from the
// daemon's enrichment data. Returns nil when no models were preloaded.
func parseDaemonEnrichmentModels(resp *sso2oauth.ConvertResponse) []string {
	if resp.Enrichment == nil || len(resp.Enrichment.Models) == 0 {
		return nil
	}
	return resp.Enrichment.Models
}

func (f *ssoBuildFlow) convert(ctx context.Context, credential accountdomain.Credential) (provider.CredentialSeed, error) {
	status, finalURL, _, err := f.do(ctx, http.MethodGet, ssoAccountsURL, nil, xaiauth.BrowserAccounts)
	if err != nil {
		return provider.CredentialSeed{}, sso2oauthTransport("probe_accounts", http.MethodGet, ssoAccountsURL, err)
	}
	if status == http.StatusUnauthorized || strings.Contains(finalURL, "sign-in") || strings.Contains(finalURL, "sign-up") {
		return provider.CredentialSeed{}, fmt.Errorf("sso2oauth[probe_accounts] SSO 无效或未登录 (status=%d final=%s): %w", status, shortURL(finalURL), provider.ErrUnauthorized)
	}
	if status < 200 || status >= 400 {
		return provider.CredentialSeed{}, fmt.Errorf("sso2oauth[probe_accounts] 校验 Grok Web SSO 失败 (status=%d final=%s): %w", status, shortURL(finalURL), conversionHTTPError{status: status})
	}

	if f.softPreflight {
		f.runSoftPreflight(ctx) // fail-open
	}

	status, body, err := f.postDeviceCode(ctx)
	if err != nil {
		return provider.CredentialSeed{}, sso2oauthTransport("device_code", http.MethodPost, ssoDeviceURL, err)
	}
	if status < 200 || status >= 300 {
		return provider.CredentialSeed{}, fmt.Errorf("sso2oauth[device_code] Device Flow 启动失败 POST %s (status=%d body=%s): %w", ssoDeviceURL, status, shortBody(body), conversionHTTPError{status: status})
	}
	var device struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete"`
		Interval                int    `json:"interval"`
		ExpiresIn               int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &device); err != nil {
		return provider.CredentialSeed{}, fmt.Errorf("sso2oauth[device_code] 解析响应失败 body=%s: %w", shortBody(body), err)
	}
	if device.DeviceCode == "" || device.UserCode == "" || !safeXAIURL(device.VerificationURIComplete) {
		return provider.CredentialSeed{}, fmt.Errorf("sso2oauth[device_code] 返回字段不完整 user_code=%q verification_uri=%q verification_uri_complete=%q", device.UserCode, device.VerificationURI, device.VerificationURIComplete)
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
		return provider.CredentialSeed{}, sso2oauthTransport("verify_page", http.MethodGet, device.VerificationURIComplete, err)
	}
	if status < 200 || status >= 400 {
		return provider.CredentialSeed{}, fmt.Errorf("sso2oauth[verify_page] 打开验证页失败 GET %s (status=%d final=%s): %w", shortURL(device.VerificationURIComplete), status, shortURL(finalURL), conversionHTTPError{status: status})
	}
	status, finalURL, _, err = f.do(ctx, http.MethodPost, ssoVerifyURL, url.Values{"user_code": {device.UserCode}}, xaiauth.BrowserVerify)
	if err != nil {
		return provider.CredentialSeed{}, sso2oauthTransport("device_verify", http.MethodPost, ssoVerifyURL, err)
	}
	if status < 200 || status >= 400 {
		return provider.CredentialSeed{}, fmt.Errorf("sso2oauth[device_verify] 自动验证失败 user_code=%s (status=%d final=%s): %w", device.UserCode, status, shortURL(finalURL), conversionHTTPError{status: status})
	}
	if !strings.Contains(finalURL, "consent") {
		return provider.CredentialSeed{}, fmt.Errorf("sso2oauth[device_verify] 未进入 consent 页 user_code=%s status=%d final=%s (期望 URL 含 consent；可能 SSO 会话未带上或被重定向到登录/错误页)", device.UserCode, status, shortURL(finalURL))
	}
	f.consentURL = finalURL
	status, finalURL, _, err = f.do(ctx, http.MethodPost, ssoApproveURL, url.Values{
		"user_code": {device.UserCode}, "action": {"allow"}, "principal_type": {"User"}, "principal_id": {""},
	}, xaiauth.BrowserApprove)
	if err != nil {
		return provider.CredentialSeed{}, sso2oauthTransport("device_approve", http.MethodPost, ssoApproveURL, err)
	}
	if status < 200 || status >= 400 {
		return provider.CredentialSeed{}, fmt.Errorf("sso2oauth[device_approve] 自动批准失败 user_code=%s (status=%d final=%s): %w", device.UserCode, status, shortURL(finalURL), conversionHTTPError{status: status})
	}
	if !strings.Contains(finalURL, "done") {
		return provider.CredentialSeed{}, fmt.Errorf("sso2oauth[device_approve] 批准后未到 done 页 user_code=%s status=%d final=%s (期望 URL 含 done)", device.UserCode, status, shortURL(finalURL))
	}

	token, err := f.pollToken(ctx, device.DeviceCode, time.Duration(device.Interval)*time.Second, time.Duration(device.ExpiresIn)*time.Second)
	if err != nil {
		return provider.CredentialSeed{}, fmt.Errorf("sso2oauth[token_poll] user_code=%s: %w", device.UserCode, err)
	}
	userID, email, teamID, accessClaims := xaiauth.IdentityFromTokens(token.AccessToken, token.IDToken)
	botClass, botRaw := xaiauth.ClassifyConvertBot(accessClaims)
	if botClass == xaiauth.ConvertBotContaminated && !f.skipConvertBotReject {
		return provider.CredentialSeed{}, fmt.Errorf("%w: %s", ErrBuildTokenBotContaminated, botRaw)
	}
	// Full CLI init enrichment (sso2oauth phase 05); fail-open; identity preferred when present.
	if !f.skipConvertInitUser {
		uid, em, tid := f.runCLIEnrichment(ctx, token.AccessToken, userID, email)
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

// postDeviceCode POSTs device/code with short 429 backoff (capture: device rate limits under batch convert).
func (f *ssoBuildFlow) postDeviceCode(ctx context.Context) (int, []byte, error) {
	form := xaiauth.DeviceCodeForm(ssoBuildClientID, ssoBuildScope)
	var lastStatus int
	var lastBody []byte
	for attempt := 1; attempt <= xaiauth.MaxFormAttempts; attempt++ {
		status, body, retryAfter, err := f.postCLIAuthForm(ctx, ssoDeviceURL, form)
		if err != nil {
			return 0, nil, err
		}
		lastStatus, lastBody = status, body
		if status == http.StatusTooManyRequests && attempt < xaiauth.MaxFormAttempts {
			if err := xaiauth.Sleep(ctx, xaiauth.ClampBackoff(retryAfter)); err != nil {
				return status, body, err
			}
			continue
		}
		return status, body, nil
	}
	return lastStatus, lastBody, nil
}

func (f *ssoBuildFlow) postCLIAuthForm(ctx context.Context, endpoint string, form url.Values) (int, []byte, time.Duration, error) {
	if !safeXAIURL(endpoint) {
		return 0, nil, 0, fmt.Errorf("xAI OAuth URL 不安全")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, nil, 0, err
	}
	xaiauth.ApplyCLIAuthForm(req, xaiauth.FormOptions{Version: f.cliVersion, Surface: xaiauth.SurfaceUI})
	resp, err := f.client.Do(req)
	if err != nil {
		return 0, nil, 0, fmt.Errorf("POST %s: %w", endpoint, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxAuthBody+1))
	if err != nil {
		return resp.StatusCode, nil, 0, err
	}
	if len(data) > maxAuthBody {
		return resp.StatusCode, nil, 0, fmt.Errorf("xAI OAuth 响应超过 2 MiB")
	}
	return resp.StatusCode, data, xaiauth.ParseRetryAfter(resp.Header), nil
}

// runSoftPreflight hits stable + login-config with CLI heads; errors are ignored (fail-open).
func (f *ssoBuildFlow) runSoftPreflight(ctx context.Context) {
	if req, err := http.NewRequestWithContext(ctx, http.MethodGet, xaiauth.CLIStableURL, nil); err == nil {
		xaiauth.ApplyCLIProbeHeaders(req)
		if resp, err := f.client.Do(req); err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
			_ = resp.Body.Close()
		}
	}
	if req, err := http.NewRequestWithContext(ctx, http.MethodGet, xaiauth.LoginConfigURL, nil); err == nil {
		xaiauth.ApplyLoginConfigHeaders(req, f.cliVersion, f.agentID)
		if resp, err := f.client.Do(req); err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
			_ = resp.Body.Close()
		}
	}
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
			return ssoBuildToken{}, fmt.Errorf("解析 xAI OAuth Token (status=%d body=%s): %w", status, shortBody(body), err)
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
			return ssoBuildToken{}, fmt.Errorf("token grant %s (%s): %w", payload.Error, firstValue(payload.ErrorDescription, payload.Error), provider.ErrAuthorizationDenied)
		default:
			if status >= 400 {
				return ssoBuildToken{}, fmt.Errorf("xAI OAuth Token 失败 error=%s desc=%s body=%s: %w", payload.Error, payload.ErrorDescription, shortBody(body), conversionHTTPError{status: status})
			}
			return ssoBuildToken{}, fmt.Errorf("xAI OAuth Token 失败 status=%d error=%s desc=%s body=%s", status, payload.Error, payload.ErrorDescription, shortBody(body))
		}
	}
	return ssoBuildToken{}, fmt.Errorf("xAI Device Flow 轮询超时 (deadline=%s)", deadline.UTC().Format(time.RFC3339))
}

// runCLIEnrichment mirrors sso2oauth phase 05: user → settings → models → bundle → billing → subscription.
// Non-2xx and network errors are fail-open; identity is taken from the first successful /v1/user.
func (f *ssoBuildFlow) runCLIEnrichment(ctx context.Context, accessToken, userID, email string) (outUserID, outEmail, outTeamID string) {
	outUserID, outEmail = strings.TrimSpace(userID), strings.TrimSpace(email)
	// 05a GET /v1/user (base auth headers)
	if uid, em, tid, ok := f.getCLIJSON(ctx, xaiauth.UserURL, accessToken, xaiauth.EnrichmentOptions{}); ok {
		if uid != "" {
			outUserID = uid
		}
		if em != "" {
			outEmail = em
		}
		if tid != "" {
			outTeamID = tid
		}
	}
	enrich := xaiauth.EnrichmentOptions{
		UserID: outUserID, Email: outEmail, AgentID: f.agentID, IncludeShellIdentifier: true,
	}
	// 05b settings
	_, _, _, _ = f.getCLIJSON(ctx, xaiauth.SettingsURL, accessToken, enrich)
	// 05c models
	_, _, _, _ = f.getCLIJSON(ctx, xaiauth.ModelsURL, accessToken, enrich)
	// 05d bundle/archive (binary-ish; discard body)
	_ = f.getCLIRaw(ctx, xaiauth.BundleURL, accessToken, enrich)
	// 05e billing
	_, _, _, _ = f.getCLIJSON(ctx, xaiauth.BillingURL, accessToken, enrich)
	// 05g subscription (user with include)
	if uid, em, tid, ok := f.getCLIJSON(ctx, xaiauth.SubscriptionURL, accessToken, xaiauth.EnrichmentOptions{AgentID: f.agentID}); ok {
		if uid != "" {
			outUserID = uid
		}
		if em != "" {
			outEmail = em
		}
		if tid != "" {
			outTeamID = tid
		}
	}
	return outUserID, outEmail, outTeamID
}

func (f *ssoBuildFlow) getCLIJSON(ctx context.Context, endpoint, accessToken string, opts xaiauth.EnrichmentOptions) (userID, email, teamID string, ok bool) {
	data, status, err := f.getCLIBytes(ctx, endpoint, accessToken, opts)
	if err != nil || status < 200 || status >= 300 || len(data) == 0 {
		return "", "", "", false
	}
	var payload struct {
		UserID string `json:"userId"`
		Email  string `json:"email"`
		TeamID string `json:"teamId"`
	}
	if json.Unmarshal(data, &payload) != nil {
		return "", "", "", true // HTTP OK but non-identity payload
	}
	return strings.TrimSpace(payload.UserID), strings.TrimSpace(payload.Email), strings.TrimSpace(payload.TeamID), true
}

func (f *ssoBuildFlow) getCLIRaw(ctx context.Context, endpoint, accessToken string, opts xaiauth.EnrichmentOptions) bool {
	_, status, err := f.getCLIBytes(ctx, endpoint, accessToken, opts)
	return err == nil && status >= 200 && status < 300
}

func (f *ssoBuildFlow) getCLIBytes(ctx context.Context, endpoint, accessToken string, opts xaiauth.EnrichmentOptions) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, 0, err
	}
	if opts.UserID != "" || opts.Email != "" || opts.IncludeShellIdentifier || opts.AgentID != "" {
		xaiauth.ApplyCLIEnrichmentHeaders(req, accessToken, f.cliVersion, opts)
	} else {
		xaiauth.ApplyCLIApiMeta(req, accessToken, f.cliVersion)
		if agent := strings.TrimSpace(opts.AgentID); agent != "" {
			req.Header.Set("x-grok-agent-id", agent)
		}
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxAuthBody))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return data, resp.StatusCode, nil
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
			return 0, "", nil, fmt.Errorf("%s %s: %w", currentMethod, currentURL, err)
		}
		f.captureCookies(response)
		data, readErr := io.ReadAll(io.LimitReader(response.Body, maxAuthBody+1))
		_ = response.Body.Close()
		if readErr != nil {
			return response.StatusCode, currentURL, nil, fmt.Errorf("read %s %s: %w", currentMethod, currentURL, readErr)
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
	case strings.Contains(msg, "timeout") || strings.Contains(msg, "deadline exceeded") || strings.Contains(msg, "connection reset") || strings.Contains(msg, "connection refused") || strings.Contains(msg, "broken pipe") || strings.Contains(msg, "temporary") || strings.Contains(msg, "unexpected eof") || strings.HasSuffix(msg, ": eof") || strings.Contains(msg, " eof") || strings.Contains(msg, "transport closed"):
		return ConversionClassNetworkRetry
	case strings.Contains(msg, "too many") || strings.Contains(msg, "rate limit") || strings.Contains(msg, "429"):
		return ConversionClassRateLimited
	case strings.Contains(msg, "access denied") || strings.Contains(msg, "authorization denied") || strings.Contains(msg, "expired_token"):
		return ConversionClassPermanent
	default:
		return ConversionClassUnknown
	}
}

// sso2oauthTransport wraps upstream transport failures with phase + URL + human hint.
func sso2oauthTransport(phase, method, endpoint string, err error) error {
	if err == nil {
		return nil
	}
	hint := transportHint(err)
	msg := err.Error()
	// do()/postCLIAuthForm already prefix METHOD URL; avoid doubling.
	if strings.Contains(msg, endpoint) || strings.HasPrefix(msg, method+" ") {
		if hint != "" {
			return fmt.Errorf("sso2oauth[%s]: %w (%s)", phase, err, hint)
		}
		return fmt.Errorf("sso2oauth[%s]: %w", phase, err)
	}
	if hint != "" {
		return fmt.Errorf("sso2oauth[%s] %s %s: %w (%s)", phase, method, shortURL(endpoint), err, hint)
	}
	return fmt.Errorf("sso2oauth[%s] %s %s: %w", phase, method, shortURL(endpoint), err)
}

func transportHint(err error) string {
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "connection refused") && strings.Contains(msg, "12334"):
		return "本地代理 12334 不可用"
	case strings.Contains(msg, "broken pipe") && strings.Contains(msg, "12334"):
		return "本地代理连接被重置"
	case strings.Contains(msg, "unexpected eof") || strings.HasSuffix(msg, ": eof") || strings.Contains(msg, " eof"):
		return "传输中断/对端或代理提前关闭连接，通常不是 SSO 失效"
	case strings.Contains(msg, "deadline exceeded") || strings.Contains(msg, "timeout"):
		return "请求超时"
	case strings.Contains(msg, "connection reset"):
		return "连接被重置"
	default:
		return ""
	}
}

func shortURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if len(raw) <= 160 {
		return raw
	}
	return raw[:157] + "..."
}

func shortBody(body []byte) string {
	s := strings.Join(strings.Fields(string(body)), " ")
	if s == "" {
		return ""
	}
	if len(s) > 160 {
		return s[:157] + "..."
	}
	return s
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
