package web

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	accountdomain "github.com/chenyme/grok2api/backend/internal/domain/account"
	"github.com/chenyme/grok2api/backend/internal/infra/provider/xaiauth"
)

type scriptedSSOClient struct {
	responses []*http.Response
	requests  []*http.Request
}

func (c *scriptedSSOClient) Do(request *http.Request) (*http.Response, error) {
	c.requests = append(c.requests, request)
	if len(c.responses) == 0 {
		return nil, errors.New("no scripted response")
	}
	response := c.responses[0]
	c.responses = c.responses[1:]
	return response, nil
}

func TestSSOBuildFlowFollowsOnlyTrustedXAIHTTPSRedirects(t *testing.T) {
	client := &scriptedSSOClient{responses: []*http.Response{
		{StatusCode: http.StatusFound, Header: http.Header{"Location": []string{"https://auth.x.ai/next"}, "Set-Cookie": []string{"session=abc; Path=/; Secure"}}, Body: io.NopCloser(strings.NewReader(""))},
		{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("ok"))},
	}}
	flow := &ssoBuildFlow{client: client, userAgent: "test-agent", cookies: map[string]string{"sso": "secret"}}
	status, finalURL, body, err := flow.do(context.Background(), http.MethodGet, ssoAccountsURL, nil, xaiauth.BrowserAccounts)
	if err != nil {
		t.Fatal(err)
	}
	if status != http.StatusOK || finalURL != "https://auth.x.ai/next" || string(body) != "ok" {
		t.Fatalf("response = %d %s %q", status, finalURL, body)
	}
	if len(client.requests) != 2 || client.requests[1].Header.Get("User-Agent") != "test-agent" {
		t.Fatalf("requests = %#v", client.requests)
	}
	cookie := client.requests[1].Header.Get("Cookie")
	if !strings.Contains(cookie, "sso=secret") || !strings.Contains(cookie, "session=abc") {
		t.Fatalf("redirect cookies = %q", cookie)
	}

	unsafe := &scriptedSSOClient{responses: []*http.Response{{StatusCode: http.StatusFound, Header: http.Header{"Location": []string{"https://example.com/steal"}}, Body: io.NopCloser(strings.NewReader(""))}}}
	flow = &ssoBuildFlow{client: unsafe, userAgent: "test-agent", cookies: map[string]string{"sso": "secret"}}
	if _, _, _, err := flow.do(context.Background(), http.MethodGet, ssoAccountsURL, nil, xaiauth.BrowserAccounts); err == nil {
		t.Fatal("unsafe redirect was accepted")
	}
}

func TestSSOBuildConversionSanitizesTokenAndURLs(t *testing.T) {
	if token := normalizeSSOToken("sso=token-value; x-userid=drop"); token != "token-value" {
		t.Fatalf("token = %q", token)
	}
	for _, value := range []string{"https://accounts.x.ai/", "https://auth.x.ai/oauth2/device/code"} {
		if !safeXAIURL(value) {
			t.Fatalf("trusted URL rejected: %s", value)
		}
	}
	for _, value := range []string{"http://auth.x.ai/", "https://x.ai.example.com/", "https://user@auth.x.ai/"} {
		if safeXAIURL(value) {
			t.Fatalf("unsafe URL accepted: %s", value)
		}
	}
}

func TestSSOBuildDeviceRetriesOn429(t *testing.T) {
	attempts := 0
	wrapped := &countingSSOClient{inner: func(req *http.Request) (*http.Response, error) {
		attempts++
		if attempts == 1 {
			h := make(http.Header)
			h.Set("Retry-After", "1")
			return &http.Response{StatusCode: http.StatusTooManyRequests, Header: h, Body: io.NopCloser(strings.NewReader(`rate`))}, nil
		}
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"device_code":"d","user_code":"u","verification_uri_complete":"https://accounts.x.ai/x","interval":5,"expires_in":600}`))}, nil
	}}
	flow := &ssoBuildFlow{client: wrapped, userAgent: "Mozilla/5.0", cliVersion: "0.2.106"}
	status, body, err := flow.postDeviceCode(context.Background())
	if err != nil || status != http.StatusOK {
		t.Fatalf("status=%d err=%v body=%s", status, err, body)
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d", attempts)
	}
	if !strings.Contains(string(body), "device_code") {
		t.Fatalf("body = %s", body)
	}
}

type countingSSOClient struct {
	inner func(*http.Request) (*http.Response, error)
}

func (c *countingSSOClient) Do(req *http.Request) (*http.Response, error) { return c.inner(req) }

func TestSSOBuildDeviceUsesCLIAuthForm(t *testing.T) {
	client := &scriptedSSOClient{responses: []*http.Response{
		{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"device_code":"d","user_code":"u","verification_uri_complete":"https://accounts.x.ai/x","interval":5,"expires_in":600}`))},
	}}
	flow := &ssoBuildFlow{client: client, userAgent: "Mozilla/5.0 test", cliVersion: "0.2.106", cookies: map[string]string{"sso": "secret"}}
	form := xaiauth.DeviceCodeForm(ssoBuildClientID, ssoBuildScope)
	status, _, _, err := flow.do(context.Background(), http.MethodPost, ssoDeviceURL, form, "")
	if err != nil || status != http.StatusOK {
		t.Fatalf("status=%d err=%v", status, err)
	}
	req := client.requests[0]
	ua := req.Header.Get("User-Agent")
	if !strings.Contains(ua, "grok-pager/") || !strings.Contains(ua, "grok-shell/") {
		t.Fatalf("device UA = %q", ua)
	}
	if req.Header.Get("Cookie") != "" {
		t.Fatalf("device form must not send SSO cookie, got %q", req.Header.Get("Cookie"))
	}
	if req.Header.Get("X-XAI-Token-Auth") != "" || req.Header.Get("Sec-Fetch-Mode") != "" {
		t.Fatalf("device form must not send Token-Auth/Sec-Fetch: %#v", req.Header)
	}
	if req.Header.Get("x-grok-client-surface") != "ui" {
		t.Fatalf("surface = %q", req.Header.Get("x-grok-client-surface"))
	}
	_ = req.ParseForm()
	if req.Form.Get("referrer") != "grok-build" || !strings.Contains(req.Form.Get("scope"), "workspaces:read") {
		t.Fatalf("form = %#v", req.Form)
	}
}

func TestSSOBuildTokenPollUsesCLIAuthForm(t *testing.T) {
	client := &scriptedSSOClient{responses: []*http.Response{
		{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"access_token":"a","expires_in":60}`))},
	}}
	flow := &ssoBuildFlow{client: client, userAgent: "Mozilla/5.0 test", cliVersion: "0.2.106", cookies: map[string]string{"sso": "secret"}}
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "client_id": {ssoBuildClientID}, "device_code": {"d"}}
	status, _, _, err := flow.do(context.Background(), http.MethodPost, ssoTokenURL, form, "")
	if err != nil || status != http.StatusOK {
		t.Fatalf("status=%d err=%v", status, err)
	}
	req := client.requests[0]
	if !strings.Contains(req.Header.Get("User-Agent"), "grok-pager/") {
		t.Fatalf("token UA = %q", req.Header.Get("User-Agent"))
	}
	if req.Header.Get("X-XAI-Token-Auth") != "" {
		t.Fatal("token poll must not send X-XAI-Token-Auth")
	}
	if req.Header.Get("Cookie") != "" {
		t.Fatal("token poll must not send SSO cookie")
	}
}

func TestSSOBuildBrowserStepsKeepBrowserUAAndCookie(t *testing.T) {
	client := &scriptedSSOClient{responses: []*http.Response{
		{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("ok"))},
	}}
	flow := &ssoBuildFlow{client: client, userAgent: "Mozilla/5.0 (Linux; Android 13) Chrome/136.0.0.0", cookies: map[string]string{"sso": "secret"}, userCode: "UC1"}
	_, _, _, err := flow.do(context.Background(), http.MethodPost, ssoVerifyURL, url.Values{"user_code": {"UC1"}}, xaiauth.BrowserVerify)
	if err != nil {
		t.Fatal(err)
	}
	req := client.requests[0]
	if !strings.Contains(req.Header.Get("User-Agent"), "Mozilla/") {
		t.Fatalf("UA = %q", req.Header.Get("User-Agent"))
	}
	if strings.Contains(req.Header.Get("User-Agent"), "grok-shell") {
		t.Fatal("verify must not use CLI UA")
	}
	if !strings.Contains(req.Header.Get("Cookie"), "sso=secret") {
		t.Fatalf("cookie = %q", req.Header.Get("Cookie"))
	}
}

func TestConvertRejectsContaminatedBotFlag(t *testing.T) {
	access := fakeJWT(map[string]any{"sub": "u1", "bot_flag_source": "automation"})
	id := fakeJWT(map[string]any{"email": "a@x.ai"})
	client := &scriptedSSOClient{responses: convertHappyPathResponses(access, id)}
	flow := &ssoBuildFlow{client: client, userAgent: xaiauth.DefaultBrowserUA, cliVersion: "0.2.106", cookies: map[string]string{"sso": "s"}}
	_, err := flow.convert(context.Background(), accountdomainCredential())
	if !errors.Is(err, ErrBuildTokenBotContaminated) {
		t.Fatalf("err = %v", err)
	}
	if ClassifyConversionError(err) != ConversionClassBotFlag {
		t.Fatalf("class = %s", ClassifyConversionError(err))
	}
	if ConversionErrorRetriable(err) {
		t.Fatal("bot contaminated must not retry")
	}
}

func TestConvertAcceptsCleanNPAndFillsIdentity(t *testing.T) {
	access := fakeJWT(map[string]any{"sub": "user-from-jwt", "team_id": "team-j", "bot_flag_source": "NP"})
	id := fakeJWT(map[string]any{"email": "jwt@x.ai"})
	// After token: full enrichment suite (user/settings/models/bundle/billing/subscription)
	responses := convertHappyPathResponses(access, id)
	responses = append(responses, enrichmentScriptedResponses()...)
	client := &scriptedSSOClient{responses: responses}
	flow := &ssoBuildFlow{
		client: client, userAgent: xaiauth.DefaultBrowserUA, cliVersion: "0.2.106",
		cookies: map[string]string{"sso": "s"}, agentID: "agent-test",
	}
	seed, err := flow.convert(context.Background(), accountdomainCredential())
	if err != nil {
		t.Fatal(err)
	}
	if seed.UserID != "user-live" || seed.Email != "live@x.ai" || seed.TeamID != "team-live" {
		t.Fatalf("seed identity = %#v", seed)
	}
	if seed.AccessToken != access {
		t.Fatalf("access token not preserved")
	}
	// Expect enrichment GETs after token: user, settings, models, bundle, billing, subscription
	var paths []string
	for _, req := range client.requests {
		if req.Method == http.MethodGet && strings.Contains(req.URL.Host, "cli-chat-proxy") {
			paths = append(paths, req.URL.Path)
			if strings.Contains(req.URL.Path, "/settings") {
				if req.Header.Get("x-userid") != "user-live" || req.Header.Get("x-grok-client-identifier") != "grok-shell" {
					t.Fatalf("settings enrichment headers = %#v", req.Header)
				}
			}
		}
	}
	joined := strings.Join(paths, ",")
	for _, need := range []string{"/v1/user", "/v1/settings", "/v1/models", "/v1/bundle/archive", "/v1/billing"} {
		if !strings.Contains(joined, need) {
			t.Fatalf("missing enrichment path %s in %v", need, paths)
		}
	}
}

func enrichmentScriptedResponses() []*http.Response {
	okJSON := func(body string) *http.Response {
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}
	}
	return []*http.Response{
		okJSON(`{"userId":"user-live","email":"live@x.ai","teamId":"team-live"}`), // user
		okJSON(`{"default_model":"grok-3","oauth2_client_id":"x"}`),               // settings
		okJSON(`{"data":[{"id":"grok-3"}]}`),                                      // models
		okJSON(`archive`),                                                         // bundle
		okJSON(`{"onDemandCap":0}`),                                               // billing
		okJSON(`{"userId":"user-live","email":"live@x.ai","teamId":"team-live"}`), // subscription
	}
}

func convertHappyPathResponses(access, id string) []*http.Response {
	// accounts → device → verify page → verify(redirect consent) → approve(redirect done) → token
	return []*http.Response{
		{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("accounts"))},
		{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"device_code":"dc","user_code":"UC","verification_uri_complete":"https://accounts.x.ai/oauth2/device?user_code=UC","interval":1,"expires_in":600}`))},
		{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("verify-page"))},
		{StatusCode: http.StatusFound, Header: http.Header{"Location": []string{"https://accounts.x.ai/oauth2/device/consent?user_code=UC"}}, Body: io.NopCloser(strings.NewReader(""))},
		{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("consent-html"))},
		{StatusCode: http.StatusFound, Header: http.Header{"Location": []string{"https://accounts.x.ai/oauth2/device/done"}}, Body: io.NopCloser(strings.NewReader(""))},
		{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("done"))},
		{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"access_token":"` + access + `","refresh_token":"r","id_token":"` + id + `","expires_in":3600}`))},
	}
}

func fakeJWT(claims map[string]any) string {
	payload, err := json.Marshal(claims)
	if err != nil {
		panic(err)
	}
	return "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"
}

func accountdomainCredential() accountdomain.Credential {
	return accountdomain.Credential{Name: "web"}
}
