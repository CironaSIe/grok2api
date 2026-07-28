// One-off step walk: compare sso2oauth-like convert path under Go tls-client + proxy.
// Modified: add statsig x-statsig-id to step 00 to test CF bypass.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
)

const (
	clientID     = "b1a00492-073a-47ea-816f-4c329264a828"
	scope        = "openid profile email offline_access grok-cli:access api:access conversations:read conversations:write workspaces:read workspaces:write"
	cliVer       = "0.2.112"
	cliUA        = "grok-pager/0.2.112 grok-shell/0.2.112 (linux; aarch64)"
	brUA         = "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.7103.0 Mobile Safari/537.36"
	proxyDef     = "http://127.0.0.1:12334"
	signerURL    = "https://grok.wodf.de/sign"
	grokBaseURL  = "https://grok.com"
)

var metaRe = regexp.MustCompile(`(?i)<meta\s+name=["']grok-site.{1,3}verification["']\s+content=["']([^"']+)["']`)

func main() {
	sso := strings.TrimSpace(os.Getenv("SSO"))
	if sso == "" && len(os.Args) > 1 {
		sso = strings.TrimSpace(os.Args[1])
	}
	sso = strings.TrimPrefix(sso, "sso=")
	if sso == "" {
		fmt.Fprintln(os.Stderr, "usage: SSO=... go run .   or  go run . <sso>")
		os.Exit(2)
	}
	proxy := os.Getenv("HTTPS_PROXY")
	if proxy == "" {
		proxy = os.Getenv("HTTP_PROXY")
	}
	if proxy == "" {
		proxy = proxyDef
	}
	profile := profiles.Chrome_133
	if p, ok := profiles.MappedTLSClients["chrome_136"]; ok {
		profile = p
	}
	opts := []tlsclient.HttpClientOption{
		tlsclient.WithTimeoutSeconds(60),
		tlsclient.WithClientProfile(profile),
		tlsclient.WithNotFollowRedirects(),
		tlsclient.WithProxyUrl(proxy),
		tlsclient.WithCookieJar(tlsclient.NewCookieJar()),
	}
	client, err := tlsclient.NewHttpClient(tlsclient.NewNoopLogger(), opts...)
	if err != nil {
		fail("client", err)
	}
	// seed cookies like Python
	u, _ := url.Parse("https://auth.x.ai/")
	client.SetCookies(u, []*fhttp.Cookie{
		{Name: "sso", Value: sso, Domain: ".x.ai", Path: "/"},
		{Name: "sso-rw", Value: sso, Domain: ".x.ai", Path: "/"},
	})
	// also seed sso cookie for grok.com
	gu, _ := url.Parse("https://grok.com/")
	client.SetCookies(gu, []*fhttp.Cookie{
		{Name: "sso", Value: sso, Domain: ".grok.com", Path: "/"},
		{Name: "sso-rw", Value: sso, Domain: ".grok.com", Path: "/"},
	})
	fmt.Printf("proxy=%s sso_len=%d profile=chrome(mapped)\n", proxy, len(sso))

	// ── statsig pre-step: GET grok.com/index → extract metaContent → POST signer ──
	var statsigID string
	step("statsig-0 GET grok.com/index", func() error {
		h := map[string]string{
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Accept-Language":           "zh-CN,zh;q=0.9,en;q=0.8",
			"Cache-Control":             "no-cache",
			"Pragma":                    "no-cache",
			"Sec-Fetch-Dest":            "document",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-Site":            "same-origin",
			"Upgrade-Insecure-Requests": "1",
			"User-Agent":                brUA,
		}
		st, _, body, err := do(client, "GET", grokBaseURL+"/index", nil, h)
		fmt.Printf("  status=%d body_len=%d\n", st, len(body))
		if err != nil {
			return err
		}
		if st != 200 {
			fmt.Printf("  body_preview=%s\n", short(string(body), 200))
			return fmt.Errorf("grok.com/index returned %d", st)
		}
		m := metaRe.FindSubmatch(body)
		if m == nil {
			fmt.Printf("  body_preview=%s\n", short(string(body), 300))
			return fmt.Errorf("grok-site-verification meta not found")
		}
		metaContent := string(m[1])
		fmt.Printf("  metaContent=%s... (len=%d)\n", metaContent[:min(40, len(metaContent))], len(metaContent))
		// POST to signer
		signPayload, _ := json.Marshal(map[string]any{
			"method": "GET",
			"path":   "/",
			"environment": map[string]string{
				"metaContent": metaContent,
			},
		})
		req, _ := fhttp.NewRequest("POST", signerURL, strings.NewReader(string(signPayload)))
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		signBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		fmt.Printf("  signer status=%d body=%s\n", resp.StatusCode, short(string(signBody), 200))
		if resp.StatusCode != 200 {
			return fmt.Errorf("signer returned %d", resp.StatusCode)
		}
		var signResult struct {
			StatsigID string `json:"x-statsig-id"`
		}
		if json.Unmarshal(signBody, &signResult) != nil || signResult.StatsigID == "" {
			return fmt.Errorf("signer response invalid")
		}
		statsigID = signResult.StatsigID
		fmt.Printf("  x-statsig-id=%s... (len=%d)\n", statsigID[:min(40, len(statsigID))], len(statsigID))
		return nil
	})

	// 00 accounts — try with and without statsig
	step("00a GET accounts.x.ai/ (no statsig)", func() error {
		st, loc, _, err := do(client, "GET", "https://accounts.x.ai/", nil, brHeaders("https://accounts.x.ai/", ""))
		fmt.Printf("  status=%d loc=%s\n", st, short(loc, 80))
		return err
	})

	if statsigID != "" {
		step("00b GET accounts.x.ai/ (with statsig)", func() error {
			h := brHeaders("https://accounts.x.ai/", "")
			h["x-statsig-id"] = statsigID
			st, loc, body, err := do(client, "GET", "https://accounts.x.ai/", nil, h)
			fmt.Printf("  status=%d loc=%s body=%s\n", st, short(loc, 80), short(string(body), 200))
			return err
		})

		// also try auth.x.ai verify page with statsig
		step("00c GET auth.x.ai/ (with statsig)", func() error {
			h := brHeaders("https://auth.x.ai/", "")
			h["x-statsig-id"] = statsigID
			st, loc, body, err := do(client, "GET", "https://auth.x.ai/", nil, h)
			fmt.Printf("  status=%d loc=%s body=%s\n", st, short(loc, 80), short(string(body), 200))
			return err
		})
	}

	// 01 stable
	step("01 GET x.ai/cli/stable", func() error {
		st, _, body, err := do(client, "GET", "https://x.ai/cli/stable", nil, map[string]string{
			"Accept": "*/*", "Accept-Encoding": "gzip, br, deflate",
		})
		fmt.Printf("  status=%d body=%q\n", st, short(string(body), 80))
		return err
	})

	// 02 login-config
	step("02 GET login-config", func() error {
		h := map[string]string{
			"Accept": "*/*", "Accept-Encoding": "gzip, br, deflate",
			"User-Agent": cliUA, "x-grok-client-identifier": "grok-shell",
			"x-grok-client-mode": "interactive", "x-grok-client-version": cliVer,
		}
		st, _, body, err := do(client, "GET", "https://cli-chat-proxy.grok.com/v1/login-config", nil, h)
		fmt.Printf("  status=%d body=%s\n", st, short(string(body), 160))
		return err
	})

	// 03 discovery
	var deviceURL, tokenURL = "https://auth.x.ai/oauth2/device/code", "https://auth.x.ai/oauth2/token"
	step("03 OIDC discovery", func() error {
		st, _, body, err := do(client, "GET", "https://auth.x.ai/.well-known/openid-configuration", nil, map[string]string{"Accept": "*/*"})
		fmt.Printf("  status=%d\n", st)
		if err != nil {
			return err
		}
		var p struct {
			DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
			TokenEndpoint               string `json:"token_endpoint"`
		}
		_ = json.Unmarshal(body, &p)
		if p.DeviceAuthorizationEndpoint != "" {
			deviceURL = p.DeviceAuthorizationEndpoint
		}
		if p.TokenEndpoint != "" {
			tokenURL = p.TokenEndpoint
		}
		fmt.Printf("  device=%s\n  token=%s\n", deviceURL, tokenURL)
		return nil
	})

	var deviceCode, userCode, verifyComplete string
	// 04 device code
	step("04 device/code", func() error {
		form := url.Values{
			"client_id": {clientID}, "scope": {scope}, "referrer": {"grok-build"},
		}
		h := map[string]string{
			"Accept": "*/*", "Accept-Encoding": "gzip, br, deflate",
			"Content-Type": "application/x-www-form-urlencoded",
			"User-Agent": cliUA, "x-grok-client-surface": "ui", "x-grok-client-version": cliVer,
		}
		st, _, body, err := do(client, "POST", deviceURL, form, h)
		fmt.Printf("  status=%d body=%s\n", st, short(string(body), 200))
		if err != nil {
			return err
		}
		var p struct {
			DeviceCode              string `json:"device_code"`
			UserCode                string `json:"user_code"`
			VerificationURIComplete string `json:"verification_uri_complete"`
			Interval                int    `json:"interval"`
		}
		if json.Unmarshal(body, &p) != nil || p.DeviceCode == "" {
			return fmt.Errorf("bad device response")
		}
		deviceCode, userCode, verifyComplete = p.DeviceCode, p.UserCode, p.VerificationURIComplete
		fmt.Printf("  user_code=%s interval=%d\n", userCode, p.Interval)
		return nil
	})

	// 04a verify page — try with statsig
	step("04a GET verify page (with statsig)", func() error {
		h := brHeaders("https://accounts.x.ai/oauth2/device", "")
		if statsigID != "" {
			h["x-statsig-id"] = statsigID
		}
		st, loc, body, err := do(client, "GET", verifyComplete, nil, h)
		fmt.Printf("  status=%d loc=%s body=%s\n", st, short(loc, 80), short(string(body), 200))
		return err
	})

	// 04b verify post
	var consentURL string
	step("04b POST verify", func() error {
		form := url.Values{"user_code": {userCode}}
		h := brHeaders("https://accounts.x.ai/oauth2/device?user_code="+userCode, "https://accounts.x.ai")
		h["Content-Type"] = "application/x-www-form-urlencoded"
		if statsigID != "" {
			h["x-statsig-id"] = statsigID
		}
		st, loc, _, err := do(client, "POST", "https://auth.x.ai/oauth2/device/verify", form, h)
		fmt.Printf("  status=%d loc=%s\n", st, short(loc, 120))
		consentURL = loc
		if st >= 300 && st < 400 && strings.Contains(loc, "consent") {
			return nil
		}
		if err != nil {
			return err
		}
		if !strings.Contains(loc, "consent") {
			return fmt.Errorf("no consent redirect")
		}
		return nil
	})

	if consentURL != "" {
		step("04b GET consent (with statsig)", func() error {
			h := brHeaders("https://auth.x.ai/oauth2/device/verify", "")
			if statsigID != "" {
				h["x-statsig-id"] = statsigID
			}
			st, loc, body, err := do(client, "GET", consentURL, nil, h)
			fmt.Printf("  status=%d loc=%s body=%s\n", st, short(loc, 80), short(string(body), 200))
			return err
		})
	}

	// 04c approve
	step("04c POST approve", func() error {
		form := url.Values{
			"user_code": {userCode}, "action": {"allow"}, "principal_type": {"User"}, "principal_id": {""},
		}
		ref := consentURL
		if ref == "" {
			ref = "https://accounts.x.ai/oauth2/device/consent?user_code=" + userCode
		}
		h := brHeaders(ref, "https://accounts.x.ai")
		h["Content-Type"] = "application/x-www-form-urlencoded"
		if statsigID != "" {
			h["x-statsig-id"] = statsigID
		}
		st, loc, body, err := do(client, "POST", "https://auth.x.ai/oauth2/device/approve", form, h)
		fmt.Printf("  status=%d loc=%s body=%s\n", st, short(loc, 80), short(string(body), 80))
		return err
	})

	// 04c token poll
	step("04c token poll (5 tries)", func() error {
		h := map[string]string{
			"Accept": "*/*", "Accept-Encoding": "gzip, br, deflate",
			"Content-Type": "application/x-www-form-urlencoded",
			"User-Agent": cliUA, "x-grok-client-surface": "ui", "x-grok-client-version": cliVer,
		}
		for i := 1; i <= 5; i++ {
			time.Sleep(2 * time.Second)
			form := url.Values{
				"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
				"device_code": {deviceCode},
				"client_id":   {clientID},
			}
			st, _, body, err := do(client, "POST", tokenURL, form, h)
			fmt.Printf("  poll%d status=%d body=%s\n", i, st, short(string(body), 180))
			if err != nil {
				return err
			}
			var p struct {
				AccessToken string `json:"access_token"`
				Error       string `json:"error"`
				ErrorDesc   string `json:"error_description"`
			}
			_ = json.Unmarshal(body, &p)
			if p.AccessToken != "" {
				fmt.Printf("  TOKEN OK len=%d\n", len(p.AccessToken))
				return nil
			}
			if p.Error != "" && p.Error != "authorization_pending" && p.Error != "slow_down" {
				return fmt.Errorf("token error: %s (%s)", p.Error, p.ErrorDesc)
			}
		}
		return fmt.Errorf("token poll timeout")
	})
	fmt.Println("DONE")
}

func step(name string, fn func() error) {
	fmt.Println("==", name)
	if err := fn(); err != nil {
		fmt.Println("  ERR:", err)
	}
}

func brHeaders(referer, origin string) map[string]string {
	h := map[string]string{
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Accept-Language": "en-US,en;q=0.9",
		"User-Agent":      brUA,
	}
	if referer != "" {
		h["Referer"] = referer
	}
	if origin != "" {
		h["Origin"] = origin
	}
	return h
}

func do(client tlsclient.HttpClient, method, raw string, form url.Values, headers map[string]string) (int, string, []byte, error) {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := fhttp.NewRequest(method, raw, body)
	if err != nil {
		return 0, "", nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	loc := resp.Header.Get("Location")
	if loc != "" {
		base, _ := url.Parse(raw)
		if next, e := url.Parse(loc); e == nil && base != nil {
			loc = base.ResolveReference(next).String()
		}
	}
	return resp.StatusCode, loc, data, nil
}

func short(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

func fail(where string, err error) {
	fmt.Fprintln(os.Stderr, where, err)
	os.Exit(1)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
