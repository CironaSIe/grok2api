// Package xaiauth centralizes xAI OIDC / CLI auth fingerprints for device, token,
// browser consent, and related metadata calls. Capture SSOT: 抓包分析.md (0.2.106).
package xaiauth

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/chenyme/grok2api/backend/internal/infra/provider/browserheaders"
)

const (
	// ClientID is the official Grok CLI OAuth client.
	ClientID = "b1a00492-073a-47ea-816f-4c329264a828"
	// DefaultCLIVersion matches RecommendedBuildClientVersion / binary 0.2.106.
	DefaultCLIVersion = "0.2.106"
	// DefaultScope is default_oauth2_scopes() from grok-build 0.2.106 (includes workspaces).
	DefaultScope = "openid profile email offline_access grok-cli:access api:access conversations:read conversations:write workspaces:read workspaces:write"
	// DeviceReferrer is the device/code form field used by official CLI.
	DeviceReferrer = "grok-build"
	// SurfaceUI is used for device/code and device_code token poll.
	SurfaceUI = "ui"
	// TokenAuthValue is only for cli-chat-proxy API, never oauth form.
	TokenAuthValue = "xai-grok-cli"

	DeviceCodeURL = "https://auth.x.ai/oauth2/device/code"
	TokenURL      = "https://auth.x.ai/oauth2/token"
	VerifyURL     = "https://auth.x.ai/oauth2/device/verify"
	ApproveURL    = "https://auth.x.ai/oauth2/device/approve"
	UserURL       = "https://cli-chat-proxy.grok.com/v1/user"

	// DefaultBrowserUA matches sso2oauth / Python build_oidc_browser_headers.
	DefaultBrowserUA = "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.7103.0 Mobile Safari/537.36"
)

// DualCLIUserAgent renders capture-aligned dual product UA.
func DualCLIUserAgent(version string) string {
	version = strings.TrimSpace(version)
	if version == "" {
		version = DefaultCLIVersion
	}
	return fmt.Sprintf("grok-pager/%s grok-shell/%s (linux; aarch64)", version, version)
}

// FormOptions controls CLIAuthForm headers for auth.x.ai form POSTs.
type FormOptions struct {
	Version string
	// Surface when non-empty sets x-grok-client-surface and x-grok-client-version (device + device poll).
	// Refresh capture omits these; leave empty for refresh.
	Surface string
}

// ApplyCLIAuthForm sets device/token/refresh form headers per 0.2.106 capture.
// Does not set Origin, Referer, Sec-Fetch-*, or X-XAI-Token-Auth.
func ApplyCLIAuthForm(req *http.Request, opts FormOptions) {
	if req == nil {
		return
	}
	version := strings.TrimSpace(opts.Version)
	if version == "" {
		version = DefaultCLIVersion
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Encoding", "gzip, br, deflate")
	req.Header.Set("User-Agent", DualCLIUserAgent(version))
	// Strip any prior browser-ish headers if caller reused a request.
	req.Header.Del("Origin")
	req.Header.Del("Referer")
	req.Header.Del("Sec-Fetch-Dest")
	req.Header.Del("Sec-Fetch-Mode")
	req.Header.Del("Sec-Fetch-Site")
	req.Header.Del("X-XAI-Token-Auth")
	req.Header.Del("Sec-Ch-Ua")
	req.Header.Del("Sec-Ch-Ua-Mobile")
	req.Header.Del("Sec-Ch-Ua-Platform")
	req.Header.Del("Sec-Ch-Ua-Model")
	req.Header.Del("Sec-Ch-Ua-Arch")
	req.Header.Del("Sec-Ch-Ua-Bitness")
	if surface := strings.TrimSpace(opts.Surface); surface != "" {
		req.Header.Set("x-grok-client-surface", surface)
		req.Header.Set("x-grok-client-version", version)
	} else {
		req.Header.Del("x-grok-client-surface")
		req.Header.Del("x-grok-client-version")
	}
}

// DeviceCodeForm builds capture-aligned device/code body.
func DeviceCodeForm(clientID, scope string) url.Values {
	if strings.TrimSpace(clientID) == "" {
		clientID = ClientID
	}
	if strings.TrimSpace(scope) == "" {
		scope = DefaultScope
	}
	return url.Values{
		"client_id": {clientID},
		"scope":     {scope},
		"referrer":  {DeviceReferrer},
	}
}

// BrowserStep names HTML/consent navigation steps (Convert path).
type BrowserStep string

const (
	BrowserAccounts   BrowserStep = "accounts"
	BrowserVerifyPage BrowserStep = "verify_page"
	BrowserVerify     BrowserStep = "verify"
	BrowserConsent    BrowserStep = "consent"
	BrowserApprove    BrowserStep = "approve"
	BrowserDocument   BrowserStep = "document"
)

// ApplyBrowserAuthHTML sets browser identity for accounts verify/approve pages.
func ApplyBrowserAuthHTML(req *http.Request, browserUA string, step BrowserStep, userCode, referer string) {
	if req == nil {
		return
	}
	browserUA = strings.TrimSpace(browserUA)
	if browserUA == "" {
		browserUA = DefaultBrowserUA
	}
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("User-Agent", browserUA)
	req.Header.Del("X-XAI-Token-Auth")
	req.Header.Del("x-grok-client-surface")
	req.Header.Del("x-grok-client-version")
	userCode = strings.TrimSpace(userCode)
	referer = strings.TrimSpace(referer)
	switch step {
	case BrowserVerifyPage:
		req.Header.Set("Referer", "https://accounts.x.ai/oauth2/device")
	case BrowserVerify:
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", "https://accounts.x.ai")
		if userCode != "" {
			req.Header.Set("Referer", "https://accounts.x.ai/oauth2/device?user_code="+userCode)
		} else {
			req.Header.Set("Referer", "https://accounts.x.ai/oauth2/device")
		}
	case BrowserConsent:
		req.Header.Set("Referer", "https://auth.x.ai/oauth2/device/verify")
	case BrowserApprove:
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", "https://accounts.x.ai")
		if referer != "" {
			req.Header.Set("Referer", referer)
		} else if userCode != "" {
			req.Header.Set("Referer", "https://accounts.x.ai/oauth2/device/consent?user_code="+userCode)
		} else {
			req.Header.Set("Referer", "https://accounts.x.ai/")
		}
	case BrowserAccounts, BrowserDocument:
		req.Header.Set("Referer", "https://accounts.x.ai/")
	default:
		// keep Accept/UA only
	}
	browserheaders.ApplyChromiumClientHints(req.Header, browserUA)
}

// ApplyCLIApiMeta sets authenticated cli-chat-proxy metadata headers (e.g. GET /v1/user).
func ApplyCLIApiMeta(req *http.Request, accessToken, version string) {
	if req == nil {
		return
	}
	version = strings.TrimSpace(version)
	if version == "" {
		version = DefaultCLIVersion
	}
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Encoding", "gzip, br, deflate")
	req.Header.Set("User-Agent", DualCLIUserAgent(version))
	req.Header.Set("x-grok-client-version", version)
	req.Header.Set("x-grok-client-mode", "interactive")
	req.Header.Set("x-xai-token-auth", TokenAuthValue)
	if token := strings.TrimSpace(accessToken); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
}

// IsCLIAuthFormURL reports device/code or token endpoints.
func IsCLIAuthFormURL(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil {
		return false
	}
	path := parsed.Path
	return strings.Contains(path, "/oauth2/device/code") || strings.HasSuffix(path, "/oauth2/token") || strings.Contains(path, "/oauth2/token")
}
