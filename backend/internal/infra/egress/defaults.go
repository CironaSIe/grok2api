package egress

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	application "github.com/chenyme/grok2api/backend/internal/application/egress"
	"github.com/chenyme/grok2api/backend/internal/infra/config"
)

// DefaultSettings is the cluster-wide outbound fallback when no node proxy is used.
type DefaultSettings struct {
	Mode       string // env | url | direct
	ProxyURL   string // only for mode=url
	PreferIPv4 bool
}

// ResolveDefaultProxy returns a proxy URL and a stable source label (env|url|direct).
// mode=env uses HTTP_PROXY/HTTPS_PROXY/NO_PROXY via ProxyFromEnvironment for https://grok.com.
// Empty result means unproxied direct (caller may still PreferIPv4).
func ResolveDefaultProxy(settings DefaultSettings) (proxyURL, source string, err error) {
	mode := strings.ToLower(strings.TrimSpace(settings.Mode))
	if mode == "" {
		mode = config.EgressModeEnv
	}
	switch mode {
	case config.EgressModeDirect:
		return "", "direct", nil
	case config.EgressModeURL:
		raw := strings.TrimSpace(settings.ProxyURL)
		if raw == "" {
			return "", "url", fmt.Errorf("egress.defaultMode=url 但 defaultProxyURL 为空")
		}
		normalized, nerr := application.NormalizeProxyURL(raw)
		if nerr != nil {
			return "", "url", nerr
		}
		return normalized, "url", nil
	case config.EgressModeEnv:
		req, reqErr := http.NewRequest(http.MethodGet, "https://grok.com/", nil)
		if reqErr != nil {
			return "", "env", reqErr
		}
		proxyURLValue, proxyErr := http.ProxyFromEnvironment(req)
		if proxyErr != nil {
			return "", "env", proxyErr
		}
		if proxyURLValue == nil {
			return "", "env", nil
		}
		return proxyURLValue.String(), "env", nil
	default:
		return "", mode, fmt.Errorf("未知 egress.defaultMode %q", mode)
	}
}

// RedactProxyURL hides userinfo for logs.
func RedactProxyURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "(invalid)"
	}
	if parsed.User != nil {
		parsed.User = url.User("***")
	}
	return parsed.String()
}

// SettingsFromConfig maps config.EgressConfig to runtime settings.
func SettingsFromConfig(cfg config.EgressConfig) DefaultSettings {
	return DefaultSettings{
		Mode:       cfg.DefaultMode,
		ProxyURL:   cfg.DefaultProxyURL,
		PreferIPv4: cfg.PreferIPv4,
	}
}

// NewHTTPClientWithDefaults builds an http.Client that uses DefaultSettings for Proxy
// (and PreferIPv4 when unproxied). Used by statsig signer and similar non-lease clients.
func NewHTTPClientWithDefaults(settings DefaultSettings, timeout time.Duration) (*http.Client, error) {
	if timeout <= 0 {
		timeout = 12 * time.Second
	}
	proxyURL, _, err := ResolveDefaultProxy(settings)
	if err != nil {
		return nil, err
	}
	client, err := newBuildClientWithOptions(proxyURL, settings.PreferIPv4 && proxyURL == "", timeout)
	if err != nil {
		return nil, err
	}
	client.Timeout = timeout
	return client, nil
}
