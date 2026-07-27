package egress

import (
	"testing"

	domain "github.com/chenyme/grok2api/backend/internal/domain/egress"
)

func TestResolveDefaultProxyDirect(t *testing.T) {
	url, source, err := ResolveDefaultProxy(DefaultSettings{Mode: "direct", PreferIPv4: true})
	if err != nil || url != "" || source != "direct" {
		t.Fatalf("url=%q source=%q err=%v", url, source, err)
	}
}

func TestResolveDefaultProxyURL(t *testing.T) {
	url, source, err := ResolveDefaultProxy(DefaultSettings{Mode: "url", ProxyURL: "http://127.0.0.1:12334"})
	if err != nil || source != "url" || url != "http://127.0.0.1:12334" {
		t.Fatalf("url=%q source=%q err=%v", url, source, err)
	}
}

func TestResolveDefaultProxyEnv(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:18080")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:18080")
	url, source, err := ResolveDefaultProxy(DefaultSettings{Mode: "env"})
	if err != nil || source != "env" {
		t.Fatalf("source=%q err=%v", source, err)
	}
	if url == "" {
		t.Fatal("expected proxy from env")
	}
}

func TestApplyDefaultProxyOnlySyntheticDirect(t *testing.T) {
	m := NewManager(nil, nil)
	m.UpdateDefaultSettings(DefaultSettings{Mode: "url", ProxyURL: "http://127.0.0.1:12334", PreferIPv4: true})
	// synthetic direct id 0
	got, settings, err := m.applyDefaultProxy(domainNodeDirect(), "")
	if err != nil || got != "http://127.0.0.1:12334" || !settings.PreferIPv4 {
		t.Fatalf("got=%q settings=%+v err=%v", got, settings, err)
	}
	// real node empty proxy stays empty
	got, _, err = m.applyDefaultProxy(domainNodeReal(), "")
	if err != nil || got != "" {
		t.Fatalf("real node got=%q err=%v", got, err)
	}
}

func domainNodeDirect() domain.Node {
	return domain.Node{ID: 0, Name: "direct", Enabled: true}
}

func domainNodeReal() domain.Node {
	return domain.Node{ID: 9, Name: "node", Enabled: true}
}

