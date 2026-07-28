package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/chenyme/grok2api/backend/internal/domain/account"
	infraegress "github.com/chenyme/grok2api/backend/internal/infra/egress"
	"github.com/chenyme/grok2api/backend/internal/infra/provider"
	"github.com/chenyme/grok2api/backend/internal/infra/sso2oauth"
)

// testLease returns a minimal non-nil Lease for convertViaDaemon tests.
func testLease() *infraegress.Lease {
	return &infraegress.Lease{NodeID: 1}
}

// newDaemonTestAdapter builds a minimal Adapter for convertViaDaemon
// tests — only config() and log() are needed, not egress/cipher.
func newDaemonTestAdapter() *Adapter {
	return &Adapter{
		cfg:    Config{BuildClientVersion: "0.2.111"},
		logger: nil, // falls back to slog.Default() via log()
	}
}

// mockDaemonServer creates an httptest server that returns the given
// ConvertResponse to POST /convert, and returns its URL + a closer.
func mockDaemonServer(t *testing.T, resp sso2oauth.ConvertResponse) (string, func()) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/convert" || r.Method != "POST" {
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Fatalf("encode: %v", err)
		}
	}))
	return server.URL, server.Close
}

func TestConvertViaDaemon_Success(t *testing.T) {
	access := fakeJWT(map[string]any{"sub": "daemon-user", "email": "daemon@x.ai", "team_id": "daemon-team", "bot_flag_source": "NP"})
	id := fakeJWT(map[string]any{"email": "daemon@x.ai"})
	serverURL, closeFn := mockDaemonServer(t, sso2oauth.ConvertResponse{
		OK: true,
		Tokens: &sso2oauth.TokenSet{
			AccessToken:  access,
			RefreshToken: "rt-daemon",
			IDToken:      id,
			ExpiresIn:    21600,
			TokenType:    "Bearer",
		},
		Identity: &sso2oauth.Identity{UserID: "daemon-user", Email: "daemon@x.ai", TeamID: "daemon-team"},
		BotFlag:  &sso2oauth.BotFlag{Class: "clean", Raw: "NP"},
	})
	defer closeFn()

	a := newDaemonTestAdapter()
	client := sso2oauth.NewClient(serverURL, nil)
	cred := account.Credential{Name: "web-account"}
	seed, err := a.convertViaDaemon(context.Background(), cred, "sso-token", testLease(), client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if seed.AccessToken != access {
		t.Fatalf("access token = %q, want %q", seed.AccessToken, access)
	}
	if seed.RefreshToken != "rt-daemon" {
		t.Fatalf("refresh token = %q", seed.RefreshToken)
	}
	if seed.UserID != "daemon-user" || seed.Email != "daemon@x.ai" || seed.TeamID != "daemon-team" {
		t.Fatalf("seed identity = %+v", seed)
	}
	if seed.OIDCClientID != ssoBuildClientID {
		t.Fatalf("OIDCClientID = %q", seed.OIDCClientID)
	}
	if seed.Provider != account.ProviderBuild || seed.AuthType != account.AuthTypeOAuth {
		t.Fatalf("provider/authType = %s/%s", seed.Provider, seed.AuthType)
	}
}

func TestConvertViaDaemon_DaemonError(t *testing.T) {
	serverURL, closeFn := mockDaemonServer(t, sso2oauth.ConvertResponse{
		OK:           false,
		ErrorPhase:   "probe_accounts",
		ErrorStatus:  401,
		ErrorMessage: "SSO 无效或未登录",
	})
	defer closeFn()

	a := newDaemonTestAdapter()
	client := sso2oauth.NewClient(serverURL, nil)
	_, err := a.convertViaDaemon(context.Background(), account.Credential{Name: "web"}, "sso-token", testLease(), client)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, provider.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized, got: %v", err)
	}
	if ClassifyConversionError(err) != ConversionClassSSODead {
		t.Fatalf("class = %s", ClassifyConversionError(err))
	}
}

func TestConvertViaDaemon_BotContaminated(t *testing.T) {
	access := fakeJWT(map[string]any{"sub": "u1", "bot_flag_source": "automation"})
	id := fakeJWT(map[string]any{"email": "a@x.ai"})
	serverURL, closeFn := mockDaemonServer(t, sso2oauth.ConvertResponse{
		OK:      true,
		Tokens:  &sso2oauth.TokenSet{AccessToken: access, IDToken: id, ExpiresIn: 21600},
		BotFlag: &sso2oauth.BotFlag{Class: "contaminated", Raw: "automation"},
	})
	defer closeFn()

	a := newDaemonTestAdapter()
	client := sso2oauth.NewClient(serverURL, nil)
	_, err := a.convertViaDaemon(context.Background(), account.Credential{Name: "web"}, "sso-token", testLease(), client)
	if !errors.Is(err, ErrBuildTokenBotContaminated) {
		t.Fatalf("expected ErrBuildTokenBotContaminated, got: %v", err)
	}
	if ClassifyConversionError(err) != ConversionClassBotFlag {
		t.Fatalf("class = %s", ClassifyConversionError(err))
	}
}

func TestConvertViaDaemon_DaemonUnreachable(t *testing.T) {
	a := newDaemonTestAdapter()
	// Port 1 is never reachable.
	client := sso2oauth.NewClient("http://127.0.0.1:1", nil)
	_, err := a.convertViaDaemon(context.Background(), account.Credential{Name: "web"}, "sso-token", testLease(), client)
	if err == nil {
		t.Fatal("expected error for unreachable daemon")
	}
	if !strings.Contains(err.Error(), "不可达") {
		t.Fatalf("error should mention unreachable: %v", err)
	}
}

func TestBuildSeedFromDaemon_IndependentJWTParse(t *testing.T) {
	// Daemon returns identity from Python, but Go should re-parse the JWT
	// independently and use the JWT claims, not the daemon's identity.
	access := fakeJWT(map[string]any{"sub": "jwt-user", "email": "jwt@x.ai", "team_id": "jwt-team", "bot_flag_source": "NP"})
	a := newDaemonTestAdapter()
	seed, err := a.buildSeedFromDaemon(&sso2oauth.ConvertResponse{
		OK:     true,
		Tokens: &sso2oauth.TokenSet{AccessToken: access, ExpiresIn: 3600},
		// Python identity is different — Go should NOT use these.
		Identity: &sso2oauth.Identity{UserID: "python-user", Email: "python@x.ai", TeamID: "python-team"},
	}, account.Credential{Name: "web-account"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Go parsed JWT claims independently — should use jwt-user, not python-user.
	if seed.UserID != "jwt-user" {
		t.Fatalf("UserID = %q (should be from JWT, not daemon)", seed.UserID)
	}
	if seed.Email != "jwt@x.ai" {
		t.Fatalf("Email = %q (should be from JWT, not daemon)", seed.Email)
	}
	if seed.TeamID != "jwt-team" {
		t.Fatalf("TeamID = %q (should be from JWT, not daemon)", seed.TeamID)
	}
}

func TestClassifyDaemonError_429(t *testing.T) {
	a := newDaemonTestAdapter()
	err := a.classifyDaemonError(&sso2oauth.ConvertResponse{
		OK:           false,
		ErrorPhase:   "device_code",
		ErrorStatus:  429,
		ErrorMessage: "rate limited",
	})
	if !errors.Is(err, conversionHTTPError{status: 429}) {
		t.Fatalf("expected conversionHTTPError{429}, got: %v", err)
	}
	if ClassifyConversionError(err) != ConversionClassRateLimited {
		t.Fatalf("class = %s", ClassifyConversionError(err))
	}
}

func TestClassifyDaemonError_500(t *testing.T) {
	a := newDaemonTestAdapter()
	err := a.classifyDaemonError(&sso2oauth.ConvertResponse{
		OK:           false,
		ErrorPhase:   "oidc_discovery",
		ErrorStatus:  503,
		ErrorMessage: "upstream down",
	})
	if ClassifyConversionError(err) != ConversionClassNetworkRetry {
		t.Fatalf("class = %s, want network_retry", ClassifyConversionError(err))
	}
}

func TestClassifyDaemonError_AccessDenied(t *testing.T) {
	a := newDaemonTestAdapter()
	err := a.classifyDaemonError(&sso2oauth.ConvertResponse{
		OK:           false,
		ErrorPhase:   "token_poll",
		ErrorStatus:  400,
		ErrorMessage: "access_denied: user denied consent",
	})
	if !errors.Is(err, provider.ErrAuthorizationDenied) {
		t.Fatalf("expected ErrAuthorizationDenied, got: %v", err)
	}
}
