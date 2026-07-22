package xaiauth

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestApplyCLIAuthFormDevicePoll(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, DeviceCodeURL, nil)
	ApplyCLIAuthForm(req, FormOptions{Version: "0.2.106", Surface: SurfaceUI})
	ua := req.Header.Get("User-Agent")
	if !strings.Contains(ua, "grok-pager/0.2.106") || !strings.Contains(ua, "grok-shell/0.2.106") {
		t.Fatalf("UA = %q", ua)
	}
	if req.Header.Get("x-grok-client-surface") != "ui" {
		t.Fatalf("surface = %q", req.Header.Get("x-grok-client-surface"))
	}
	if req.Header.Get("x-grok-client-version") != "0.2.106" {
		t.Fatalf("version = %q", req.Header.Get("x-grok-client-version"))
	}
	if req.Header.Get("X-XAI-Token-Auth") != "" || req.Header.Get("Sec-Fetch-Mode") != "" || req.Header.Get("Origin") != "" {
		t.Fatalf("unexpected browser/token-auth headers: %#v", req.Header)
	}
	if req.Header.Get("Accept") != "*/*" {
		t.Fatalf("Accept = %q", req.Header.Get("Accept"))
	}
}

func TestApplyCLIAuthFormRefreshOmitsSurface(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, TokenURL, nil)
	ApplyCLIAuthForm(req, FormOptions{Version: "0.2.106"})
	if req.Header.Get("x-grok-client-surface") != "" || req.Header.Get("x-grok-client-version") != "" {
		t.Fatal("refresh form must omit surface/version by default")
	}
	if !strings.Contains(req.Header.Get("User-Agent"), "grok-pager/") {
		t.Fatalf("UA = %q", req.Header.Get("User-Agent"))
	}
}

func TestDeviceCodeFormIncludesReferrerAndWorkspaces(t *testing.T) {
	form := DeviceCodeForm("", "")
	if form.Get("referrer") != DeviceReferrer {
		t.Fatalf("referrer = %q", form.Get("referrer"))
	}
	scope := form.Get("scope")
	if !strings.Contains(scope, "workspaces:read") || !strings.Contains(scope, "conversations:write") {
		t.Fatalf("scope = %q", scope)
	}
	if form.Get("client_id") != ClientID {
		t.Fatalf("client_id = %q", form.Get("client_id"))
	}
}

func TestApplyBrowserAuthHTMLVerify(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, VerifyURL, nil)
	ApplyBrowserAuthHTML(req, "", BrowserVerify, "ABCD", "")
	if !strings.Contains(req.Header.Get("User-Agent"), "Mozilla/") {
		t.Fatalf("UA = %q", req.Header.Get("User-Agent"))
	}
	if strings.Contains(req.Header.Get("User-Agent"), "grok-shell") {
		t.Fatal("browser step must not use CLI UA")
	}
	if !strings.Contains(req.Header.Get("Referer"), "user_code=ABCD") {
		t.Fatalf("Referer = %q", req.Header.Get("Referer"))
	}
	if req.Header.Get("Origin") != "https://accounts.x.ai" {
		t.Fatalf("Origin = %q", req.Header.Get("Origin"))
	}
}

func TestClassifyConvertBot(t *testing.T) {
	cases := []struct {
		name string
		raw  any
		want ConvertBotClass
	}{
		{name: "absent", want: ConvertBotClean},
		{name: "np", raw: "NP", want: ConvertBotClean},
		{name: "bot string", raw: "automation", want: ConvertBotContaminated},
		{name: "super numeric", raw: float64(1), want: ConvertBotSuperSignal},
		{name: "zero", raw: float64(0), want: ConvertBotClean},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var claims map[string]any
			if tc.raw != nil {
				claims = map[string]any{"bot_flag_source": tc.raw}
			}
			got, _ := ClassifyConvertBot(claims)
			if got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestIdentityFromTokensPrefersAccessSubAndIDEmail(t *testing.T) {
	// header.payload.sig — payload only decoded
	access := fakeJWT(map[string]any{"sub": "user-1", "team_id": "team-9", "email": "a@x"})
	id := fakeJWT(map[string]any{"email": "id@x", "sub": "other"})
	userID, email, teamID, _ := IdentityFromTokens(access, id)
	if userID != "user-1" || email != "id@x" || teamID != "team-9" {
		t.Fatalf("identity = %s %s %s", userID, email, teamID)
	}
}

func fakeJWT(claims map[string]any) string {
	payload, err := json.Marshal(claims)
	if err != nil {
		panic(err)
	}
	return "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"
}
