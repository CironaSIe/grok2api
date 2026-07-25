package cli

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/chenyme/grok2api/backend/internal/infra/provider"
)

func TestOAuthRefreshClassifiesPermanentAndTransientFailures(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		body       string
		retryAfter string
		permanent  bool
		code       string
	}{
		{name: "transient upstream", status: http.StatusServiceUnavailable, body: `{"error":"temporarily_unavailable"}`, retryAfter: "7", code: "temporarily_unavailable"},
		{name: "invalid grant", status: http.StatusBadRequest, body: `{"error":"invalid_grant"}`, permanent: true, code: "invalid_grant"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			httpClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				if request.FormValue("grant_type") != "refresh_token" || request.FormValue("refresh_token") != "refresh" {
					t.Fatalf("form = %#v", request.Form)
				}
				header := make(http.Header)
				if test.retryAfter != "" {
					header.Set("Retry-After", test.retryAfter)
				}
				return &http.Response{StatusCode: test.status, Header: header, Body: io.NopCloser(strings.NewReader(test.body)), Request: request}, nil
			})}
			client := newOAuthClient(httpClient, func() string { return "0.2.111" })
			client.tokenURL = "https://auth.x.ai/oauth2/token"
			_, err := client.refresh(context.Background(), "refresh", "")
			var refreshErr *provider.CredentialRefreshError
			if !errors.As(err, &refreshErr) || refreshErr.Permanent != test.permanent || refreshErr.Code != test.code {
				t.Fatalf("error = %#v", err)
			}
			if test.retryAfter != "" && refreshErr.RetryAfter != 7*time.Second {
				t.Fatalf("retry after = %s", refreshErr.RetryAfter)
			}
		})
	}
}

func TestOAuthDeviceRetriesOn429(t *testing.T) {
	attempts := 0
	httpClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		attempts++
		if attempts == 1 {
			header := make(http.Header)
			header.Set("Retry-After", "1")
			return &http.Response{StatusCode: http.StatusTooManyRequests, Header: header, Body: io.NopCloser(strings.NewReader(`{"error":"rate_limited"}`)), Request: request}, nil
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{
			"device_code":"d","user_code":"u","verification_uri":"https://auth.x.ai/device","interval":5,"expires_in":600
		}`)), Request: request}, nil
	})}
	client := newOAuthClient(httpClient, func() string { return "0.2.111" })
	client.deviceURL = "https://auth.x.ai/oauth2/device/code"
	if _, err := client.startDevice(context.Background()); err != nil {
		t.Fatal(err)
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d", attempts)
	}
}

func TestOAuthFormHeadersUseCLIAuthForm(t *testing.T) {
	var deviceReq, tokenReq *http.Request
	httpClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		_ = request.ParseForm()
		switch {
		case strings.Contains(request.URL.Path, "/device/code"):
			deviceReq = request
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{
				"device_code":"d","user_code":"u","verification_uri":"https://auth.x.ai/device","interval":5,"expires_in":600
			}`)), Request: request}, nil
		case strings.Contains(request.URL.Path, "/token"):
			tokenReq = request
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{
				"access_token":"a","refresh_token":"r","expires_in":3600
			}`)), Request: request}, nil
		default:
			t.Fatalf("unexpected path %s", request.URL.Path)
			return nil, nil
		}
	})}
	client := newOAuthClient(httpClient, func() string { return "0.2.111" })
	client.deviceURL = "https://auth.x.ai/oauth2/device/code"
	client.tokenURL = "https://auth.x.ai/oauth2/token"
	if _, err := client.startDevice(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := client.refresh(context.Background(), "refresh", "user-uuid-1"); err != nil {
		t.Fatal(err)
	}
	if deviceReq == nil || tokenReq == nil {
		t.Fatal("missing requests")
	}
	for _, req := range []*http.Request{deviceReq, tokenReq} {
		ua := req.Header.Get("User-Agent")
		if !strings.Contains(ua, "grok-pager/") || !strings.Contains(ua, "grok-shell/") {
			t.Fatalf("oauth form must use dual CLI UA, got %q", ua)
		}
		if req.Header.Get("Sec-Fetch-Mode") != "" || req.Header.Get("Origin") != "" {
			t.Fatalf("CLI form must not send browser Sec-Fetch/Origin on %s", req.URL.Path)
		}
		if req.Header.Get("X-XAI-Token-Auth") != "" {
			t.Fatalf("oauth form must not send Token-Auth on %s", req.URL.Path)
		}
	}
	if err := deviceReq.ParseForm(); err != nil {
		t.Fatal(err)
	}
	if deviceReq.Form.Get("referrer") != "grok-build" {
		t.Fatalf("device referrer = %q", deviceReq.Form.Get("referrer"))
	}
	if !strings.Contains(deviceReq.Form.Get("scope"), "workspaces:read") {
		t.Fatalf("device scope = %q", deviceReq.Form.Get("scope"))
	}
	if deviceReq.Header.Get("x-grok-client-surface") != "ui" {
		t.Fatalf("device surface = %q", deviceReq.Header.Get("x-grok-client-surface"))
	}
	if err := tokenReq.ParseForm(); err != nil {
		t.Fatal(err)
	}
	if tokenReq.Form.Get("principal_type") != "User" || tokenReq.Form.Get("principal_id") != "user-uuid-1" {
		t.Fatalf("refresh principal = %q %q", tokenReq.Form.Get("principal_type"), tokenReq.Form.Get("principal_id"))
	}
	if tokenReq.Header.Get("x-grok-client-surface") != "" {
		t.Fatal("refresh must omit surface by default")
	}
}

func TestOAuthScopeMatchesOfficialPersonalAccountContract(t *testing.T) {
	values := strings.Fields(defaultOAuthScope)
	want := []string{
		"openid", "profile", "email", "offline_access", "grok-cli:access", "api:access",
		"conversations:read", "conversations:write", "workspaces:read", "workspaces:write",
	}
	if len(values) != len(want) {
		t.Fatalf("scope count = %d, want %d: %v", len(values), len(want), values)
	}
	for index := range want {
		if values[index] != want[index] {
			t.Fatalf("scope[%d] = %q, want %q", index, values[index], want[index])
		}
	}
}
