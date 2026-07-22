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
			client := newOAuthClient(httpClient)
			client.tokenURL = "https://auth.x.ai/oauth2/token"
			_, err := client.refresh(context.Background(), "refresh")
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

func TestOAuthFormHeadersUseBrowserIdentity(t *testing.T) {
	var deviceReq, tokenReq *http.Request
	httpClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
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
	client := newOAuthClient(httpClient)
	client.deviceURL = "https://auth.x.ai/oauth2/device/code"
	client.tokenURL = "https://auth.x.ai/oauth2/token"
	if _, err := client.startDevice(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := client.refresh(context.Background(), "refresh"); err != nil {
		t.Fatal(err)
	}
	if deviceReq == nil || tokenReq == nil {
		t.Fatal("missing requests")
	}
	for _, req := range []*http.Request{deviceReq, tokenReq} {
		ua := req.Header.Get("User-Agent")
		if ua == "" || strings.Contains(strings.ToLower(ua), "grok-shell") || strings.Contains(strings.ToLower(ua), "grok-pager") {
			t.Fatalf("oauth form must use browser UA, got %q", ua)
		}
		if req.Header.Get("Sec-Ch-Ua") == "" {
			t.Fatalf("missing chromium client hints on %s", req.URL.Path)
		}
	}
	if deviceReq.Header.Get("X-XAI-Token-Auth") != "" {
		t.Fatal("device_code must not send X-XAI-Token-Auth")
	}
	if tokenReq.Header.Get("X-XAI-Token-Auth") != "xai-grok-cli" {
		t.Fatalf("token exchange Token-Auth = %q", tokenReq.Header.Get("X-XAI-Token-Auth"))
	}
}
