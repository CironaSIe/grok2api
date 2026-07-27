package sso2oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClient_Convert_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/convert" || r.Method != "POST" {
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
		var req ConvertRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req.SsoToken == "" {
			t.Fatal("missing sso_token")
		}
		if err := json.NewEncoder(w).Encode(ConvertResponse{
			OK:     true,
			Tokens: &TokenSet{AccessToken: "at", RefreshToken: "rt", ExpiresIn: 21600},
		}); err != nil {
			t.Fatalf("encode response: %v", err)
		}
	}))
	defer server.Close()
	c := NewClient(server.URL, nil)
	resp, err := c.Convert(context.Background(), ConvertRequest{SsoToken: "test"})
	if err != nil || !resp.OK || resp.Tokens.AccessToken != "at" {
		t.Fatalf("resp=%+v err=%v", resp, err)
	}
}

func TestClient_Convert_DaemonError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewEncoder(w).Encode(ConvertResponse{
			OK:           false,
			ErrorPhase:   "probe_accounts",
			ErrorStatus:  403,
			ErrorMessage: "CF blocked",
		}); err != nil {
			t.Fatalf("encode response: %v", err)
		}
	}))
	defer server.Close()
	c := NewClient(server.URL, nil)
	resp, err := c.Convert(context.Background(), ConvertRequest{SsoToken: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.OK || resp.ErrorStatus != 403 {
		t.Fatalf("expected failure, got %+v", resp)
	}
}

func TestClient_Convert_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer server.Close()
	c := NewClient(server.URL, nil)
	_, err := c.Convert(context.Background(), ConvertRequest{SsoToken: "test"})
	if err == nil {
		t.Fatal("expected error for HTTP 500")
	}
}

func TestClient_Convert_DaemonUnreachable(t *testing.T) {
	c := NewClient("http://127.0.0.1:1", nil) // 不可达端口
	_, err := c.Convert(context.Background(), ConvertRequest{SsoToken: "test"})
	if err == nil {
		t.Fatal("expected error for unreachable daemon")
	}
}

func TestClient_Health(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			if err := json.NewEncoder(w).Encode(map[string]string{"status": "ok"}); err != nil {
				t.Fatalf("encode response: %v", err)
			}
		}
	}))
	defer server.Close()
	c := NewClient(server.URL, nil)
	if err := c.Health(context.Background()); err != nil {
		t.Fatalf("health check failed: %v", err)
	}
}
