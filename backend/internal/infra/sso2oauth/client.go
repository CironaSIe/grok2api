package sso2oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// Client talks to the local sso2oauth Python daemon over HTTP.
// The daemon is started by the Supervisor (see supervisor.go); the
// Client only needs the daemon's base URL (http://127.0.0.1:PORT).
type Client struct {
	baseURL    string
	httpClient *http.Client
	logger     *slog.Logger
}

// NewClient returns a Client pointed at baseURL. The HTTP timeout is
// 120s to cover the full 9-step flow (token poll alone can take ~90s).
// A nil logger falls back to slog.Default().
func NewClient(baseURL string, logger *slog.Logger) *Client {
	if logger == nil {
		logger = slog.Default()
	}
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 120 * time.Second,
		},
		logger: logger,
	}
}

// BaseURL returns the daemon's base URL (http://127.0.0.1:PORT) for
// logging and diagnostics.
func (c *Client) BaseURL() string { return c.baseURL }

// Convert sends a POST /convert request to the daemon and decodes the
// response. A non-nil error means the daemon was unreachable or
// returned a non-200 HTTP status; a nil error with resp.OK=false means
// the daemon processed the request but the SSO2OAUTH flow failed
// (resp.Error* fields carry the detail).
func (c *Client) Convert(ctx context.Context, req ConvertRequest) (*ConvertResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("编码请求: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/convert", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("创建请求: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("sso2oauth daemon 不可达: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sso2oauth daemon HTTP %d", resp.StatusCode)
	}
	// 4 MB limit covers enrichment data (billing_raw, subscription_raw
	// as JSON objects, models list) plus 20+ phase traces each with
	// 512-char body previews.
	var result ConvertResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&result); err != nil {
		return nil, fmt.Errorf("解析 daemon 响应: %w", err)
	}
	return &result, nil
}

// Health pings GET /health on the daemon. Used by the Supervisor to
// decide when the daemon is ready and by the integration layer to
// decide whether to fall back to the Go tls-client path.
func (c *Client) Health(ctx context.Context) error {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/health", nil)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("健康检查失败: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("健康检查 HTTP %d", resp.StatusCode)
	}
	return nil
}
