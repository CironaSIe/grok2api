package xaiauth

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	// MaxFormAttempts covers initial try + short 429 retries for device/code.
	MaxFormAttempts = 3
	// Default429Backoff when Retry-After is missing.
	Default429Backoff = 2 * time.Second
	// Max429Backoff caps wait so batch convert cannot stall for minutes.
	Max429Backoff = 5 * time.Second
)

// ParseRetryAfter reads Retry-After seconds or HTTP-date; returns 0 if absent/invalid.
func ParseRetryAfter(header http.Header) time.Duration {
	if header == nil {
		return 0
	}
	value := strings.TrimSpace(header.Get("Retry-After"))
	if value == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(value); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	if parsed, err := http.ParseTime(value); err == nil && parsed.After(time.Now()) {
		return time.Until(parsed)
	}
	return 0
}

// ClampBackoff limits rate-limit waits for pool convert/refresh.
func ClampBackoff(wait time.Duration) time.Duration {
	if wait <= 0 {
		return Default429Backoff
	}
	if wait > Max429Backoff {
		return Max429Backoff
	}
	return wait
}

// Sleep respects context cancellation.
func Sleep(ctx context.Context, wait time.Duration) error {
	if wait <= 0 {
		return nil
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
