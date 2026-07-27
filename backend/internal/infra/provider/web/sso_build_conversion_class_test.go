package web

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/chenyme/grok2api/backend/internal/infra/provider"
)

func TestClassifyConversionError(t *testing.T) {
	cases := []struct {
		err  error
		want ConversionErrorClass
	}{
		{provider.ErrUnauthorized, ConversionClassSSODead},
		{fmt.Errorf("wrap: %w", conversionHTTPError{status: http.StatusTooManyRequests}), ConversionClassRateLimited},
		{fmt.Errorf("wrap: %w", conversionHTTPError{status: http.StatusBadGateway}), ConversionClassNetworkRetry},
		{fmt.Errorf("wrap: %w", conversionHTTPError{status: http.StatusBadRequest}), ConversionClassPermanent},
		{errors.New("connection reset by peer"), ConversionClassNetworkRetry},
		{errors.New(`Post "https://auth.x.ai/oauth2/device/code": EOF`), ConversionClassNetworkRetry},
		{errors.New("sso2oauth[device_code]: Post https://auth.x.ai/oauth2/device/code: unexpected EOF (传输中断/对端或代理提前关闭连接，通常不是 SSO 失效)"), ConversionClassNetworkRetry},
		{errors.New("xAI OAuth Token 失败 (Access denied): xAI OAuth HTTP 400"), ConversionClassPermanent},
		{errors.New("unexpected device flow state"), ConversionClassUnknown},
		{ErrBuildTokenBotContaminated, ConversionClassBotFlag},
		{fmt.Errorf("%w: automation", ErrBuildTokenBotContaminated), ConversionClassBotFlag},
	}
	for _, tc := range cases {
		if got := ClassifyConversionError(tc.err); got != tc.want {
			t.Fatalf("ClassifyConversionError(%v)=%q want %q", tc.err, got, tc.want)
		}
	}
	if !ConversionErrorRetriable(fmt.Errorf("%w", conversionHTTPError{status: 429})) {
		t.Fatal("429 should be retriable")
	}
	if ConversionErrorRetriable(provider.ErrUnauthorized) {
		t.Fatal("unauthorized must not retry")
	}
}
