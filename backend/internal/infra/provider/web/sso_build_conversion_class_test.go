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
