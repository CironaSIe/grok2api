package gateway

import (
	"errors"
	"testing"
)

func TestIsAccountRiskImageError(t *testing.T) {
	if !isAccountRiskImageError(errors.New("Image generation failed: systemErrCode=1010 (account risk)")) {
		t.Fatal("expected 1010 detection")
	}
	if isAccountRiskImageError(errors.New("proxy timeout")) {
		t.Fatal("timeout is not account risk")
	}
	if !isAccountRiskImageResponse(502, []byte(`{"systemErrCode":1010,"error":{"systemErrCode":1010}}`)) {
		t.Fatal("expected body 1010")
	}
	if isAccountRiskImageResponse(502, []byte(`{"error":"boom"}`)) {
		t.Fatal("generic 502 is not account risk")
	}
}
