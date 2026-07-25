package account

import "testing"

func TestInferReauthReason(t *testing.T) {
	cases := []struct {
		in   string
		want ReauthReason
	}{
		{"", ReauthReasonUnknown},
		{"grok_web SSO credential rejected", ReauthReasonSSORejected},
		{"Grok Web SSO credential rejected", ReauthReasonSSORejected},
		{"OAuth refresh token 已永久失效且 access token 已过期", ReauthReasonRefreshPermanent},
		{"oauth access token rejected after permanent refresh failure", ReauthReasonRefreshPermanent},
		{"token expired", ReauthReasonExpired},
		{"access denied by upstream", ReauthReasonAccessDenied},
		{"account banned by provider", ReauthReasonBanned},
		{"something else", ReauthReasonUnknown},
		{"credential rejected", ReauthReasonAccessDenied},
	}
	for _, tc := range cases {
		if got := InferReauthReason(tc.in); got != tc.want {
			t.Fatalf("InferReauthReason(%q)=%q want %q", tc.in, got, tc.want)
		}
	}
}

func TestNormalizeAndDisplayLabel(t *testing.T) {
	if NormalizeReauthReason(" SSO_REJECTED ") != ReauthReasonSSORejected {
		t.Fatal("normalize case")
	}
	if NormalizeReauthReason("weird") != ReauthReasonUnknown {
		t.Fatal("unknown normalize")
	}
	if NormalizeReauthReason("") != ReauthReasonNone {
		t.Fatal("empty normalize")
	}
	if ReauthReasonBanned.DisplayLabel() != "BANNED" {
		t.Fatal("display")
	}
	if ReauthReasonNone.DisplayLabel() != "" {
		t.Fatal("empty display")
	}
}
