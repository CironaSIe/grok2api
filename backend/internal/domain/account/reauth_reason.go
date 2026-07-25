package account

import "strings"

// ReauthReason is a stable ops-facing code for why AuthStatus became reauthRequired.
// AuthStatus remains active|reauthRequired; this field is empty when active.
type ReauthReason string

const (
	ReauthReasonNone             ReauthReason = ""
	ReauthReasonSSORejected      ReauthReason = "sso_rejected"
	ReauthReasonRefreshPermanent ReauthReason = "refresh_permanent"
	ReauthReasonExpired          ReauthReason = "expired"
	ReauthReasonAccessDenied     ReauthReason = "access_denied"
	ReauthReasonBanned           ReauthReason = "banned"
	ReauthReasonUnknown          ReauthReason = "unknown"
)

// NormalizeReauthReason returns a known code or unknown; empty stays empty.
func NormalizeReauthReason(value string) ReauthReason {
	switch ReauthReason(strings.ToLower(strings.TrimSpace(value))) {
	case ReauthReasonNone:
		return ReauthReasonNone
	case ReauthReasonSSORejected:
		return ReauthReasonSSORejected
	case ReauthReasonRefreshPermanent:
		return ReauthReasonRefreshPermanent
	case ReauthReasonExpired:
		return ReauthReasonExpired
	case ReauthReasonAccessDenied:
		return ReauthReasonAccessDenied
	case ReauthReasonBanned:
		return ReauthReasonBanned
	case ReauthReasonUnknown:
		return ReauthReasonUnknown
	default:
		if strings.TrimSpace(value) == "" {
			return ReauthReasonNone
		}
		return ReauthReasonUnknown
	}
}

// InferReauthReason maps free-form failure text (existing LastError style) to a stable code.
func InferReauthReason(message string) ReauthReason {
	text := strings.ToLower(strings.TrimSpace(message))
	if text == "" {
		return ReauthReasonUnknown
	}
	switch {
	case strings.Contains(text, "banned") || strings.Contains(text, "suspend") || strings.Contains(text, "封禁"):
		return ReauthReasonBanned
	case strings.Contains(text, "sso") && (strings.Contains(text, "reject") || strings.Contains(text, "401") || strings.Contains(text, "unauthorized")):
		return ReauthReasonSSORejected
	case strings.Contains(text, "sso credential rejected"):
		return ReauthReasonSSORejected
	case strings.Contains(text, "refresh") && (strings.Contains(text, "permanent") || strings.Contains(text, "永久")):
		return ReauthReasonRefreshPermanent
	case strings.Contains(text, "expired") || strings.Contains(text, "过期"):
		return ReauthReasonExpired
	case strings.Contains(text, "access denied") || strings.Contains(text, "403") || strings.Contains(text, "forbidden"):
		return ReauthReasonAccessDenied
	case strings.Contains(text, "credential rejected") || strings.Contains(text, "unauthorized") || strings.Contains(text, "401"):
		// Prefer SSO when provider SSO wording is present; otherwise generic reject as access.
		if strings.Contains(text, "sso") {
			return ReauthReasonSSORejected
		}
		return ReauthReasonAccessDenied
	default:
		return ReauthReasonUnknown
	}
}

// DisplayLabel is a short ops badge label (English codes stay machine-stable).
func (r ReauthReason) DisplayLabel() string {
	switch NormalizeReauthReason(string(r)) {
	case ReauthReasonSSORejected:
		return "SSO_REJECTED"
	case ReauthReasonRefreshPermanent:
		return "REFRESH_DEAD"
	case ReauthReasonExpired:
		return "EXPIRED"
	case ReauthReasonAccessDenied:
		return "ACCESS_DENIED"
	case ReauthReasonBanned:
		return "BANNED"
	case ReauthReasonNone:
		return ""
	default:
		return "REAUTH"
	}
}
