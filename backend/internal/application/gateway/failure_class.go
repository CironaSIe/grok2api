package gateway

import (
	"context"
	"errors"
	"math/rand/v2"
	"net"
	"strings"
	"time"
)

// rateLimitCooldownMin/Max bound the random cooldown applied to 429 failures.
// A pool proxy rotates accounts within a few seconds and must NOT honor the
// upstream Retry-After header, which is meant for single-account clients and
// only makes pool-wide 429s sluggish. The jitter prevents thundering-herd
// retries against the same upstream after a shared rate limit.
const (
	rateLimitCooldownMin = 2 * time.Second
	rateLimitCooldownMax = 5 * time.Second
)

// rateLimitAccountCooldown returns a short random duration in [2s, 5s) used
// for account and team-model cooldowns on 429 responses.
func rateLimitAccountCooldown() time.Duration {
	return rateLimitCooldownMin + time.Duration(rand.Int64N(int64(rateLimitCooldownMax-rateLimitCooldownMin)))
}

// FailureClass groups upstream failures for cooldown policy (class vs legacy).
type FailureClass string

const (
	FailureClassTransport         FailureClass = "transport"
	FailureClassTransientUpstream FailureClass = "transient_upstream"
	FailureClassRateLimitWindow   FailureClass = "rate_limit_window"
	FailureClassModelDenied       FailureClass = "model_denied"
	FailureClassCredentialDead    FailureClass = "credential_dead"
	FailureClassAccountRiskSoft   FailureClass = "account_risk_soft"
	FailureClassUnknown           FailureClass = "unknown"
)

// CooldownModeClass uses zero account cooldown for transport/transient failures (free-pool default).
// CooldownModeLegacy restores exponential cooldownBase/cooldownMax behavior.
const (
	CooldownModeClass  = "class"
	CooldownModeLegacy = "legacy"
)

// ClassifyUpstreamFailure maps HTTP status / error to a FailureClass.
// Callers that already know the semantic class (1010, model deny) should pass it explicitly.
func ClassifyUpstreamFailure(status int, err error) FailureClass {
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return FailureClassTransport
		}
		var netErr net.Error
		if errors.As(err, &netErr) {
			return FailureClassTransport
		}
		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, "timeout") || strings.Contains(msg, "connection reset") || strings.Contains(msg, "connection refused") {
			return FailureClassTransport
		}
		if isAccountRiskImageError(err) {
			return FailureClassAccountRiskSoft
		}
	}
	switch status {
	case 0:
		return FailureClassTransport
	case 408, 499:
		return FailureClassTransport
	case 429:
		return FailureClassRateLimitWindow
	case 401, 402:
		return FailureClassCredentialDead
	case 403:
		// May be model/egress; callers should prefer MarkModelAccessDenied for pure model denies.
		return FailureClassModelDenied
	default:
		if status >= 500 {
			return FailureClassTransientUpstream
		}
		if status >= 400 {
			return FailureClassUnknown
		}
		return FailureClassUnknown
	}
}
