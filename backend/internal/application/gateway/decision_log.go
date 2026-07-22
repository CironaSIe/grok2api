package gateway

import (
	"log/slog"

	accountdomain "github.com/chenyme/grok2api/backend/internal/domain/account"
)

// logRoutingDecision emits Debug-level pool routing events for ops (no secrets/bodies).
func logRoutingDecision(logger *slog.Logger, event, requestID string, provider accountdomain.Provider, accountID uint64, attempt int, reason string) {
	if logger == nil {
		return
	}
	logger.Debug("routing_decision",
		"event", event,
		"request_id", requestID,
		"provider", provider,
		"account_id", accountID,
		"attempt", attempt,
		"reason", reason,
	)
}
