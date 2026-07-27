package writequeue

import (
	"context"
	"fmt"
	"time"

	"github.com/chenyme/grok2api/backend/internal/repository"
)

// AccountSink adapts repository.AccountRepository plus optional identity writer.
// Identity metadata lives on the relational repository but is not part of the
// core AccountRepository interface used by routing.
type AccountSink struct {
	Accounts repository.AccountRepository
	// Identity is optional; when nil, UpdateIdentityMetadata is a no-op success.
	Identity IdentityWriter
}

// IdentityWriter matches relational.AccountRepository.UpdateIdentityMetadata.
type IdentityWriter interface {
	UpdateIdentityMetadata(ctx context.Context, accountID uint64, email, userID, teamID string) error
}

func (s AccountSink) UpdateHealth(ctx context.Context, id uint64, failureCount int, cooldownUntil *time.Time, lastError string, success bool) error {
	if s.Accounts == nil {
		return fmt.Errorf("writequeue: accounts sink missing")
	}
	return s.Accounts.UpdateHealth(ctx, id, failureCount, cooldownUntil, lastError, success)
}

func (s AccountSink) RecordBuildCLISuccessWithCalls(ctx context.Context, accountID uint64, at time.Time, callDelta int) error {
	if s.Accounts == nil {
		return fmt.Errorf("writequeue: accounts sink missing")
	}
	return s.Accounts.RecordBuildCLISuccessWithCalls(ctx, accountID, at, callDelta)
}

func (s AccountSink) BumpBuildCLICallCountBy(ctx context.Context, accountID uint64, delta int) error {
	if s.Accounts == nil {
		return fmt.Errorf("writequeue: accounts sink missing")
	}
	return s.Accounts.BumpBuildCLICallCountBy(ctx, accountID, delta)
}

func (s AccountSink) UpdateIdentityMetadata(ctx context.Context, accountID uint64, email, userID, teamID string) error {
	if s.Identity == nil {
		return nil
	}
	return s.Identity.UpdateIdentityMetadata(ctx, accountID, email, userID, teamID)
}

// NewAccountSink builds a Sink from the routing repository and optional identity writer.
// When accounts also implements IdentityWriter it is used automatically.
func NewAccountSink(accounts repository.AccountRepository) AccountSink {
	sink := AccountSink{Accounts: accounts}
	if identity, ok := accounts.(IdentityWriter); ok {
		sink.Identity = identity
	}
	return sink
}
