package gateway

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/chenyme/grok2api/backend/internal/domain/account"
	"github.com/chenyme/grok2api/backend/internal/infra/persistence/relational"
	"github.com/chenyme/grok2api/backend/internal/infra/runtime/memory"
)

func TestClassifyUpstreamFailure(t *testing.T) {
	if ClassifyUpstreamFailure(502, nil) != FailureClassTransientUpstream {
		t.Fatalf("502 => %s", ClassifyUpstreamFailure(502, nil))
	}
	if ClassifyUpstreamFailure(0, context.DeadlineExceeded) != FailureClassTransport {
		t.Fatal("deadline")
	}
	if ClassifyUpstreamFailure(429, nil) != FailureClassRateLimitWindow {
		t.Fatal("429")
	}
	if ClassifyUpstreamFailure(401, nil) != FailureClassCredentialDead {
		t.Fatal("401")
	}
	if ClassifyUpstreamFailure(403, nil) != FailureClassModelDenied {
		t.Fatal("403")
	}
}

func TestMarkFailureClassModeZeroCooldown(t *testing.T) {
	ctx := context.Background()
	database, err := relational.OpenSQLite(ctx, filepath.Join(t.TempDir(), "cooldown-class.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.InitializeSchema(ctx); err != nil {
		t.Fatal(err)
	}
	repo := relational.NewAccountRepository(database)
	created, _, err := repo.UpsertByIdentity(ctx, account.Credential{
		Provider: account.ProviderBuild, AuthType: account.AuthTypeOAuth,
		Name: "fail", SourceKey: "fail", EncryptedAccessToken: "tok",
		Enabled: true, AuthStatus: account.AuthStatusActive, ExpiresAt: time.Now().UTC().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	selector := NewSelector(repo, memory.NewConcurrencyLimiter(), memory.NewStickyStore(), nil, time.Hour, 30*time.Second, 30*time.Minute, 500*time.Millisecond)
	selector.UpdateCooldownMode(CooldownModeClass)
	selector.MarkFailure(ctx, created, 502, time.Minute)

	got, err := repo.Get(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.FailureCount != 1 {
		t.Fatalf("failureCount=%d", got.FailureCount)
	}
	if got.CooldownUntil != nil {
		t.Fatalf("class mode must not set cooldown, got %v", got.CooldownUntil)
	}

	// Legacy still parks the account.
	selector.UpdateCooldownMode(CooldownModeLegacy)
	selector.MarkFailure(ctx, got, 502, 0)
	got, err = repo.Get(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.CooldownUntil == nil || !got.CooldownUntil.After(time.Now().UTC()) {
		t.Fatalf("legacy cooldown missing: %v", got.CooldownUntil)
	}
}
