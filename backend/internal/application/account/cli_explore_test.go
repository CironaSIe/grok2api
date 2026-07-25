package account

import (
	"testing"
	"time"

	accountdomain "github.com/chenyme/grok2api/backend/internal/domain/account"
	"github.com/chenyme/grok2api/backend/internal/infra/config"
)

func TestCLIExploreGateOpen(t *testing.T) {
	s := &Service{}
	cfg := config.CLIRoutingConfig{
		ExploreMinProvenReady:       30,
		ExploreUnprovenShareTrigger: 0.35,
	}
	// Proven thick, unproven share low → closed.
	if s.cliExploreGateOpen(cfg, warmScanStats{readyTotal: 100, provenReady: 80, unprovenReady: 20}) {
		t.Fatal("expected gate closed when proven healthy and unproven share low")
	}
	// Proven thin → open.
	if !s.cliExploreGateOpen(cfg, warmScanStats{readyTotal: 100, provenReady: 10, unprovenReady: 20}) {
		t.Fatal("expected gate open when proven thin")
	}
	// Unproven share high → open.
	if !s.cliExploreGateOpen(cfg, warmScanStats{readyTotal: 100, provenReady: 50, unprovenReady: 50}) {
		t.Fatal("expected gate open when unproven share high")
	}
}

func TestFilterExploreCandidates(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	cool := 30 * time.Minute
	recent := now.Add(-5 * time.Minute)
	old := now.Add(-2 * time.Hour)
	base := func(mut func(*warmAccount)) warmAccount {
		item := warmAccount{
			credential: accountdomain.Credential{
				ID: 1, Provider: accountdomain.ProviderBuild, Enabled: true, AuthStatus: accountdomain.AuthStatusActive,
			},
			profile: accountdomain.CLIProfile{AccountID: 1},
			class: accountdomain.CLIClassification{
				Layer:       accountdomain.CLILayerUnproven,
				Eligibility: accountdomain.CLIEligibilityReady,
				WarmBucket:  accountdomain.WarmBucketL4,
				Proven:      false,
			},
		}
		if mut != nil {
			mut(&item)
		}
		return item
	}
	pool := filterExploreCandidates([]warmAccount{
		base(nil),
		base(func(w *warmAccount) { w.profile.MaybeDead = true }),
		base(func(w *warmAccount) { w.class.Proven = true }),
		base(func(w *warmAccount) { w.profile.LastExploreAt = &recent }),
		base(func(w *warmAccount) {
			w.profile.LastExploreAt = &old
			w.class.Layer = accountdomain.CLILayerTrusted
			w.class.WarmBucket = accountdomain.WarmBucketL3
		}),
	}, now, cool)
	if len(pool) != 2 {
		t.Fatalf("pool = %d, want 2 (fresh + old-explore L3)", len(pool))
	}
}
