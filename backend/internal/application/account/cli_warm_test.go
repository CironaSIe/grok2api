package account

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	accountdomain "github.com/chenyme/grok2api/backend/internal/domain/account"
	"github.com/chenyme/grok2api/backend/internal/infra/config"
	"github.com/chenyme/grok2api/backend/internal/infra/persistence/relational"
)

func TestShouldAutoRefreshBuildDue(t *testing.T) {
	s := &Service{now: func() time.Time { return time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC) }}
	cfg := config.DefaultCLIRoutingConfig()
	now := s.now()
	success := now.Add(-time.Hour)
	cred := accountdomain.Credential{
		ID: 1, Provider: accountdomain.ProviderBuild, Enabled: true, AuthStatus: accountdomain.AuthStatusActive,
		EncryptedAccessToken: "a", EncryptedRefreshToken: "r", ExpiresAt: now.Add(time.Hour),
	}
	// proven always
	if !s.shouldAutoRefreshBuildDue(cred, accountdomain.CLIProfile{LastSuccessAt: &success}, nil, cfg) {
		t.Fatal("proven should refresh")
	}
	// plain unproven with auto fill
	if !s.shouldAutoRefreshBuildDue(cred, accountdomain.CLIProfile{}, nil, cfg) {
		t.Fatal("unproven with AutoFillUnproven should refresh")
	}
	cfg.AutoFillUnproven = false
	if s.shouldAutoRefreshBuildDue(cred, accountdomain.CLIProfile{}, nil, cfg) {
		t.Fatal("unproven without auto fill must skip due RT")
	}
	cfg.Enabled = false
	if !s.shouldAutoRefreshBuildDue(cred, accountdomain.CLIProfile{}, nil, cfg) {
		t.Fatal("CLI disabled falls back to allow due refresh")
	}
}

func TestScanBuildCLIWarmMaterialCountsReady(t *testing.T) {
	ctx := context.Background()
	database, err := relational.OpenSQLite(ctx, filepath.Join(t.TempDir(), "cli-warm.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.InitializeSchema(ctx); err != nil {
		t.Fatal(err)
	}
	repo := relational.NewAccountRepository(database)
	now := time.Now().UTC()
	success := now.Add(-time.Hour)
	proven, _, err := repo.UpsertByIdentity(ctx, accountdomain.Credential{
		Provider: accountdomain.ProviderBuild, AuthType: accountdomain.AuthTypeOAuth, Name: "proven",
		SourceKey: "warm-proven", EncryptedAccessToken: "enc", EncryptedRefreshToken: "rt",
		ExpiresAt: now.Add(2 * time.Hour), Enabled: true, AuthStatus: accountdomain.AuthStatusActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.RecordBuildCLISuccess(ctx, proven.ID, success); err != nil {
		t.Fatal(err)
	}
	// unproven expired access with RT — material for refresh
	_, _, err = repo.UpsertByIdentity(ctx, accountdomain.Credential{
		Provider: accountdomain.ProviderBuild, AuthType: accountdomain.AuthTypeOAuth, Name: "refreshable",
		SourceKey: "warm-refreshable", EncryptedAccessToken: "enc", EncryptedRefreshToken: "rt",
		ExpiresAt: now.Add(-time.Hour), Enabled: true, AuthStatus: accountdomain.AuthStatusActive,
	})
	if err != nil {
		t.Fatal(err)
	}

	s := NewService(repo, nil, nil, nil, nil, nil, nil)
	s.SetCLIRouting(config.DefaultCLIRoutingConfig())
	stats, material, err := s.scanBuildCLIWarmMaterial(ctx, s.cliRouting())
	if err != nil {
		t.Fatal(err)
	}
	if stats.readyTotal < 1 {
		t.Fatalf("expected proven READY, stats=%+v", stats)
	}
	if len(material[accountdomain.WarmBucketL4])+len(material[accountdomain.WarmBucketL3]) < 1 {
		// refreshable unproven should appear in some unproven bucket
		found := false
		for b, items := range material {
			if len(items) > 0 {
				found = true
				t.Logf("material bucket %s count %d", b, len(items))
			}
		}
		if !found {
			t.Fatalf("expected refreshable material, stats=%+v material=%v", stats, material)
		}
	}
}

func TestNormalizeWarmFillOrderAndUnprovenCap(t *testing.T) {
	order := normalizeWarmFillOrder([]string{"l2", "l1", "l2", "nope"})
	if len(order) != 2 || order[0] != accountdomain.WarmBucketL2 || order[1] != accountdomain.WarmBucketL1 {
		t.Fatalf("order=%v", order)
	}
	cfg := config.DefaultCLIRoutingConfig()
	if cfg.UnprovenCap() != 120 {
		t.Fatalf("cap=%d", cfg.UnprovenCap())
	}
}

func TestEffectiveSoftFloorAndMaterialRank(t *testing.T) {
	if got := effectiveSoftFloor(20, 0, 2); got != 2 {
		t.Fatalf("floor clamped by material: got %d", got)
	}
	if got := effectiveSoftFloor(20, 5, 100); got != 20 {
		t.Fatalf("floor full material: got %d", got)
	}
	if got := effectiveSoftFloor(0, 0, 10); got != 0 {
		t.Fatalf("zero floor: got %d", got)
	}
	items := []warmAccount{
		{class: accountdomain.CLIClassification{Eligibility: accountdomain.CLIEligibilityAcquireAllowed}},
		{class: accountdomain.CLIClassification{Eligibility: accountdomain.CLIEligibilityRefreshable}},
	}
	sortWarmMaterial(items)
	if items[0].class.Eligibility != accountdomain.CLIEligibilityRefreshable {
		t.Fatalf("RT should rank first, got %s", items[0].class.Eligibility)
	}
}

func TestTryAcquireCLIConvertPerMinute(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	s := &Service{
		now:                func() time.Time { return now },
		cliConvertInflight: make(chan struct{}, 8),
	}
	cfg := config.DefaultCLIRoutingConfig()
	cfg.MaxConvertInflight = 8
	cfg.MaxConvertPerMinute = 2
	if !s.tryAcquireCLIConvert(cfg) {
		t.Fatal("first acquire")
	}
	if !s.tryAcquireCLIConvert(cfg) {
		t.Fatal("second acquire")
	}
	if s.tryAcquireCLIConvert(cfg) {
		t.Fatal("third must hit per-minute cap")
	}
	// release slots does not free rate window
	s.releaseCLIConvertSlot()
	s.releaseCLIConvertSlot()
	if s.tryAcquireCLIConvert(cfg) {
		t.Fatal("rate window still full")
	}
	// advance clock past 1m
	s.now = func() time.Time { return now.Add(61 * time.Second) }
	if !s.tryAcquireCLIConvert(cfg) {
		t.Fatal("after window should allow")
	}
}
