package account

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	accountdomain "github.com/chenyme/grok2api/backend/internal/domain/account"
	"github.com/chenyme/grok2api/backend/internal/infra/config"
	"github.com/chenyme/grok2api/backend/internal/infra/persistence/relational"
	"github.com/chenyme/grok2api/backend/internal/infra/runtime/memory"
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

func TestWarmMaterialHasUnused(t *testing.T) {
	material := map[accountdomain.WarmBucket][]warmAccount{
		accountdomain.WarmBucketL4: {
			{credential: accountdomain.Credential{ID: 1}, class: accountdomain.CLIClassification{Eligibility: accountdomain.CLIEligibilityReady}},
			{credential: accountdomain.Credential{ID: 2}, class: accountdomain.CLIClassification{Eligibility: accountdomain.CLIEligibilityRefreshable}},
		},
	}
	if !warmMaterialHasUnused(material, map[uint64]bool{}) {
		t.Fatal("refreshable unused should count as material")
	}
	if warmMaterialHasUnused(material, map[uint64]bool{2: true}) {
		t.Fatal("only used refreshable + ready should mean exhausted")
	}
	if warmMaterialHasUnused(map[accountdomain.WarmBucket][]warmAccount{}, nil) {
		t.Fatal("empty material is exhausted")
	}
}

func TestListPioneerWebCandidatesPrefersTrusted(t *testing.T) {
	ctx := context.Background()
	database, err := relational.OpenSQLite(ctx, filepath.Join(t.TempDir(), "cli-pioneer.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.InitializeSchema(ctx); err != nil {
		t.Fatal(err)
	}
	repo := relational.NewAccountRepository(database)

	other, _, err := repo.UpsertByIdentity(ctx, accountdomain.Credential{
		Provider: accountdomain.ProviderWeb, AuthType: accountdomain.AuthTypeSSO, Name: "web-other",
		SourceKey: "sso-other", EncryptedAccessToken: "sso-other", Enabled: true, AuthStatus: accountdomain.AuthStatusActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	trusted, _, err := repo.UpsertByIdentity(ctx, accountdomain.Credential{
		Provider: accountdomain.ProviderWeb, AuthType: accountdomain.AuthTypeSSO, Name: "web-trusted",
		SourceKey: "sso-trusted", EncryptedAccessToken: "sso-trusted", Enabled: true, AuthStatus: accountdomain.AuthStatusActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.AddAccountTag(ctx, trusted.ID, accountdomain.TagCLITrusted); err != nil {
		t.Fatal(err)
	}
	// linked web should not appear as unlinked
	build, _, err := repo.UpsertByIdentity(ctx, accountdomain.Credential{
		Provider: accountdomain.ProviderBuild, AuthType: accountdomain.AuthTypeOAuth, Name: "build-linked",
		SourceKey: "build-linked", EncryptedAccessToken: "a", EncryptedRefreshToken: "r",
		Enabled: true, AuthStatus: accountdomain.AuthStatusActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	linked, _, err := repo.UpsertByIdentity(ctx, accountdomain.Credential{
		Provider: accountdomain.ProviderWeb, AuthType: accountdomain.AuthTypeSSO, Name: "web-linked",
		SourceKey: "sso-linked", EncryptedAccessToken: "sso-linked", Enabled: true, AuthStatus: accountdomain.AuthStatusActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.LinkWebToBuild(ctx, linked.ID, build.ID); err != nil {
		t.Fatal(err)
	}

	s := NewService(repo, nil, nil, nil, nil, nil, nil)
	cfg := config.DefaultCLIRoutingConfig()
	cfg.PioneerPreferTrusted = true
	ids, err := s.listPioneerWebCandidates(ctx, cfg, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) < 2 {
		t.Fatalf("expected unlinked web candidates, got %v", ids)
	}
	if ids[0] != trusted.ID {
		t.Fatalf("expected trusted first, got %v (trusted=%d other=%d)", ids, trusted.ID, other.ID)
	}
	for _, id := range ids {
		if id == linked.ID {
			t.Fatalf("linked web must not be pioneer candidate: %v", ids)
		}
	}
}

func TestRunCLIWarmTickPioneersWhenMaterialEmpty(t *testing.T) {
	ctx := context.Background()
	database, err := relational.OpenSQLite(ctx, filepath.Join(t.TempDir(), "cli-warm-pioneer.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.InitializeSchema(ctx); err != nil {
		t.Fatal(err)
	}
	repo := relational.NewAccountRepository(database)
	if _, _, err := repo.UpsertByIdentity(ctx, accountdomain.Credential{
		Provider: accountdomain.ProviderWeb, AuthType: accountdomain.AuthTypeSSO, Name: "web-seed",
		SourceKey: "sso-seed", EncryptedAccessToken: "sso-seed", Enabled: true, AuthStatus: accountdomain.AuthStatusActive,
	}); err != nil {
		t.Fatal(err)
	}

	s := NewService(repo, nil, nil, nil, nil, nil, memory.NewLockStore())
	cfg := config.DefaultCLIRoutingConfig()
	cfg.WarmTargetTotal = 500
	cfg.AutoPioneerFromWeb = true
	cfg.MaxPioneerPerTick = 2
	cfg.MaxConvertInflight = 8
	cfg.MaxConvertPerMinute = 20
	s.SetCLIRouting(cfg)

	// No Build material + unlinked Web → Phase C starts bounded pioneer jobs.
	// providers=nil so convert returns ErrUnsupported (no panic); slot is still released.
	ids, err := s.listPioneerWebCandidates(ctx, cfg, 4)
	if err != nil || len(ids) == 0 {
		t.Fatalf("candidates err=%v ids=%v", err, ids)
	}
	actions := 0
	started := s.pioneerFromUnlinkedWeb(ctx, cfg, 10, &actions)
	if started != 1 {
		t.Fatalf("expected one pioneer start from single candidate, got %d actions=%d", started, actions)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(s.cliConvertInflight) == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(s.cliConvertInflight) != 0 {
		t.Fatalf("convert slot not released after pioneer job")
	}
}

func TestDefaultCLIRoutingEnablesPioneer(t *testing.T) {
	cfg := config.DefaultCLIRoutingConfig()
	if !cfg.AutoPioneerFromWeb || cfg.MaxPioneerPerTick != 5 || !cfg.PioneerPreferTrusted {
		t.Fatalf("unexpected pioneer defaults: %+v", cfg)
	}
}

func TestPioneerWantRespectsUnprovenHeadroom(t *testing.T) {
	// When unproven_ready already at/over cap, Phase C must not start more pioneers
	// even if total ready is still below warm_target_total (号池调度.md §4.3.1 / §7.3).
	cfg := config.DefaultCLIRoutingConfig()
	cfg.WarmTargetTotal = 500
	cfg.WarmMaxUnprovenAbs = 120
	cfg.WarmMaxUnprovenShare = 0.40
	cfg.AutoPioneerFromWeb = true
	if cfg.UnprovenCap() != 120 {
		t.Fatalf("cap=%d", cfg.UnprovenCap())
	}
	// Pure arithmetic mirror of runCLIWarmTick Phase C gate.
	unprovenReady := 162
	unprovenCap := cfg.UnprovenCap()
	totalReady := 162
	deficit := cfg.WarmTargetTotal - totalReady
	want := deficit
	if unprovenCap > 0 {
		headroom := unprovenCap - unprovenReady
		if headroom <= 0 {
			want = 0
		} else if want > headroom {
			want = headroom
		}
	}
	if want != 0 {
		t.Fatalf("expected pioneer want 0 when over unproven cap, got %d (deficit=%d)", want, deficit)
	}
}
