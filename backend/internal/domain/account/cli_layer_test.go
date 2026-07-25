package account

import (
	"testing"
	"time"
)

func TestClassifyCLI_LayerMatrix(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	success := now.Add(-time.Hour)
	base := Credential{
		ID: 1, Provider: ProviderBuild, Enabled: true, AuthStatus: AuthStatusActive,
		EncryptedAccessToken: "enc-access", ExpiresAt: now.Add(2 * time.Hour),
	}

	tests := []struct {
		name     string
		cred     Credential
		billing  *Billing
		profile  CLIProfile
		bot      bool
		wantLayer CLILayer
		wantBucket WarmBucket
	}{
		{
			name: "L1 super proven",
			cred: func() Credential { c := base; c.BuildSuperEntitled = true; return c }(),
			profile: CLIProfile{LastSuccessAt: &success},
			wantLayer: CLILayerNonFreeProven, wantBucket: WarmBucketL1,
		},
		{
			name: "L1 paid billing proven",
			cred: base,
			billing: &Billing{PlanName: "Super", MonthlyLimit: 100, SyncedAt: now},
			profile: CLIProfile{LastSuccessAt: &success},
			wantLayer: CLILayerNonFreeProven, wantBucket: WarmBucketL1,
		},
		{
			name: "nonfree unproven is not L1",
			cred: func() Credential { c := base; c.BuildSuperEntitled = true; return c }(),
			profile: CLIProfile{},
			wantLayer: CLILayerUnproven, wantBucket: WarmBucketNonFreeUnproven,
		},
		{
			name: "L2 free proven",
			cred: base,
			profile: CLIProfile{LastSuccessAt: &success},
			wantLayer: CLILayerProven, wantBucket: WarmBucketL2,
		},
		{
			name: "L3 trusted unproven",
			cred: base,
			profile: CLIProfile{TrustedSource: true},
			wantLayer: CLILayerTrusted, wantBucket: WarmBucketL3,
		},
		{
			name: "L4 plain unproven",
			cred: base,
			profile: CLIProfile{},
			wantLayer: CLILayerUnproven, wantBucket: WarmBucketL4,
		},
		{
			name: "L5 maybe_dead unproven",
			cred: base,
			profile: CLIProfile{MaybeDead: true},
			wantLayer: CLILayerBotUnproven, wantBucket: WarmBucketL5,
		},
		{
			name: "L5 bot flag unproven",
			cred: base,
			bot: true,
			wantLayer: CLILayerBotUnproven, wantBucket: WarmBucketL5,
		},
		{
			name: "maybe_dead always L5 even if residual proven",
			cred: base,
			profile: CLIProfile{LastSuccessAt: &success, MaybeDead: true},
			wantLayer: CLILayerBotUnproven, wantBucket: WarmBucketL5,
		},
		{
			name: "web never classifies as build layer",
			cred: Credential{ID: 9, Provider: ProviderWeb, Enabled: true, AuthStatus: AuthStatusActive},
			wantLayer: CLILayerBotUnproven, wantBucket: WarmBucketL5,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyCLI(CLIClassifyInput{
				Credential: tc.cred, Billing: tc.billing, Profile: tc.profile, Now: now, BotFlagged: tc.bot,
			})
			if got.Layer != tc.wantLayer {
				t.Fatalf("layer = %d, want %d", got.Layer, tc.wantLayer)
			}
			if got.WarmBucket != tc.wantBucket {
				t.Fatalf("bucket = %s, want %s", got.WarmBucket, tc.wantBucket)
			}
		})
	}
}

func TestClassifyCLI_Eligibility(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	future := now.Add(time.Hour)
	past := now.Add(-time.Hour)
	blockedUntil := now.Add(10 * time.Minute)

	mk := func(mut func(*Credential, *CLIProfile)) CLIClassification {
		cred := Credential{
			ID: 1, Provider: ProviderBuild, Enabled: true, AuthStatus: AuthStatusActive,
			EncryptedAccessToken: "a", ExpiresAt: future,
		}
		profile := CLIProfile{}
		if mut != nil {
			mut(&cred, &profile)
		}
		return ClassifyCLI(CLIClassifyInput{Credential: cred, Profile: profile, Now: now})
	}

	if got := mk(nil); got.Eligibility != CLIEligibilityReady || !got.Selectable || !got.CountsTowardWarm {
		t.Fatalf("ready: %+v", got)
	}
	if got := mk(func(c *Credential, _ *CLIProfile) {
		c.ExpiresAt = past
		c.EncryptedRefreshToken = "rt"
	}); got.Eligibility != CLIEligibilityRefreshable || !got.Selectable || got.CountsTowardWarm {
		t.Fatalf("refreshable: %+v", got)
	}
	if got := mk(func(c *Credential, _ *CLIProfile) {
		c.ExpiresAt = past
		c.EncryptedRefreshToken = "rt"
		c.RefreshPermanent = true
	}); got.Eligibility != CLIEligibilityAcquireAllowed || got.Selectable {
		t.Fatalf("acquire after rt dead: %+v", got)
	}
	if got := mk(func(_ *Credential, p *CLIProfile) {
		p.NextEligibleAt = &blockedUntil
	}); got.Eligibility != CLIEligibilityTempBlocked || got.Selectable {
		t.Fatalf("temp blocked: %+v", got)
	}
	if got := mk(func(_ *Credential, p *CLIProfile) {
		p.MaybeDead = true
	}); got.Eligibility != CLIEligibilityChatBanned || got.Selectable || got.CountsTowardWarm {
		t.Fatalf("chat ban unproven: %+v", got)
	}
	if got := mk(func(c *Credential, _ *CLIProfile) {
		c.AuthStatus = AuthStatusReauthRequired
	}); got.Eligibility != CLIEligibilityDenied {
		t.Fatalf("reauth: %+v", got)
	}
	// Chat ban always non-selectable, even with residual proven success.
	success := now.Add(-time.Minute)
	if got := mk(func(_ *Credential, p *CLIProfile) {
		p.LastSuccessAt = &success
		p.MaybeDead = true
	}); got.Eligibility != CLIEligibilityChatBanned || got.Selectable || got.Layer != CLILayerBotUnproven {
		t.Fatalf("maybe_dead must not be selectable: %+v", got)
	}
	// Soft bot unproven with usable access: L5, READY, selectable, not warm.
	if got := ClassifyCLI(CLIClassifyInput{
		Credential: Credential{
			ID: 2, Provider: ProviderBuild, Enabled: true, AuthStatus: AuthStatusActive,
			EncryptedAccessToken: "a", ExpiresAt: future,
		},
		Profile:    CLIProfile{},
		Now:        now,
		BotFlagged: true,
	}); got.Layer != CLILayerBotUnproven || got.Eligibility != CLIEligibilityReady || !got.Selectable || got.CountsTowardWarm {
		t.Fatalf("soft bot L5 should be selectable READY, not warm: %+v", got)
	}
	// Soft bot + proven stays L2 and selectable.
	if got := ClassifyCLI(CLIClassifyInput{
		Credential: Credential{
			ID: 3, Provider: ProviderBuild, Enabled: true, AuthStatus: AuthStatusActive,
			EncryptedAccessToken: "a", ExpiresAt: future,
		},
		Profile:    CLIProfile{LastSuccessAt: &success},
		Now:        now,
		BotFlagged: true,
	}); got.Layer != CLILayerProven || !got.Selectable {
		t.Fatalf("soft bot proven should stay L2 selectable: %+v", got)
	}
}

func TestUnprovenWarmBucket(t *testing.T) {
	if !UnprovenWarmBucket(WarmBucketL3) || !UnprovenWarmBucket(WarmBucketL4) || !UnprovenWarmBucket(WarmBucketNonFreeUnproven) {
		t.Fatal("expected unproven buckets")
	}
	if UnprovenWarmBucket(WarmBucketL1) || UnprovenWarmBucket(WarmBucketL2) || UnprovenWarmBucket(WarmBucketL5) {
		t.Fatal("expected proven/l5 not unproven-cap")
	}
}

func TestEligibilityRankOrder(t *testing.T) {
	if EligibilityRank(CLIEligibilityReady) <= EligibilityRank(CLIEligibilityRefreshable) {
		t.Fatal("ready should rank above refreshable")
	}
}
