package relational

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	accountdomain "github.com/chenyme/grok2api/backend/internal/domain/account"
)

func TestBuildCLIProfileCRUDAndRoutingAttach(t *testing.T) {
	ctx := context.Background()
	database, err := OpenSQLite(ctx, filepath.Join(t.TempDir(), "build-cli-profile.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.InitializeSchema(ctx); err != nil {
		t.Fatal(err)
	}
	accounts := NewAccountRepository(database)
	now := time.Now().UTC().Truncate(time.Second)

	build, _, err := accounts.UpsertByIdentity(ctx, accountdomain.Credential{
		Provider: accountdomain.ProviderBuild, AuthType: accountdomain.AuthTypeOAuth,
		Name: "cli-build", SourceKey: "cli-build-1", EncryptedAccessToken: testEncryptedToken,
		ExpiresAt: now.Add(2 * time.Hour), AuthStatus: accountdomain.AuthStatusActive, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	web, _, err := accounts.UpsertByIdentity(ctx, accountdomain.Credential{
		Provider: accountdomain.ProviderWeb, AuthType: accountdomain.AuthTypeSSO,
		Name: "cli-web", SourceKey: "cli-web-1", EncryptedAccessToken: testEncryptedToken,
		AuthStatus: accountdomain.AuthStatusActive, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := accounts.UpsertBuildCLIProfile(ctx, accountdomain.CLIProfile{
		AccountID: build.ID, TrustedSource: true, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := accounts.RecordBuildCLISuccess(ctx, build.ID, now); err != nil {
		t.Fatal(err)
	}
	if err := accounts.BumpBuildCLICallCount(ctx, build.ID); err != nil {
		t.Fatal(err)
	}
	gen, err := accounts.BumpBuildCLITokenGeneration(ctx, build.ID)
	if err != nil || gen != 1 {
		t.Fatalf("generation=%d err=%v", gen, err)
	}

	profiles, err := accounts.GetBuildCLIProfiles(ctx, []uint64{build.ID, web.ID})
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 1 {
		t.Fatalf("profiles=%d want 1 (web must not have build profile)", len(profiles))
	}
	p := profiles[build.ID]
	if !p.IsProven() || p.SuccessCount != 1 || p.CallCount != 1 || !p.TrustedSource || p.TokenGeneration != 1 {
		t.Fatalf("profile=%+v", p)
	}

	candidates, err := accounts.ListRoutingCandidates(ctx, accountdomain.ProviderBuild, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 || candidates[0].CLIProfile == nil {
		t.Fatalf("build candidates=%#v", candidates)
	}
	if !candidates[0].CLIProfile.IsProven() {
		t.Fatalf("expected proven profile on routing candidate")
	}
	class := accountdomain.ClassifyCLI(accountdomain.CLIClassifyInput{
		Credential: candidates[0].Credential,
		Billing:    candidates[0].Billing,
		Profile:    candidates[0].ProfileOrEmpty(),
		Now:        now,
	})
	if class.Layer != accountdomain.CLILayerProven {
		t.Fatalf("layer=%d want proven free", class.Layer)
	}

	webCandidates, err := accounts.ListRoutingCandidates(ctx, accountdomain.ProviderWeb, "", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range webCandidates {
		if c.CLIProfile != nil {
			t.Fatalf("web candidate must not load build_cli_profiles: %#v", c.CLIProfile)
		}
	}

	// Cascade delete profile with account.
	if err := accounts.Delete(ctx, build.ID); err != nil {
		t.Fatal(err)
	}
	left, err := accounts.GetBuildCLIProfiles(ctx, []uint64{build.ID})
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		t.Fatalf("profile should cascade delete, got %#v", left)
	}
}

func TestRecordBuildCLI403MaybeDead(t *testing.T) {
	ctx := context.Background()
	database, err := OpenSQLite(ctx, filepath.Join(t.TempDir(), "build-cli-403.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.InitializeSchema(ctx); err != nil {
		t.Fatal(err)
	}
	accounts := NewAccountRepository(database)
	build, _, err := accounts.UpsertByIdentity(ctx, accountdomain.Credential{
		Provider: accountdomain.ProviderBuild, AuthType: accountdomain.AuthTypeOAuth,
		Name: "cli-403", SourceKey: "cli-403", EncryptedAccessToken: testEncryptedToken,
		AuthStatus: accountdomain.AuthStatusActive, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := accounts.RecordBuildCLI403(ctx, build.ID, 3); err != nil {
			t.Fatal(err)
		}
	}
	profiles, err := accounts.GetBuildCLIProfiles(ctx, []uint64{build.ID})
	if err != nil {
		t.Fatal(err)
	}
	if profiles[build.ID].MaybeDead || profiles[build.ID].Consecutive403 != 2 {
		t.Fatalf("before threshold: %+v", profiles[build.ID])
	}
	if err := accounts.RecordBuildCLI403(ctx, build.ID, 3); err != nil {
		t.Fatal(err)
	}
	profiles, err = accounts.GetBuildCLIProfiles(ctx, []uint64{build.ID})
	if err != nil {
		t.Fatal(err)
	}
	if !profiles[build.ID].MaybeDead || profiles[build.ID].Consecutive403 != 3 {
		t.Fatalf("after threshold: %+v", profiles[build.ID])
	}
}
