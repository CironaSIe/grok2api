package relational

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/chenyme/grok2api/backend/internal/domain/account"
)

func TestAccountTagsAddRemoveAndUpsertPreserves(t *testing.T) {
	ctx := context.Background()
	database, err := OpenSQLite(ctx, filepath.Join(t.TempDir(), "account-tags.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.InitializeSchema(ctx); err != nil {
		t.Fatal(err)
	}
	repo := NewAccountRepository(database)
	created, _, err := repo.UpsertByIdentity(ctx, account.Credential{
		Provider: account.ProviderWeb, AuthType: account.AuthTypeSSO,
		Name: "tag-acc", SourceKey: "tag-acc", EncryptedAccessToken: "tok",
		Enabled: true, AuthStatus: account.AuthStatusActive, ExpiresAt: time.Now().UTC().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.AddAccountTag(ctx, created.ID, account.TagNoImage); err != nil {
		t.Fatal(err)
	}
	got, err := repo.Get(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.HasAccountTag(account.TagNoImage) {
		t.Fatalf("tags = %#v", got.Tags)
	}
	// Upsert must preserve tags.
	_, _, err = repo.UpsertByIdentity(ctx, account.Credential{
		Provider: account.ProviderWeb, AuthType: account.AuthTypeSSO,
		Name: "tag-acc", SourceKey: "tag-acc", EncryptedAccessToken: "tok2",
		Enabled: true, AuthStatus: account.AuthStatusActive, ExpiresAt: time.Now().UTC().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err = repo.Get(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.HasAccountTag(account.TagNoImage) {
		t.Fatalf("tags wiped by upsert: %#v", got.Tags)
	}
	if err := repo.RemoveAccountTag(ctx, created.ID, account.TagNoImage); err != nil {
		t.Fatal(err)
	}
	got, err = repo.Get(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.HasAccountTag(account.TagNoImage) {
		t.Fatalf("tag still present: %#v", got.Tags)
	}
}
