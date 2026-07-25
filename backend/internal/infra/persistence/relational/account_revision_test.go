package relational

import (
	"context"
	"path/filepath"
	"testing"
)

func TestAccountDomainRevisionBump(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database, err := OpenSQLite(ctx, filepath.Join(t.TempDir(), "account-rev.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if err := database.InitializeSchema(ctx); err != nil {
		t.Fatal(err)
	}
	repo := NewAccountRepository(database)
	rev, err := repo.AccountDomainRevision(ctx)
	if err != nil || rev != 0 {
		t.Fatalf("initial revision = %d, %v", rev, err)
	}
	next, err := repo.BumpAccountDomainRevision(ctx)
	if err != nil || next != 1 {
		t.Fatalf("bump1 = %d, %v", next, err)
	}
	next, err = repo.BumpAccountDomainRevision(ctx)
	if err != nil || next != 2 {
		t.Fatalf("bump2 = %d, %v", next, err)
	}
	rev, err = repo.AccountDomainRevision(ctx)
	if err != nil || rev != 2 {
		t.Fatalf("read = %d, %v", rev, err)
	}
}
