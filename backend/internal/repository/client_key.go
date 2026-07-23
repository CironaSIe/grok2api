package repository

import (
	"context"

	"github.com/chenyme/grok2api/backend/internal/domain/clientkey"
)

// ClientKeyRepository 定义下游 API Key 持久化能力。
type ClientKeyRepository interface {
	List(ctx context.Context, query ClientKeyListQuery) ([]clientkey.Key, int64, error)
	Create(ctx context.Context, value clientkey.Key) (clientkey.Key, error)
	Get(ctx context.Context, id uint64) (clientkey.Key, error)
	GetByPrefix(ctx context.Context, prefix string) (clientkey.Key, error)
	// GetBySecretHash looks up a client key by the SHA-256 hex digest of the full raw secret.
	// Used for custom (non-g2a_*) secrets.
	GetBySecretHash(ctx context.Context, secretHash string) (clientkey.Key, error)
	Update(ctx context.Context, value clientkey.Key) (clientkey.Key, error)
	// ReplaceSecret updates secret material and whether the secret is operator-custom.
	// prefix is optional: empty keeps the current prefix.
	ReplaceSecret(ctx context.Context, id uint64, secretHash, encryptedSecret, prefix string, customSecret bool) error
	UpdateManyEnabled(ctx context.Context, ids []uint64, enabled bool) (int64, error)
	Delete(ctx context.Context, id uint64) error
	DeleteMany(ctx context.Context, ids []uint64) (int64, error)
	Touch(ctx context.Context, id uint64) error
}
