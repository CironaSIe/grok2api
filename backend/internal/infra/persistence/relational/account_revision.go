package relational

import (
	"context"
	"errors"
	"strconv"
	"time"

	"gorm.io/gorm"
)

const accountDomainRevisionKey = "revision"

// AccountDomainRevision returns the monotonic account-domain revision used by admin snapshot/changes.
func (r *AccountRepository) AccountDomainRevision(ctx context.Context) (int64, error) {
	var row accountDomainMetaModel
	err := r.db.db.WithContext(ctx).Where("key = ?", accountDomainRevisionKey).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, mapError(err)
	}
	value, parseErr := strconv.ParseInt(row.Value, 10, 64)
	if parseErr != nil || value < 0 {
		return 0, nil
	}
	return value, nil
}

// BumpAccountDomainRevision increments and returns the new account-domain revision.
// SQLite uses IMMEDIATE transactions (see DSN); no row-level FOR UPDATE required.
func (r *AccountRepository) BumpAccountDomainRevision(ctx context.Context) (int64, error) {
	var next int64
	err := r.db.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var row accountDomainMetaModel
		readErr := tx.Where("key = ?", accountDomainRevisionKey).First(&row).Error
		now := time.Now().UTC()
		if errors.Is(readErr, gorm.ErrRecordNotFound) {
			next = 1
			return tx.Create(&accountDomainMetaModel{Key: accountDomainRevisionKey, Value: "1", UpdatedAt: now}).Error
		}
		if readErr != nil {
			return readErr
		}
		current, parseErr := strconv.ParseInt(row.Value, 10, 64)
		if parseErr != nil || current < 0 {
			current = 0
		}
		next = current + 1
		return tx.Model(&accountDomainMetaModel{}).Where("key = ?", accountDomainRevisionKey).Updates(map[string]any{
			"value":      strconv.FormatInt(next, 10),
			"updated_at": now,
		}).Error
	})
	if err != nil {
		return 0, mapError(err)
	}
	return next, nil
}
