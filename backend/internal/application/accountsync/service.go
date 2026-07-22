package accountsync

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	accountapp "github.com/chenyme/grok2api/backend/internal/application/account"
	accountdomain "github.com/chenyme/grok2api/backend/internal/domain/account"
	"github.com/chenyme/grok2api/backend/internal/infra/provider"
	"github.com/chenyme/grok2api/backend/internal/pkg/batch"
	"golang.org/x/sync/singleflight"
)

const (
	defaultWorkerCount                  = 25
	operationTimeout                    = 2 * time.Minute
	defaultImportSyncMaxRounds          = 3
	defaultImportSyncPerAccountAttempts = 2
	defaultImportSyncBackoff            = 500 * time.Millisecond
)

type billingSynchronizer interface {
	HasBillingSnapshot(ctx context.Context, accountID uint64) (bool, error)
	RefreshBilling(ctx context.Context, accountID uint64) (accountdomain.Billing, error)
}

type modelSynchronizer interface {
	HasSuccessfulAccountSync(ctx context.Context, accountID uint64) (bool, error)
	SyncAccount(ctx context.Context, accountID uint64) (int, error)
}

type accountReader interface {
	Get(ctx context.Context, id uint64) (accountapp.View, error)
}

type providerPolicy interface {
	ProviderDefinition(value accountdomain.Provider) (provider.Definition, bool)
}

type quotaSynchronizer interface {
	HasQuotaWindows(ctx context.Context, accountID uint64) (bool, error)
	RefreshQuota(ctx context.Context, accountID uint64) ([]accountdomain.QuotaWindow, error)
}

type identitySynchronizer interface {
	SyncAccountIdentity(ctx context.Context, accountID uint64) error
}

// Service 对新接入账号执行一次性额度与模型补齐，并限制批量同步并发。
type Service struct {
	logger   *slog.Logger
	accounts accountReader
	billing  billingSynchronizer
	quota    quotaSynchronizer
	models   modelSynchronizer
	syncs    singleflight.Group
	workers  atomic.Int64
	bulkPool *batch.Pool

	// import sync rate-limit policy (0 / negative means defaults; backoff 0 is valid for tests)
	importSyncMaxRounds          int
	importSyncPerAccountAttempts int
	importSyncBackoff            time.Duration
	importSyncBackoffSet         bool
}

func NewService(logger *slog.Logger, accounts accountReader, billing billingSynchronizer, quota quotaSynchronizer, models modelSynchronizer) *Service {
	service := &Service{logger: logger, accounts: accounts, billing: billing, quota: quota, models: models, bulkPool: batch.NewPool(defaultWorkerCount)}
	service.workers.Store(defaultWorkerCount)
	return service
}

func (s *Service) SetBulkPool(pool *batch.Pool) {
	if pool != nil {
		s.bulkPool = pool
	}
}

func (s *Service) UpdateConcurrency(value int) {
	if value < 1 {
		value = defaultWorkerCount
	}
	s.workers.Store(int64(value))
	s.bulkPool.UpdateLimit(value)
}

// UpdateImportSyncRetry configures end-of-batch rate-limit recheck and per-account attempts.
// maxRounds / perAccountAttempts <= 0 keep previous (or defaults). backoff is applied when set=true.
func (s *Service) UpdateImportSyncRetry(maxRounds, perAccountAttempts int, backoff time.Duration) {
	if maxRounds > 0 {
		s.importSyncMaxRounds = maxRounds
	}
	if perAccountAttempts > 0 {
		s.importSyncPerAccountAttempts = perAccountAttempts
	}
	s.importSyncBackoff = backoff
	s.importSyncBackoffSet = true
}

func (s *Service) retryPolicy() (maxRounds, attempts int, backoff time.Duration) {
	maxRounds = s.importSyncMaxRounds
	if maxRounds < 1 {
		maxRounds = defaultImportSyncMaxRounds
	}
	attempts = s.importSyncPerAccountAttempts
	if attempts < 1 {
		attempts = defaultImportSyncPerAccountAttempts
	}
	if s.importSyncBackoffSet {
		backoff = s.importSyncBackoff
		if backoff < 0 {
			backoff = 0
		}
	} else {
		backoff = defaultImportSyncBackoff
	}
	return maxRounds, attempts, backoff
}

// SyncModels 强制刷新指定账号的模型能力，不受初始同步快照跳过规则影响。
func (s *Service) SyncModels(ctx context.Context, accountID uint64) error {
	if accountID == 0 {
		return errors.New("账号 ID 无效")
	}
	if s.models == nil {
		return errors.New("模型同步器未初始化")
	}
	operationCtx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	_, err := s.models.SyncAccount(operationCtx, accountID)
	if err != nil {
		s.logger.Warn("account_model_sync_failed", "account_id", accountID, "error", err)
		return fmt.Errorf("同步模型: %w", err)
	}
	return nil
}

// Result 汇总本次初始同步成功与失败的账号数。
type Result struct {
	Succeeded int
	Failed    int
}

// Sync 等待本次涉及的账号完成额度与模型补齐；已同步数据会跳过，同账号并发请求会合并。
func (s *Service) Sync(ctx context.Context, accountIDs ...uint64) Result {
	input := make(chan uint64, len(accountIDs))
	for _, accountID := range accountIDs {
		input <- accountID
	}
	close(input)
	return s.SyncStream(ctx, input)
}

// SyncStream 以固定 Worker 数消费持续到达的账号，使导入与上游同步形成有界流水线。
func (s *Service) SyncStream(ctx context.Context, accountIDs <-chan uint64) Result {
	return s.syncStream(ctx, accountIDs, nil)
}

// SyncStreamObserved 在每个去重账号完成初始同步后报告进度。
func (s *Service) SyncStreamObserved(ctx context.Context, accountIDs <-chan uint64, observer func(completed, total int)) Result {
	return s.syncStream(ctx, accountIDs, observer)
}

func (s *Service) syncStream(ctx context.Context, accountIDs <-chan uint64, observer func(completed, total int)) Result {
	maxRounds, perAccountAttempts, backoff := s.retryPolicy()
	jobs := make(chan uint64)
	var workers sync.WaitGroup
	var succeeded atomic.Int64
	var failed atomic.Int64
	var total atomic.Int64
	var progressMu sync.Mutex
	var rateLimitMu sync.Mutex
	rateLimitFailed := make(map[uint64]struct{})
	completed := 0
	count := max(1, int(s.workers.Load()))
	workers.Add(count)
	for range count {
		go func() {
			defer workers.Done()
			for accountID := range jobs {
				err := s.runSyncJob(ctx, accountID, 1, perAccountAttempts, backoff)
				if err != nil {
					var panicErr *batch.PanicError
					if errors.As(err, &panicErr) {
						s.logger.Error("account_initial_sync_panicked", "account_id", accountID, "error", panicErr, "stack", string(panicErr.Stack))
					}
					failed.Add(1)
					if isRetryableImportSyncError(err) {
						rateLimitMu.Lock()
						rateLimitFailed[accountID] = struct{}{}
						rateLimitMu.Unlock()
					}
				} else {
					succeeded.Add(1)
				}
				if observer != nil {
					progressMu.Lock()
					completed++
					observer(completed, int(total.Load()))
					progressMu.Unlock()
				}
			}
		}()
	}
	seen := make(map[uint64]struct{})
sendLoop:
	for {
		select {
		case <-ctx.Done():
			break sendLoop
		case accountID, ok := <-accountIDs:
			if !ok {
				break sendLoop
			}
			if accountID == 0 {
				continue
			}
			if _, exists := seen[accountID]; exists {
				continue
			}
			seen[accountID] = struct{}{}
			total.Add(1)
			select {
			case jobs <- accountID:
			case <-ctx.Done():
				break sendLoop
			}
		}
	}
	close(jobs)
	workers.Wait()

	// End-of-batch recheck: only accounts that still failed with rate-limit errors.
	for round := 2; round <= maxRounds; round++ {
		rateLimitMu.Lock()
		recheck := make([]uint64, 0, len(rateLimitFailed))
		for accountID := range rateLimitFailed {
			recheck = append(recheck, accountID)
		}
		rateLimitMu.Unlock()
		if len(recheck) == 0 || ctx.Err() != nil {
			break
		}
		s.logger.Info("account_initial_sync_recheck", "sync_round", round, "count", len(recheck), "max_rounds", maxRounds)
		if backoff > 0 {
			if err := sleepWithContext(ctx, backoff); err != nil {
				break
			}
		}
		nextFailed := make(map[uint64]struct{})
		var recheckWG sync.WaitGroup
		recheckJobs := make(chan uint64)
		recheckWorkers := max(1, int(s.workers.Load()))
		recheckWG.Add(recheckWorkers)
		for range recheckWorkers {
			go func() {
				defer recheckWG.Done()
				for accountID := range recheckJobs {
					err := s.runSyncJob(ctx, accountID, round, perAccountAttempts, backoff)
					if err != nil {
						var panicErr *batch.PanicError
						if errors.As(err, &panicErr) {
							s.logger.Error("account_initial_sync_panicked", "account_id", accountID, "sync_round", round, "error", panicErr, "stack", string(panicErr.Stack))
						}
						if isRetryableImportSyncError(err) {
							rateLimitMu.Lock()
							nextFailed[accountID] = struct{}{}
							rateLimitMu.Unlock()
						}
						// non-rate-limit failure keeps the prior Failed count
						continue
					}
					// recovered from a previously counted failure
					failed.Add(-1)
					succeeded.Add(1)
				}
			}()
		}
		for _, accountID := range recheck {
			select {
			case recheckJobs <- accountID:
			case <-ctx.Done():
			}
			if ctx.Err() != nil {
				break
			}
		}
		close(recheckJobs)
		recheckWG.Wait()
		rateLimitMu.Lock()
		rateLimitFailed = nextFailed
		rateLimitMu.Unlock()
	}

	return Result{Succeeded: int(succeeded.Load()), Failed: int(failed.Load())}
}

func (s *Service) runSyncJob(ctx context.Context, accountID uint64, syncRound, perAccountAttempts int, backoff time.Duration) error {
	return s.bulkPool.Do(ctx, func(workCtx context.Context) error {
		return s.syncAccountWithRateLimitRetry(workCtx, accountID, syncRound, perAccountAttempts, backoff)
	})
}

func (s *Service) syncAccountWithRateLimitRetry(ctx context.Context, accountID uint64, syncRound, attempts int, backoff time.Duration) error {
	if attempts < 1 {
		attempts = 1
	}
	var last error
	for attempt := 1; attempt <= attempts; attempt++ {
		_, syncErr, _ := s.syncs.Do(strconv.FormatUint(accountID, 10), func() (any, error) {
			return nil, s.syncAccount(ctx, accountID)
		})
		last = syncErr
		if last == nil || !isRetryableImportSyncError(last) {
			return last
		}
		if attempt >= attempts {
			break
		}
		s.logger.Warn("account_initial_sync_rate_limited_retry",
			"account_id", accountID,
			"sync_round", syncRound,
			"attempt", attempt,
			"max_attempts", attempts,
			"error", last,
		)
		if err := sleepWithContext(ctx, backoff); err != nil {
			return err
		}
	}
	return last
}

func sleepWithContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// isRetryableImportSyncError reports whether an import/sync failure is a transient rate limit.
// Unauthorized / permanent credential failures are never rechecked.
func isRetryableImportSyncError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, provider.ErrUnauthorized) {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var refresh *provider.CredentialRefreshError
	if errors.As(err, &refresh) {
		if refresh != nil && refresh.Permanent {
			return false
		}
		if refresh != nil && refresh.Status == http.StatusTooManyRequests {
			return true
		}
	}
	if status, ok := provider.ErrorHTTPStatus(err); ok {
		return status == http.StatusTooManyRequests
	}
	// Fallback for adapters that wrap status only in the error text.
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "too many requests") {
		return true
	}
	if strings.Contains(msg, "rate limit") || strings.Contains(msg, "rate-limit") || strings.Contains(msg, "ratelimit") {
		return true
	}
	// Match " 429" / "429 " / "status 429" without treating unrelated numbers as rate limits.
	if strings.Contains(msg, " 429") || strings.Contains(msg, "429 ") || strings.Contains(msg, "status 429") || strings.HasPrefix(msg, "429") {
		return true
	}
	return false
}

func (s *Service) syncAccount(ctx context.Context, accountID uint64) error {
	var syncErr error
	billingSnapshotCreated := false
	view, err := s.accounts.Get(ctx, accountID)
	if err != nil {
		return fmt.Errorf("读取账号: %w", err)
	}
	policy, ok := s.accounts.(providerPolicy)
	if !ok {
		return fmt.Errorf("账号读取器未提供 Provider 生命周期策略")
	}
	definition, ok := policy.ProviderDefinition(view.Credential.Provider)
	if !ok {
		return fmt.Errorf("Provider %s 未注册生命周期策略", view.Credential.Provider)
	}
	if view.Credential.Provider == accountdomain.ProviderWeb || view.Credential.Provider == accountdomain.ProviderConsole {
		if identity, ok := s.accounts.(identitySynchronizer); ok {
			operationCtx, cancel := context.WithTimeout(ctx, operationTimeout)
			identityErr := identity.SyncAccountIdentity(operationCtx, accountID)
			if identityErr != nil {
				s.logger.Warn("account_initial_identity_sync_failed", "account_id", accountID, "error", identityErr)
			}
			cancel()
			if errors.Is(identityErr, provider.ErrUnauthorized) {
				return fmt.Errorf("同步账号身份: %w", identityErr)
			}
		}
	}
	if definition.Quota == provider.QuotaRemoteWindow || definition.Quota == provider.QuotaLocalWindow {
		hasQuota, quotaErr := s.quota.HasQuotaWindows(ctx, accountID)
		if quotaErr != nil {
			syncErr = errors.Join(syncErr, fmt.Errorf("检查 Provider 额度快照: %w", quotaErr))
		} else if !hasQuota {
			operationCtx, cancel := context.WithTimeout(ctx, operationTimeout)
			_, quotaErr = s.quota.RefreshQuota(operationCtx, accountID)
			cancel()
			if quotaErr != nil {
				syncErr = errors.Join(syncErr, fmt.Errorf("同步 Provider 额度: %w", quotaErr))
			}
		}
	} else {
		hasBilling, err := s.billing.HasBillingSnapshot(ctx, accountID)
		if err != nil {
			s.logger.Warn("account_initial_billing_check_failed", "account_id", accountID, "error", err)
			syncErr = errors.Join(syncErr, fmt.Errorf("检查额度快照: %w", err))
		} else if !hasBilling {
			operationCtx, cancel := context.WithTimeout(ctx, operationTimeout)
			_, err = s.billing.RefreshBilling(operationCtx, accountID)
			cancel()
			if err != nil {
				s.logger.Warn("account_initial_billing_sync_failed", "account_id", accountID, "error", err)
				syncErr = errors.Join(syncErr, fmt.Errorf("同步额度: %w", err))
			} else {
				billingSnapshotCreated = true
			}
		}
	}

	hasModels, err := s.models.HasSuccessfulAccountSync(ctx, accountID)
	if err != nil {
		s.logger.Warn("account_initial_model_check_failed", "account_id", accountID, "error", err)
		return errors.Join(syncErr, fmt.Errorf("检查模型快照: %w", err))
	}
	if hasModels && !billingSnapshotCreated {
		return syncErr
	}
	operationCtx, cancel := context.WithTimeout(ctx, operationTimeout)
	_, err = s.models.SyncAccount(operationCtx, accountID)
	cancel()
	if err != nil {
		s.logger.Warn("account_initial_model_sync_failed", "account_id", accountID, "error", err)
		syncErr = errors.Join(syncErr, fmt.Errorf("同步模型: %w", err))
	}
	return syncErr
}
