package account

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	accountdomain "github.com/chenyme/grok2api/backend/internal/domain/account"
)

const (
	maxWebAccountScriptAccounts = 1000
	webAccountScriptLockTTL     = 5 * time.Minute
)

var ErrWebAccountScriptBusy = errors.New("Grok Web 账号脚本正在执行")

// WebAccountScriptOptions 定义 Grok Web 账号脚本需要执行的步骤。
// EnableNSFW 会隐式启用 SetBirthDate，保证上游年龄前置条件成立。
type WebAccountScriptOptions struct {
	AcceptTerms  bool
	SetBirthDate bool
	EnableNSFW   bool
}

// RunWebAccountScriptsWithProgress 为指定 Web 账号并发执行所选脚本，并按账号报告进度。
func (s *Service) RunWebAccountScriptsWithProgress(ctx context.Context, ids []uint64, options WebAccountScriptOptions, progress BatchProgressObserver) (int, int, error) {
	options, err := normalizeWebAccountScriptOptions(options)
	if err != nil {
		return 0, 0, err
	}
	ids, err = normalizeIDs(ids, maxWebAccountScriptAccounts)
	if err != nil {
		return 0, 0, err
	}
	return s.runWebAccountScriptBatch(ctx, ids, options, progress)
}

// RunAllWebAccountScriptsWithProgress 分页处理完整 Web 号池，避免一次性加载全部账号。
func (s *Service) RunAllWebAccountScriptsWithProgress(ctx context.Context, options WebAccountScriptOptions, progress BatchProgressObserver) (int, int, error) {
	options, err := normalizeWebAccountScriptOptions(options)
	if err != nil {
		return 0, 0, err
	}
	var (
		afterID   uint64
		completed int
		total     int
		succeeded int
		failed    int
		started   bool
	)
	for {
		values, count, err := s.accounts.ListProviderAccountBatch(ctx, accountdomain.ProviderWeb, afterID, accountTaskBatchSize)
		if err != nil {
			return succeeded, failed, mapRepositoryError(err)
		}
		if !started {
			total = int(count)
			started = true
			if progress != nil {
				if err := progress(0, total); err != nil {
					return succeeded, failed, err
				}
			}
		}
		if len(values) == 0 {
			return succeeded, failed, nil
		}
		remaining := total - completed
		if remaining <= 0 {
			return succeeded, failed, nil
		}
		if len(values) > remaining {
			values = values[:remaining]
		}
		ids := make([]uint64, 0, len(values))
		for _, value := range values {
			ids = append(ids, value.ID)
		}
		batchSucceeded, batchFailed, err := s.runWebAccountScriptBatch(ctx, ids, options, offsetBatchProgress(progress, completed, total))
		succeeded += batchSucceeded
		failed += batchFailed
		if err != nil {
			return succeeded, failed, err
		}
		completed += len(ids)
		afterID = ids[len(ids)-1]
		if completed >= total || len(ids) < accountTaskBatchSize {
			return succeeded, failed, nil
		}
	}
}

func normalizeWebAccountScriptOptions(options WebAccountScriptOptions) (WebAccountScriptOptions, error) {
	if !options.AcceptTerms && !options.SetBirthDate && !options.EnableNSFW {
		return WebAccountScriptOptions{}, invalidInput("至少选择一个账号脚本")
	}
	if options.EnableNSFW {
		options.SetBirthDate = true
	}
	return options, nil
}

func (s *Service) runSingleWebAccountScript(ctx context.Context, id uint64, options WebAccountScriptOptions) error {
	if s.syncPool == nil {
		return s.runWebAccountScript(ctx, id, options)
	}
	return s.syncPool.Do(ctx, func(workCtx context.Context) error {
		return s.runWebAccountScript(workCtx, id, options)
	})
}

func (s *Service) acquireWebAccountScriptLock(ctx context.Context, id uint64) (func(), error) {
	if s.refreshLock == nil {
		return func() {}, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key := "web-account-script:" + strconv.FormatUint(id, 10)
	release, acquired, err := s.refreshLock.Acquire(ctx, key, webAccountScriptLockTTL)
	if err != nil {
		return nil, err
	}
	if !acquired {
		return nil, ErrWebAccountScriptBusy
	}
	if release == nil {
		return func() {}, nil
	}
	return release, nil
}

func (s *Service) runWebAccountScriptBatch(ctx context.Context, ids []uint64, options WebAccountScriptOptions, progress BatchProgressObserver) (int, int, error) {
	return s.runAccountBatch(ctx, "web_account_scripts", ids, s.syncPool, progress, func(workCtx context.Context, id uint64) error {
		err := s.runWebAccountScript(workCtx, id, options)
		if err != nil && !errors.Is(err, context.Canceled) {
			s.logger.Warn("web_account_script_failed", "account_id", id, "error", err)
		}
		return err
	})
}

// WebAccountScriptScope selects which Web accounts a batch script run targets.
type WebAccountScriptScope string

const (
	// WebScriptScopeIDs uses the explicit id list.
	WebScriptScopeIDs WebAccountScriptScope = "ids"
	// WebScriptScopePending only accounts that still need the selected script steps (default for "all").
	WebScriptScopePending WebAccountScriptScope = "pending"
	// WebScriptScopePendingNSFW is an alias of pending when EnableNSFW is selected (R5).
	WebScriptScopePendingNSFW WebAccountScriptScope = "pending_nsfw"
	// WebScriptScopeAllForce processes the full Web pool (previous all=true semantics).
	WebScriptScopeAllForce WebAccountScriptScope = "all_force"
)

// NormalizeWebAccountScriptScope resolves empty/all defaults for R5 pending-only behavior.
func NormalizeWebAccountScriptScope(scope string, all bool, hasIDs bool) (WebAccountScriptScope, error) {
	raw := strings.TrimSpace(strings.ToLower(scope))
	switch raw {
	case "", "auto":
		if hasIDs && !all {
			return WebScriptScopeIDs, nil
		}
		if all || !hasIDs {
			return WebScriptScopePending, nil
		}
		return WebScriptScopeIDs, nil
	case "ids":
		return WebScriptScopeIDs, nil
	case "pending", "pending_only":
		return WebScriptScopePending, nil
	case "pending_nsfw":
		return WebScriptScopePendingNSFW, nil
	case "all", "all_force", "force_all":
		return WebScriptScopeAllForce, nil
	default:
		return "", invalidInput("脚本范围无效")
	}
}

// RunWebAccountScriptsScopedWithProgress runs scripts for ids/pending/all_force scopes.
func (s *Service) RunWebAccountScriptsScopedWithProgress(ctx context.Context, scope WebAccountScriptScope, ids []uint64, options WebAccountScriptOptions, progress BatchProgressObserver) (int, int, error) {
	options, err := normalizeWebAccountScriptOptions(options)
	if err != nil {
		return 0, 0, err
	}
	switch scope {
	case WebScriptScopeIDs:
		return s.RunWebAccountScriptsWithProgress(ctx, ids, options, progress)
	case WebScriptScopeAllForce:
		return s.RunAllWebAccountScriptsWithProgress(ctx, options, progress)
	case WebScriptScopePending, WebScriptScopePendingNSFW:
		return s.runPendingWebAccountScriptsWithProgress(ctx, options, progress)
	default:
		return 0, 0, invalidInput("脚本范围无效")
	}
}

func (s *Service) runPendingWebAccountScriptsWithProgress(ctx context.Context, options WebAccountScriptOptions, progress BatchProgressObserver) (int, int, error) {
	// Two-phase: collect candidates first so progress total is stable (async task friendly).
	candidates, err := s.listPendingWebScriptAccountIDs(ctx, options)
	if err != nil {
		return 0, 0, err
	}
	if progress != nil {
		if err := progress(0, len(candidates)); err != nil {
			return 0, 0, err
		}
	}
	if len(candidates) == 0 {
		return 0, 0, nil
	}
	return s.runWebAccountScriptBatch(ctx, candidates, options, progress)
}

func (s *Service) listPendingWebScriptAccountIDs(ctx context.Context, options WebAccountScriptOptions) ([]uint64, error) {
	var (
		afterID uint64
		out     []uint64
	)
	for {
		values, _, err := s.accounts.ListProviderAccountBatch(ctx, accountdomain.ProviderWeb, afterID, accountTaskBatchSize)
		if err != nil {
			return nil, mapRepositoryError(err)
		}
		if len(values) == 0 {
			return out, nil
		}
		for _, value := range values {
			if !value.Enabled || value.AuthStatus != accountdomain.AuthStatusActive {
				continue
			}
			if strings.TrimSpace(value.EncryptedAccessToken) == "" {
				continue
			}
			pending := pendingWebAccountScriptOptions(value, options)
			if !pending.AcceptTerms && !pending.SetBirthDate && !pending.EnableNSFW {
				continue
			}
			out = append(out, value.ID)
		}
		afterID = values[len(values)-1].ID
		if len(values) < accountTaskBatchSize {
			return out, nil
		}
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
	}
}
