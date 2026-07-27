package account

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	accountdomain "github.com/chenyme/grok2api/backend/internal/domain/account"
	"github.com/chenyme/grok2api/backend/internal/infra/config"
	"github.com/chenyme/grok2api/backend/internal/infra/provider"
	"github.com/chenyme/grok2api/backend/internal/infra/provider/conversation"
)

const (
	cliExploreDefaultModel   = "grok-3-mini"
	cliExploreDefaultTimeout = 25 * time.Second
	cliExploreDefaultCool    = 30 * time.Minute
	cliExploreMaxBodyPeek    = 64 << 10
)

// exploreOutcome is a stable ops label for logs (not stored as enum).
type exploreOutcome string

const (
	exploreOutcomeOK        exploreOutcome = "ok"
	exploreOutcomeBanned    exploreOutcome = "banned"
	exploreOutcomeJWTDead   exploreOutcome = "jwt_dead"
	exploreOutcomeQuota     exploreOutcome = "quota"
	exploreOutcomeTransport exploreOutcome = "transport"
	exploreOutcomeSkip      exploreOutcome = "skip"
)

// runCLIWarmExplore is Phase E: bounded chat probes on READY unproven warm accounts.
// Does not touch Web/Console, convert slots, or user request hard-layering.
func (s *Service) runCLIWarmExplore(ctx context.Context, cfg config.CLIRoutingConfig, stats warmScanStats, candidates []warmAccount) int {
	if !cfg.ExploreEnabled || s.providers == nil || s.accounts == nil {
		return 0
	}
	if !s.cliExploreGateOpen(cfg, stats) {
		s.logger.Debug("cli_explore_skipped", "reason", "gate_closed",
			"ready", stats.readyTotal, "unproven_ready", stats.unprovenReady, "proven_ready", stats.provenReady)
		return 0
	}
	budget := cfg.ExploreMaxPerTick
	if budget <= 0 {
		budget = 2
	}
	cooldown := cfg.ExploreCooldown.Value()
	if cooldown <= 0 {
		cooldown = cliExploreDefaultCool
	}
	timeout := cfg.ExploreTimeout.Value()
	if timeout <= 0 {
		timeout = cliExploreDefaultTimeout
	}
	model := strings.TrimSpace(cfg.ExploreModel)
	if model == "" {
		model = cliExploreDefaultModel
	}
	now := s.now()
	pool := filterExploreCandidates(candidates, now, cooldown)
	if len(pool) == 0 {
		s.logger.Debug("cli_explore_skipped", "reason", "no_candidates")
		return 0
	}
	// Prefer never-explored, then lower call_count, then older last_explore.
	sort.SliceStable(pool, func(i, j int) bool {
		ai, aj := pool[i].profile.LastExploreAt, pool[j].profile.LastExploreAt
		if ai == nil && aj != nil {
			return true
		}
		if ai != nil && aj == nil {
			return false
		}
		if ai != nil && aj != nil && !ai.Equal(*aj) {
			return ai.Before(*aj)
		}
		if pool[i].profile.CallCount != pool[j].profile.CallCount {
			return pool[i].profile.CallCount < pool[j].profile.CallCount
		}
		// Prefer L3 (trusted) over L4.
		return pool[i].class.Layer < pool[j].class.Layer
	})

	done := 0
	for _, item := range pool {
		if done >= budget {
			break
		}
		if !s.tryAcquireCLIExplore(cfg) {
			s.logger.Debug("cli_explore_skipped", "reason", "rate_limited", "done", done)
			break
		}
		outcome, err := s.exploreOneBuildAccount(ctx, item, model, timeout)
		if err != nil {
			s.logger.Debug("cli_explore_account_failed", "account_id", item.credential.ID, "outcome", string(outcome), "error", err)
		} else {
			s.logger.Info("cli_explore_result", "account_id", item.credential.ID, "outcome", string(outcome), "layer", int(item.class.Layer))
		}
		done++
	}
	if done > 0 {
		s.logger.Info("cli_explore_tick", "probed", done, "budget", budget,
			"ready", stats.readyTotal, "unproven_ready", stats.unprovenReady, "proven_ready", stats.provenReady)
	}
	return done
}

func (s *Service) cliExploreGateOpen(cfg config.CLIRoutingConfig, stats warmScanStats) bool {
	// Open when proven is thin OR unproven share is high (or either gate is zero = ignored).
	provenGate := cfg.ExploreMinProvenReady
	shareGate := cfg.ExploreUnprovenShareTrigger
	if provenGate <= 0 && shareGate <= 0 {
		// No gate configured: allow (ops must still set exploreEnabled).
		return true
	}
	if provenGate > 0 && stats.provenReady < provenGate {
		return true
	}
	if shareGate > 0 && stats.readyTotal > 0 {
		share := float64(stats.unprovenReady) / float64(stats.readyTotal)
		if share >= shareGate {
			return true
		}
	}
	return false
}

func filterExploreCandidates(candidates []warmAccount, now time.Time, cooldown time.Duration) []warmAccount {
	out := make([]warmAccount, 0, len(candidates))
	for _, item := range candidates {
		if item.profile.MaybeDead {
			continue
		}
		if item.class.Eligibility != accountdomain.CLIEligibilityReady {
			continue
		}
		if item.class.Proven {
			continue
		}
		if !accountdomain.UnprovenWarmBucket(item.class.WarmBucket) {
			continue
		}
		if item.profile.NextEligibleAt != nil && item.profile.NextEligibleAt.After(now) {
			continue
		}
		if item.credential.CooldownUntil != nil && item.credential.CooldownUntil.After(now) {
			continue
		}
		if item.profile.LastExploreAt != nil && cooldown > 0 && item.profile.LastExploreAt.Add(cooldown).After(now) {
			continue
		}
		out = append(out, item)
	}
	return out
}

func (s *Service) tryAcquireCLIExplore(cfg config.CLIRoutingConfig) bool {
	s.cliWarmMu.Lock()
	defer s.cliWarmMu.Unlock()
	limit := cfg.ExploreMaxPerMinute
	if limit <= 0 {
		limit = 10
	}
	now := s.now()
	cutoff := now.Add(-time.Minute)
	kept := s.cliExploreStarts[:0]
	for _, started := range s.cliExploreStarts {
		if started.After(cutoff) {
			kept = append(kept, started)
		}
	}
	s.cliExploreStarts = kept
	if len(s.cliExploreStarts) >= limit {
		return false
	}
	s.cliExploreStarts = append(s.cliExploreStarts, now)
	return true
}

func (s *Service) exploreOneBuildAccount(ctx context.Context, item warmAccount, model string, timeout time.Duration) (exploreOutcome, error) {
	cred := item.credential
	now := s.now()
	_ = s.accounts.TouchBuildCLIExploreAt(ctx, cred.ID, now)

	adapter, ok := s.providers.Responses(accountdomain.ProviderBuild)
	if !ok {
		return exploreOutcomeSkip, fmt.Errorf("build responses adapter unavailable")
	}
	body := []byte(fmt.Sprintf(`{"model":%q,"input":"ping","stream":false,"max_output_tokens":8}`, model))
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	resp, err := adapter.ForwardResponse(probeCtx, provider.ResponseResourceRequest{
		Credential:    cred,
		Billing:       item.billing,
		Method:        http.MethodPost,
		Path:          "/v1/responses",
		Body:          body,
		Model:         model,
		Streaming:     false,
		NormalizeBody: true,
		Operation:     conversation.OperationResponses,
	})
	if err != nil {
		return exploreOutcomeTransport, err
	}
	if resp == nil {
		return exploreOutcomeTransport, fmt.Errorf("empty upstream response")
	}
	peek, _ := io.ReadAll(io.LimitReader(resp.Body, cliExploreMaxBodyPeek))
	_ = resp.Body.Close()

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		if err := s.accounts.RecordBuildCLISuccess(ctx, cred.ID, s.now()); err != nil {
			return exploreOutcomeOK, err
		}
		return exploreOutcomeOK, nil
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusPaymentRequired:
		until := s.now().Add(15 * time.Minute)
		_ = s.accounts.RecordBuildCLICooldown(ctx, cred.ID, until, fmt.Sprintf("%d", resp.StatusCode))
		return exploreOutcomeQuota, nil
	case resp.StatusCode == http.StatusForbidden:
		alive, probeStatus := s.probeBuildJWTAlive(ctx, cred)
		if alive {
			// Chat ban: soft mark only (no RT, no reauth).
			_ = s.accounts.UpdateHealth(ctx, cred.ID, cred.FailureCount+1, nil, "cli_chat_banned", false)
			_ = s.accounts.RecordBuildCLI403(ctx, cred.ID, 1, "cli_chat_banned")
			if s.sticky != nil {
				_ = s.sticky.DeleteByAccount(ctx, cred.ID)
			}
			s.logger.Warn("cli_explore_banned", "account_id", cred.ID, "jwt_probe_status", probeStatus, "body_preview", truncateExploreBody(peek))
			return exploreOutcomeBanned, nil
		}
		s.logger.Warn("cli_explore_jwt_dead", "account_id", cred.ID, "jwt_probe_status", probeStatus)
		return exploreOutcomeJWTDead, nil
	case resp.StatusCode == http.StatusUnauthorized:
		return exploreOutcomeJWTDead, nil
	default:
		return exploreOutcomeTransport, fmt.Errorf("upstream status %d", resp.StatusCode)
	}
}

// probeBuildJWTAlive mirrors gateway.probeBuildJWTAlive: non-401/403 on billing ⇒ JWT alive.
func (s *Service) probeBuildJWTAlive(ctx context.Context, credential accountdomain.Credential) (alive bool, status int) {
	billing, ok := s.providers.Billing(credential.Provider)
	if !ok {
		return false, 0
	}
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := billing.GetBilling(probeCtx, credential)
	if err == nil {
		return true, http.StatusOK
	}
	msg := err.Error()
	for _, code := range []int{401, 403, 404, 429, 500, 502, 503} {
		if strings.Contains(msg, fmt.Sprintf("返回 %d", code)) || strings.Contains(msg, fmt.Sprintf(" %d", code)) {
			status = code
			break
		}
	}
	if status == 0 {
		return true, 0
	}
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return false, status
	}
	return true, status
}

func truncateExploreBody(body []byte) string {
	const max = 160
	text := strings.TrimSpace(string(body))
	if len(text) <= max {
		return text
	}
	return text[:max] + "…"
}
