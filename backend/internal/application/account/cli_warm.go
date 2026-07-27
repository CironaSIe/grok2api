package account

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	accountdomain "github.com/chenyme/grok2api/backend/internal/domain/account"
	"github.com/chenyme/grok2api/backend/internal/infra/config"
	webprovider "github.com/chenyme/grok2api/backend/internal/infra/provider/web"
)

const (
	cliWarmScanBatch             = 200
	cliWarmMaxActionsTick        = 40
	cliWarmDefaultTick           = 15 * time.Second
	cliWarmBillingCatchupPerTick = 5
	cliWarmWakeMinInterval       = 5 * time.Second  // coalesce WakeCLIWarm / wake-driven ticks
	cliWarmStatusLogMinInterval  = 60 * time.Second // rate-limit below_target / pioneer_blocked
)

// RunCLIWarm maintains Build CLI READY inventory (total water level) via RT then bounded Convert.
// Isolation: only touches grok_build credentials/profiles; never Web/Console auth state.
func (s *Service) RunCLIWarm(ctx context.Context) {
	cfg := s.cliRouting()
	tick := cfg.WarmTickInterval.Value()
	if tick <= 0 {
		tick = cliWarmDefaultTick
	}
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		fromTimer := false
		select {
		case <-ctx.Done():
			return
		case <-s.cliWarmWake:
		case <-s.cliConvertWake:
		case <-timer.C:
			fromTimer = true
		}
		// Drain extra wake signals so a storm collapses into one decision.
		s.drainCLIWarmSignals()

		runFullTick := fromTimer
		if !runFullTick {
			s.cliWarmMu.RLock()
			last := s.cliWarmLastTickAt
			s.cliWarmMu.RUnlock()
			runFullTick = last.IsZero() || s.now().Sub(last) >= cliWarmWakeMinInterval
		}
		if runFullTick {
			if err := s.runCLIWarmTick(ctx); err != nil && ctx.Err() == nil {
				s.logger.Warn("cli_warm_tick_failed", "error", err)
			}
			s.cliWarmMu.Lock()
			s.cliWarmLastTickAt = s.now()
			s.cliWarmMu.Unlock()
		}
		// Drain convert queue opportunistically each wake (cheap vs full material scan).
		s.drainCLIConvertQueue(ctx)
		cfg = s.cliRouting()
		tick = cfg.WarmTickInterval.Value()
		if tick <= 0 {
			tick = cliWarmDefaultTick
		}
		resetCredentialRefreshTimer(timer, tick)
	}
}

// drainCLIWarmSignals empties pending warm/convert wake channels (non-blocking).
func (s *Service) drainCLIWarmSignals() {
	for {
		select {
		case <-s.cliWarmWake:
		case <-s.cliConvertWake:
		default:
			return
		}
	}
}

func (s *Service) runCLIWarmTick(ctx context.Context) error {
	cfg := s.cliRouting()
	if !cfg.Enabled || cfg.WarmTargetTotal <= 0 {
		return nil
	}
	stats, material, err := s.scanBuildCLIWarmMaterial(ctx, cfg)
	if err != nil {
		return err
	}
	// Prefer RT (REFRESHABLE) over Convert (ACQUIRE) within each bucket.
	for bucket, items := range material {
		sortWarmMaterial(items)
		material[bucket] = items
	}
	s.storeCLIWarmSnapshot(cfg, stats)

	totalReady := stats.readyTotal
	unprovenReady := stats.unprovenReady
	unprovenCap := cfg.UnprovenCap()
	actions := 0
	used := map[uint64]bool{}
	order := normalizeWarmFillOrder(cfg.WarmFillOrder)

	// Phase A — soft floors (号池调度.md §4.1): if soft_floor 未满足, 优先补到 effective_floor.
	// effective_floor = min(config floor, have+material); never chase empty sea / free Convert.
	if totalReady < cfg.WarmTargetTotal || softFloorsNeedMaintenance(cfg, stats, material) {
		for _, bucket := range order {
			if actions >= cliWarmMaxActionsTick || ctx.Err() != nil {
				break
			}
			if !bucketAllowedByConfig(cfg, bucket) {
				continue
			}
			if accountdomain.UnprovenWarmBucket(bucket) && unprovenCap > 0 && unprovenReady >= unprovenCap {
				continue
			}
			have := stats.readyByBucket[bucket]
			floor := softFloorFor(cfg, bucket)
			if floor <= 0 {
				continue
			}
			effective := effectiveSoftFloor(floor, have, len(material[bucket]))
			if have >= effective {
				continue
			}
			want := effective - have
			if totalReady < cfg.WarmTargetTotal {
				// While below target, floors must not alone exceed remaining deficit.
				if deficit := cfg.WarmTargetTotal - totalReady; want > deficit {
					want = deficit
				}
			}
			filled, _ := s.fillWarmBucket(ctx, cfg, bucket, material[bucket], want, &actions, used)
			totalReady += filled
			stats.readyByBucket[bucket] = have + filled
			if accountdomain.UnprovenWarmBucket(bucket) {
				unprovenReady += filled
			}
		}
	}

	// Phase B — primary deficit fill by fill_order (proven first; no soft-floor cap).
	if totalReady < cfg.WarmTargetTotal {
		deficit := cfg.WarmTargetTotal - totalReady
		for _, bucket := range order {
			if deficit <= 0 || actions >= cliWarmMaxActionsTick || ctx.Err() != nil {
				break
			}
			if !bucketAllowedByConfig(cfg, bucket) {
				continue
			}
			if accountdomain.UnprovenWarmBucket(bucket) && unprovenCap > 0 && unprovenReady >= unprovenCap {
				continue
			}
			filled, _ := s.fillWarmBucket(ctx, cfg, bucket, material[bucket], deficit, &actions, used)
			totalReady += filled
			deficit -= filled
			stats.readyByBucket[bucket] += filled
			if accountdomain.UnprovenWarmBucket(bucket) {
				unprovenReady += filled
			}
		}
	}

	// Phase C — open-field pioneer: Web SSO → new Build when material cannot cover the deficit.
	// Convert is async; pioneered counts started jobs (not immediate READY).
	// New pioneers are unproven (L3/L4): must respect UnprovenCap (号池调度.md §4.3.1 / §7.3).
	pioneered := 0
	if totalReady < cfg.WarmTargetTotal && cfg.AutoPioneerFromWeb && actions < cliWarmMaxActionsTick && ctx.Err() == nil {
		// Only pioneer when Build-side fill material is exhausted (or none left unused).
		if !warmMaterialHasUnused(material, used) {
			deficit := cfg.WarmTargetTotal - totalReady
			if unprovenCap > 0 {
				headroom := unprovenCap - unprovenReady
				if headroom <= 0 {
					s.logCLIWarmStatus("cli_warm_pioneer_blocked_unproven_cap", totalReady, cfg.WarmTargetTotal, unprovenReady, unprovenCap, 0, 0, 0)
				} else {
					if deficit > headroom {
						deficit = headroom
					}
					pioneered = s.pioneerFromUnlinkedWeb(ctx, cfg, deficit, &actions)
				}
			} else {
				pioneered = s.pioneerFromUnlinkedWeb(ctx, cfg, deficit, &actions)
			}
		}
	}

	// Phase D — catch up missing Build billing snapshots (开荒后「待识别」).
	// Bounded; does not hold convert slots. Existing pioneered accounts without billing get healed over ticks.
	s.catchupMissingBuildBilling(ctx, cliWarmBillingCatchupPerTick)

	// Phase E — bounded unproven explore (旁路验真). Never blocks fill/convert; default off.
	explored := s.runCLIWarmExplore(ctx, cfg, stats, stats.explorePool)

	s.storeCLIWarmSnapshot(cfg, warmScanStats{
		readyTotal: totalReady, unprovenReady: unprovenReady, provenReady: stats.provenReady, readyByBucket: stats.readyByBucket,
	})
	if totalReady < cfg.WarmTargetTotal {
		s.logCLIWarmStatus("cli_warm_below_target", totalReady, cfg.WarmTargetTotal, unprovenReady, unprovenCap, actions, pioneered, explored)
	}
	return nil
}

// logCLIWarmStatus rate-limits inventory-stuck INFO logs when the signature is unchanged
// (e.g. actions=0 under unproven cap). State changes or action progress always log.
func (s *Service) logCLIWarmStatus(msg string, ready, target, unprovenReady, unprovenCap, actions, pioneered, explored int) {
	sig := fmt.Sprintf("%s|%d|%d|%d|%d|%d|%d|%d", msg, ready, target, unprovenReady, unprovenCap, actions, pioneered, explored)
	now := s.now()
	s.cliWarmMu.Lock()
	same := s.cliWarmLastStatusSig == sig
	recent := !s.cliWarmLastStatusLog.IsZero() && now.Sub(s.cliWarmLastStatusLog) < cliWarmStatusLogMinInterval
	// Always surface progress; only suppress identical stuck snapshots.
	if same && recent && actions == 0 && pioneered == 0 && explored == 0 {
		s.cliWarmMu.Unlock()
		return
	}
	s.cliWarmLastStatusSig = sig
	s.cliWarmLastStatusLog = now
	s.cliWarmMu.Unlock()
	if s.logger == nil {
		return
	}
	s.logger.Info(msg,
		"ready", ready, "target", target, "unproven_ready", unprovenReady, "unproven_cap", unprovenCap,
		"actions", actions, "pioneered", pioneered, "explored", explored)
}

func warmMaterialHasUnused(material map[accountdomain.WarmBucket][]warmAccount, used map[uint64]bool) bool {
	for _, items := range material {
		for _, item := range items {
			if used[item.credential.ID] {
				continue
			}
			if item.class.Eligibility == accountdomain.CLIEligibilityReady {
				continue
			}
			return true
		}
	}
	return false
}

// pioneerFromUnlinkedWeb starts bounded async Web→Build converts for unlinked SSO accounts.
// Returns number of pioneer jobs started (each holds a convert slot until finished).
func (s *Service) pioneerFromUnlinkedWeb(ctx context.Context, cfg config.CLIRoutingConfig, want int, actions *int) int {
	if s.accounts == nil || !cfg.AutoPioneerFromWeb || want <= 0 || actions == nil {
		return 0
	}
	maxPerTick := cfg.MaxPioneerPerTick
	if maxPerTick <= 0 {
		maxPerTick = 5
	}
	if want > maxPerTick {
		want = maxPerTick
	}
	if remain := cliWarmMaxActionsTick - *actions; remain <= 0 {
		return 0
	} else if want > remain {
		want = remain
	}

	candidates, err := s.listPioneerWebCandidates(ctx, cfg, want*4)
	if err != nil {
		s.logger.Warn("cli_warm_pioneer_list_failed", "error", err)
		return 0
	}
	if len(candidates) == 0 {
		s.logger.Info("cli_warm_pioneer_no_candidates", "want", want)
		return 0
	}

	started := 0
	for _, webID := range candidates {
		if started >= want || *actions >= cliWarmMaxActionsTick || ctx.Err() != nil {
			break
		}
		if !s.tryAcquireCLIConvert(cfg) {
			s.logger.Debug("cli_warm_pioneer_rate_limited", "started", started, "want", want)
			break
		}
		*actions++
		started++
		go s.runCLIPioneerJob(ctx, webID)
	}
	if started > 0 {
		s.logger.Info("cli_warm_pioneer_started", "started", started, "want", want, "candidates", len(candidates))
	}
	return started
}

func (s *Service) listPioneerWebCandidates(ctx context.Context, cfg config.CLIRoutingConfig, limit int) ([]uint64, error) {
	if limit < 1 {
		return nil, nil
	}
	const batch = 50
	trusted := make([]uint64, 0, limit)
	other := make([]uint64, 0, limit)
	var afterID uint64
	for len(trusted)+len(other) < limit {
		ids, _, err := s.accounts.ListUnlinkedWebAccountIDs(ctx, afterID, batch)
		if err != nil {
			return nil, mapRepositoryError(err)
		}
		if len(ids) == 0 {
			break
		}
		for _, id := range ids {
			if len(trusted)+len(other) >= limit {
				break
			}
			value, getErr := s.accounts.Get(ctx, id)
			if getErr != nil {
				continue
			}
			if value.Provider != accountdomain.ProviderWeb || value.AuthType != accountdomain.AuthTypeSSO {
				continue
			}
			if !value.Enabled || value.AuthStatus != accountdomain.AuthStatusActive {
				continue
			}
			if strings.TrimSpace(value.EncryptedAccessToken) == "" {
				continue
			}
			if value.HasAccountTag(accountdomain.TagCLITrusted) {
				trusted = append(trusted, id)
			} else {
				other = append(other, id)
			}
		}
		afterID = ids[len(ids)-1]
		if len(ids) < batch {
			break
		}
	}
	out := make([]uint64, 0, len(trusted)+len(other))
	if cfg.PioneerPreferTrusted {
		out = append(out, trusted...)
		out = append(out, other...)
	} else {
		out = append(out, other...)
		out = append(out, trusted...)
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// runCLIPioneerJob converts an unlinked Web SSO into Build (missing strategy). Failures do not disable Web.
// After convert, best-effort RefreshBilling so admin UI does not stay 「待识别」(quota unknown).
func (s *Service) runCLIPioneerJob(ctx context.Context, webID uint64) {
	slotHeld := true
	releaseSlot := func() {
		if slotHeld {
			slotHeld = false
			s.releaseCLIConvertSlot()
		}
	}
	defer releaseSlot()

	taskCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
	defer cancel()
	lock := s.ssoLock(webID)
	lock.Lock()
	buildID, created, skipped, err := s.convertWebAccountToBuild(taskCtx, webID, BuildConversionMissing, ConvertBuildOptions{})
	lock.Unlock()
	// Free convert slot before billing so slow billing does not starve further pioneers.
	releaseSlot()
	if err != nil {
		s.logger.Warn("cli_warm_pioneer_failed", "web_account_id", webID, "error", err)
		return
	}
	if skipped {
		s.logger.Debug("cli_warm_pioneer_skipped", "web_account_id", webID)
		return
	}
	s.logger.Info("cli_warm_pioneer_ok", "web_account_id", webID, "build_account_id", buildID, "created", created)
	// Admin convert path runs accountsync (billing+models) via HTTP Observe.
	// Pioneer is worker-side: RefreshBilling alone is enough to classify free/paid.
	if buildID != 0 {
		billCtx, billCancel := context.WithTimeout(context.WithoutCancel(ctx), 45*time.Second)
		if _, billErr := s.RefreshBilling(billCtx, buildID); billErr != nil {
			s.logger.Warn("cli_warm_pioneer_billing_sync_failed", "web_account_id", webID, "build_account_id", buildID, "error", billErr)
		} else {
			s.logger.Info("cli_warm_pioneer_billing_synced", "build_account_id", buildID)
			s.bumpAccountDomainRevision(billCtx)
		}
		billCancel()
	}
	s.WakeCredentialRefresh()
	s.WakeCLIWarm()
}

// catchupMissingBuildBilling best-effort RefreshBilling for Build accounts lacking a snapshot.
// Fixes UI 「待识别」 after pioneer/import without admin bulk sync. Failures are logged only.
func (s *Service) catchupMissingBuildBilling(ctx context.Context, limit int) {
	if s.accounts == nil || limit <= 0 || ctx.Err() != nil {
		return
	}
	ids, err := s.listBuildIDsMissingBilling(ctx, limit)
	if err != nil {
		s.logger.Warn("cli_warm_billing_catchup_list_failed", "error", err)
		return
	}
	if len(ids) == 0 {
		return
	}
	started := make([]uint64, 0, len(ids))
	for _, id := range ids {
		if ctx.Err() != nil {
			break
		}
		if _, loaded := s.cliBillingCatchupInflight.LoadOrStore(id, struct{}{}); loaded {
			continue
		}
		started = append(started, id)
		buildID := id
		go func() {
			defer s.cliBillingCatchupInflight.Delete(buildID)
			billCtx, billCancel := context.WithTimeout(context.WithoutCancel(ctx), 45*time.Second)
			defer billCancel()
			if _, billErr := s.RefreshBilling(billCtx, buildID); billErr != nil {
				s.logger.Warn("cli_warm_billing_catchup_failed", "build_account_id", buildID, "error", billErr)
				return
			}
			s.logger.Info("cli_warm_billing_catchup_synced", "build_account_id", buildID)
			s.bumpAccountDomainRevision(billCtx)
		}()
	}
	if len(started) > 0 {
		s.logger.Info("cli_warm_billing_catchup_started", "count", len(started))
	}
}

// listBuildIDsMissingBilling returns up to limit enabled Build IDs with no billing snapshot.
func (s *Service) listBuildIDsMissingBilling(ctx context.Context, limit int) ([]uint64, error) {
	if limit <= 0 {
		return nil, nil
	}
	out := make([]uint64, 0, limit)
	var afterID uint64
	for len(out) < limit {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		values, _, err := s.accounts.ListProviderAccountBatch(ctx, accountdomain.ProviderBuild, afterID, cliWarmScanBatch)
		if err != nil {
			return out, err
		}
		if len(values) == 0 {
			break
		}
		ids := make([]uint64, 0, len(values))
		for _, v := range values {
			afterID = v.ID
			if !v.Enabled || v.AuthStatus != accountdomain.AuthStatusActive {
				continue
			}
			ids = append(ids, v.ID)
		}
		if len(ids) == 0 {
			continue
		}
		billings, err := s.accounts.GetBillings(ctx, ids)
		if err != nil {
			return out, err
		}
		for _, id := range ids {
			if _, ok := billings[id]; ok {
				continue
			}
			out = append(out, id)
			if len(out) >= limit {
				return out, nil
			}
		}
	}
	return out, nil
}

// fillWarmBucket attempts up to want READY promotions from candidates (RT then Convert).
// Mutates actions and used; skips READY and accounts already touched this tick.
func (s *Service) fillWarmBucket(ctx context.Context, cfg config.CLIRoutingConfig, bucket accountdomain.WarmBucket, candidates []warmAccount, want int, actions *int, used map[uint64]bool) (filled int, actedN int) {
	if want <= 0 || len(candidates) == 0 || actions == nil {
		return 0, 0
	}
	if used == nil {
		used = map[uint64]bool{}
	}
	for _, item := range candidates {
		if want <= 0 || *actions >= cliWarmMaxActionsTick || ctx.Err() != nil {
			break
		}
		id := item.credential.ID
		if used[id] || item.class.Eligibility == accountdomain.CLIEligibilityReady {
			continue
		}
		acted, becameReady, err := s.warmOneBuildAccount(ctx, cfg, item)
		if err != nil && ctx.Err() == nil {
			s.logger.Debug("cli_warm_account_failed", "account_id", id, "bucket", string(bucket), "error", err)
		}
		if !acted {
			continue
		}
		used[id] = true
		*actions++
		actedN++
		if becameReady {
			filled++
			want--
		}
	}
	return filled, actedN
}

func sortWarmMaterial(items []warmAccount) {
	// REFRESHABLE (cheap RT) before ACQUIRE_ALLOWED (Convert).
	sort.SliceStable(items, func(i, j int) bool {
		return warmMaterialRank(items[i]) > warmMaterialRank(items[j])
	})
}

func warmMaterialRank(item warmAccount) int {
	return accountdomain.EligibilityRank(item.class.Eligibility)
}

func effectiveSoftFloor(floor, have, material int) int {
	if floor <= 0 {
		return 0
	}
	maxReady := have + material
	if maxReady < floor {
		return maxReady
	}
	return floor
}

// softFloorsNeedMaintenance reports whether any bucket is below effective soft floor with material left.
func softFloorsNeedMaintenance(cfg config.CLIRoutingConfig, stats warmScanStats, material map[accountdomain.WarmBucket][]warmAccount) bool {
	for _, bucket := range normalizeWarmFillOrder(cfg.WarmFillOrder) {
		if !bucketAllowedByConfig(cfg, bucket) {
			continue
		}
		floor := softFloorFor(cfg, bucket)
		if floor <= 0 {
			continue
		}
		have := stats.readyByBucket[bucket]
		effective := effectiveSoftFloor(floor, have, len(material[bucket]))
		if have < effective {
			return true
		}
	}
	return false
}

type warmAccount struct {
	credential accountdomain.Credential
	billing    *accountdomain.Billing
	profile    accountdomain.CLIProfile
	class      accountdomain.CLIClassification
}

type warmScanStats struct {
	readyTotal     int
	unprovenReady  int
	provenReady    int
	readyByBucket  map[accountdomain.WarmBucket]int
	explorePool    []warmAccount // READY unproven (for Phase E)
}

func (s *Service) scanBuildCLIWarmMaterial(ctx context.Context, cfg config.CLIRoutingConfig) (warmScanStats, map[accountdomain.WarmBucket][]warmAccount, error) {
	stats := warmScanStats{readyByBucket: map[accountdomain.WarmBucket]int{}}
	material := map[accountdomain.WarmBucket][]warmAccount{}
	now := s.now()
	var afterID uint64
	for {
		values, _, err := s.accounts.ListProviderAccountBatch(ctx, accountdomain.ProviderBuild, afterID, cliWarmScanBatch)
		if err != nil {
			return stats, nil, err
		}
		if len(values) == 0 {
			break
		}
		ids := make([]uint64, 0, len(values))
		for _, v := range values {
			ids = append(ids, v.ID)
		}
		profiles, err := s.accounts.GetBuildCLIProfiles(ctx, ids)
		if err != nil {
			return stats, nil, err
		}
		billings, err := s.accounts.GetBillings(ctx, ids)
		if err != nil {
			return stats, nil, err
		}
		for _, cred := range values {
			if !cred.Enabled || cred.AuthStatus != accountdomain.AuthStatusActive {
				continue
			}
			profile := profiles[cred.ID]
			if profile.AccountID == 0 {
				profile.AccountID = cred.ID
			}
			var billing *accountdomain.Billing
			if b, ok := billings[cred.ID]; ok {
				billing = &b
			}
			class := accountdomain.ClassifyCLI(accountdomain.CLIClassifyInput{
				Credential: cred, Billing: billing, Profile: profile, Now: now,
			})
			item := warmAccount{credential: cred, billing: billing, profile: profile, class: class}
			if class.CountsTowardWarm {
				stats.readyTotal++
				stats.readyByBucket[class.WarmBucket]++
				if accountdomain.UnprovenWarmBucket(class.WarmBucket) {
					stats.unprovenReady++
					// READY unproven stock is explore material (Phase E).
					if class.Eligibility == accountdomain.CLIEligibilityReady && !profile.MaybeDead {
						stats.explorePool = append(stats.explorePool, item)
					}
				} else if class.Proven {
					stats.provenReady++
				}
			}
			if !class.WarmFillAllowed {
				continue
			}
			// Material for fill: not READY yet but could become READY via RT/Convert.
			if class.Eligibility == accountdomain.CLIEligibilityReady {
				continue
			}
			if class.Eligibility == accountdomain.CLIEligibilityTempBlocked || class.Eligibility == accountdomain.CLIEligibilityDenied {
				continue
			}
			if class.Eligibility == accountdomain.CLIEligibilityChatBanned || class.Eligibility == accountdomain.CLIEligibilityBotFlagged {
				// Chat ban never fill; soft bot_flagged enum is legacy hard-skip if ever set.
				continue
			}
			material[class.WarmBucket] = append(material[class.WarmBucket], item)
		}
		afterID = values[len(values)-1].ID
		if len(values) < cliWarmScanBatch {
			break
		}
	}
	return stats, material, nil
}

func (s *Service) warmOneBuildAccount(ctx context.Context, cfg config.CLIRoutingConfig, item warmAccount) (acted bool, becameReady bool, err error) {
	cred := item.credential
	switch item.class.Eligibility {
	case accountdomain.CLIEligibilityRefreshable:
		taskCtx, cancel := context.WithTimeout(ctx, credentialRefreshTimeout)
		defer cancel()
		refreshed, refreshErr := s.ensureCredential(taskCtx, cred, true, false, false)
		if refreshErr != nil {
			if errors.Is(refreshErr, ErrCredentialRefreshPermanent) && cred.LinkedAccountID != 0 {
				s.EnqueueBuildCLIConvert(cred.ID)
			}
			return true, false, refreshErr
		}
		class := accountdomain.ClassifyCLI(accountdomain.CLIClassifyInput{
			Credential: refreshed, Billing: item.billing, Profile: item.profile, Now: s.now(),
		})
		return true, class.Eligibility == accountdomain.CLIEligibilityReady, nil
	case accountdomain.CLIEligibilityAcquireAllowed:
		if cfg.ConvertOnRequest {
			// request path not used here; warm still converts async
		}
		if !cfg.AutoFillUnproven && !item.class.Proven && !item.class.NonFree {
			return false, false, nil
		}
		if item.class.NonFree && !cfg.AutoFillNonFree {
			return false, false, nil
		}
		if cfg.AutoFillRequireLinkedWeb && cred.LinkedAccountID == 0 {
			return false, false, nil
		}
		if cred.LinkedAccountID == 0 {
			return false, false, nil
		}
		s.EnqueueBuildCLIConvert(cred.ID)
		return true, false, nil
	default:
		return false, false, nil
	}
}

func (s *Service) drainCLIConvertQueue(ctx context.Context) {
	cfg := s.cliRouting()
	if !cfg.Enabled {
		return
	}
	// Spawn up to MaxConvertInflight workers per drain; rate also capped by MaxConvertPerMinute.
	limit := cfg.MaxConvertInflight
	if limit < 1 {
		limit = 1
	}
	budget := limit * 2
	for budget > 0 {
		select {
		case <-ctx.Done():
			return
		case buildID := <-s.cliConvertQueue:
			budget--
			if !s.tryAcquireCLIConvert(cfg) {
				// re-queue later (inflight full or per-minute cap)
				s.EnqueueBuildCLIConvert(buildID)
				return
			}
			// Parallel convert: slot held until job finishes (see runCLIConvertJob defer).
			go s.runCLIConvertJob(ctx, buildID)
		default:
			return
		}
	}
}

// tryAcquireCLIConvert enforces MaxConvertInflight and MaxConvertPerMinute (号池调度.md §8).
func (s *Service) tryAcquireCLIConvert(cfg config.CLIRoutingConfig) bool {
	s.cliWarmMu.Lock()
	defer s.cliWarmMu.Unlock()
	if cfg.MaxConvertPerMinute > 0 {
		now := s.now()
		cutoff := now.Add(-time.Minute)
		kept := s.cliConvertStarts[:0]
		for _, started := range s.cliConvertStarts {
			if started.After(cutoff) {
				kept = append(kept, started)
			}
		}
		s.cliConvertStarts = kept
		if len(s.cliConvertStarts) >= cfg.MaxConvertPerMinute {
			return false
		}
	}
	if s.cliConvertInflight == nil {
		limit := cfg.MaxConvertInflight
		if limit < 1 {
			limit = 1
		}
		if limit > 32 {
			limit = 32
		}
		s.cliConvertInflight = make(chan struct{}, limit)
	}
	select {
	case s.cliConvertInflight <- struct{}{}:
		if cfg.MaxConvertPerMinute > 0 {
			s.cliConvertStarts = append(s.cliConvertStarts, s.now())
		}
		return true
	default:
		return false
	}
}

func (s *Service) releaseCLIConvertSlot() {
	s.cliWarmMu.RLock()
	ch := s.cliConvertInflight
	s.cliWarmMu.RUnlock()
	if ch == nil {
		return
	}
	select {
	case <-ch:
	default:
	}
}

func (s *Service) runCLIConvertJob(ctx context.Context, buildID uint64) {
	defer s.releaseCLIConvertSlot()
	// Detach from parent cancel so warm-tick return does not abort in-flight convert;
	// still bound by process context deadline if present, plus hard 2m timeout.
	taskCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
	defer cancel()
	if err := s.reviveBuildCLIViaLinkedWeb(taskCtx, buildID); err != nil {
		s.logger.Warn("cli_warm_convert_failed",
			"build_account_id", buildID,
			"class", string(webprovider.ClassifyConversionError(err)),
			"error", err,
		)
	}
}

// reviveBuildCLIViaLinkedWeb re-runs Web→Build convert for an existing linked pair (RT death / acquire).
// Writes only Build tokens + CLI generation; does not MarkReauth on Web unless SSO rejected.
func (s *Service) reviveBuildCLIViaLinkedWeb(ctx context.Context, buildID uint64) error {
	build, err := s.accounts.Get(ctx, buildID)
	if err != nil {
		mapped := mapRepositoryError(err)
		if errors.Is(mapped, ErrNotFound) {
			return fmt.Errorf("Build 账号不存在 id=%d（warm 队列持有旧 build_account_id；不等于关联 SSO 失效）: %w", buildID, mapped)
		}
		return mapped
	}
	if build.Provider != accountdomain.ProviderBuild {
		return fmt.Errorf("cli convert revive 需要 Build 账号 id=%d provider=%s", buildID, build.Provider)
	}
	if build.LinkedAccountID == 0 {
		return fmt.Errorf("Build 账号 id=%d 未关联 Web SSO，无法 revive convert", buildID)
	}
	webID := build.LinkedAccountID
	lock := s.ssoLock(webID)
	lock.Lock()
	defer lock.Unlock()
	_, _, _, err = s.convertWebAccountToBuild(ctx, webID, BuildConversionAll, ConvertBuildOptions{})
	if err != nil {
		return fmt.Errorf("revive build_id=%d web_id=%d: %w", buildID, webID, err)
	}
	if _, genErr := s.accounts.BumpBuildCLITokenGeneration(ctx, buildID); genErr != nil {
		s.logger.Warn("cli_token_generation_bump_failed", "build_account_id", buildID, "error", genErr)
	}
	// Clear permanent RT flag by loading refreshed account (persistSeed updates tokens).
	s.clearRefreshState(buildID)
	s.WakeCredentialRefresh()
	s.WakeCLIWarm()
	return nil
}

func (s *Service) ssoLock(webAccountID uint64) *sync.Mutex {
	actual, _ := s.cliSSOLocks.LoadOrStore(webAccountID, &sync.Mutex{})
	return actual.(*sync.Mutex)
}

// shouldAutoRefreshBuildDue gates due-list auto RT for Build so free sea accounts are not all refreshed.
func (s *Service) shouldAutoRefreshBuildDue(cred accountdomain.Credential, profile accountdomain.CLIProfile, billing *accountdomain.Billing, cfg config.CLIRoutingConfig) bool {
	if !cfg.Enabled {
		return true // legacy: refresh any due when CLI policy off
	}
	// Chat-only ban: JWT still works; thrashing RT refresh wastes budget and confuses ops.
	if profile.MaybeDead {
		return false
	}
	class := accountdomain.ClassifyCLI(accountdomain.CLIClassifyInput{
		Credential: cred, Billing: billing, Profile: profile, Now: s.now(),
	})
	if !class.WarmFillAllowed && !class.Proven {
		return false
	}
	// Always maintain proven / non-free / trusted for due RT.
	if class.Proven || class.NonFree || profile.TrustedSource {
		return true
	}
	// Unproven free: only if auto-fill unproven allowed (warm path prefers worker).
	return cfg.AutoFillUnproven
}

func normalizeWarmFillOrder(order []string) []accountdomain.WarmBucket {
	if len(order) == 0 {
		order = config.DefaultCLIRoutingConfig().WarmFillOrder
	}
	out := make([]accountdomain.WarmBucket, 0, len(order))
	seen := map[accountdomain.WarmBucket]bool{}
	for _, raw := range order {
		b := accountdomain.WarmBucket(raw)
		switch b {
		case accountdomain.WarmBucketL1, accountdomain.WarmBucketL2, accountdomain.WarmBucketNonFreeUnproven,
			accountdomain.WarmBucketL3, accountdomain.WarmBucketL4:
			if !seen[b] {
				seen[b] = true
				out = append(out, b)
			}
		}
	}
	return out
}

// softFloorFor returns configured soft floor for a warm bucket (号池调度.md §4.1 / §7.6).
func softFloorFor(cfg config.CLIRoutingConfig, bucket accountdomain.WarmBucket) int {
	switch bucket {
	case accountdomain.WarmBucketL1:
		return cfg.WarmSoftFloorL1
	case accountdomain.WarmBucketL2:
		return cfg.WarmSoftFloorL2
	case accountdomain.WarmBucketNonFreeUnproven:
		return cfg.WarmSoftFloorNonFreeUnproven
	case accountdomain.WarmBucketL3:
		return cfg.WarmSoftFloorL3
	case accountdomain.WarmBucketL4:
		return cfg.WarmSoftFloorL4
	default:
		return 0
	}
}

func bucketAllowedByConfig(cfg config.CLIRoutingConfig, bucket accountdomain.WarmBucket) bool {
	switch bucket {
	case accountdomain.WarmBucketL1, accountdomain.WarmBucketL2:
		// Proven inventory is always maintained when CLI warm is enabled.
		return true
	case accountdomain.WarmBucketNonFreeUnproven:
		return cfg.AutoFillNonFree
	case accountdomain.WarmBucketL3, accountdomain.WarmBucketL4:
		return cfg.AutoFillUnproven
	default:
		return true
	}
}

func (s *Service) storeCLIWarmSnapshot(cfg config.CLIRoutingConfig, stats warmScanStats) {
	by := make(map[string]int, len(stats.readyByBucket))
	for b, n := range stats.readyByBucket {
		by[string(b)] = n
	}
	s.cliWarmMu.Lock()
	s.cliWarmSnapshot = CLIWarmSnapshot{
		ReadyTotal: stats.readyTotal, UnprovenReady: stats.unprovenReady, UnprovenCap: cfg.UnprovenCap(),
		Target: cfg.WarmTargetTotal, ReadyByBucket: by, UpdatedAt: s.now(),
	}
	s.cliWarmMu.Unlock()
}
