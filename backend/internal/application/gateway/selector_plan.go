package gateway

import (
	"container/heap"
	"context"
	"crypto/sha256"
	"fmt"
	"math/rand/v2"
	"strconv"
	"time"

	"github.com/chenyme/grok2api/backend/internal/domain/account"
	"github.com/chenyme/grok2api/backend/internal/repository"
)

type candidateScore struct {
	index           int
	tier            int
	preferFreeBuild bool
	// cliLayer is 1..5 when CLI layering enabled; 0 means disabled/ignored.
	cliLayer int
	// eligibilityRank higher is better when CLI layering enabled.
	eligibilityRank int
	// callCount from build_cli_profiles for load spread within layer.
	callCount int
	billingFresh    bool
	inFlight        int
	remaining       float64
	lastSelected    time.Time
	// jitter is a stable [0,1) hash used only when selectionJitterRatio > 0.
	jitter float64
}

// candidatePlan 使用线性建堆保留完整路由优先级，并允许 claim 失败后按顺序取下一账号。
type candidatePlan struct {
	values     []account.RoutingCandidate
	scores     []candidateScore
	jitterRatio float64
}

func (p *candidatePlan) Len() int { return len(p.scores) }

func (p *candidatePlan) Less(left, right int) bool {
	return candidateScoreBetter(p.values, p.scores[left], p.scores[right], p.jitterRatio)
}

func (p *candidatePlan) Swap(left, right int) {
	p.scores[left], p.scores[right] = p.scores[right], p.scores[left]
}

func (p *candidatePlan) Push(value any) {
	p.scores = append(p.scores, value.(candidateScore))
}

func (p *candidatePlan) Pop() any {
	last := len(p.scores) - 1
	value := p.scores[last]
	p.scores = p.scores[:last]
	return value
}

func (p *candidatePlan) Next() (account.RoutingCandidate, bool) {
	if p == nil || p.Len() == 0 {
		return account.RoutingCandidate{}, false
	}
	score := heap.Pop(p).(candidateScore)
	return p.values[score.index], true
}

func candidateScoreBetter(values []account.RoutingCandidate, leftScore, rightScore candidateScore, jitterRatio float64) bool {
	leftCandidate, rightCandidate := values[leftScore.index], values[rightScore.index]
	left, right := leftCandidate.Credential, rightCandidate.Credential
	if leftCandidate.SupportsModel != rightCandidate.SupportsModel {
		return leftCandidate.SupportsModel
	}
	if leftCandidate.ModelCapabilityKnown != rightCandidate.ModelCapabilityKnown {
		return leftCandidate.ModelCapabilityKnown
	}
	// CLI hard layer: lower layer number wins (safety if partition not applied).
	if leftScore.cliLayer != 0 && rightScore.cliLayer != 0 && leftScore.cliLayer != rightScore.cliLayer {
		return leftScore.cliLayer < rightScore.cliLayer
	}
	if leftScore.eligibilityRank != rightScore.eligibilityRank {
		return leftScore.eligibilityRank > rightScore.eligibilityRank
	}
	// preferFreeBuild is within-layer only when layers match (see 号池调度.md).
	if leftScore.preferFreeBuild != rightScore.preferFreeBuild {
		return leftScore.preferFreeBuild
	}
	if leftScore.callCount != rightScore.callCount {
		return leftScore.callCount < rightScore.callCount
	}
	if leftScore.tier != rightScore.tier {
		return leftScore.tier < rightScore.tier
	}
	if left.Priority != right.Priority {
		return left.Priority > right.Priority
	}
	if leftScore.billingFresh != rightScore.billingFresh {
		return leftScore.billingFresh
	}
	if leftScore.inFlight != rightScore.inFlight {
		return leftScore.inFlight < rightScore.inFlight
	}
	if leftScore.remaining != rightScore.remaining {
		// Near-tie on continuous remaining: fall through so hash jitter can break ties.
		if jitterRatio <= 0 || !remainingNearTie(leftScore.remaining, rightScore.remaining, jitterRatio) {
			return leftScore.remaining > rightScore.remaining
		}
	}
	if !leftScore.lastSelected.Equal(rightScore.lastSelected) {
		return leftScore.lastSelected.Before(rightScore.lastSelected)
	}
	if jitterRatio > 0 && leftScore.jitter != rightScore.jitter {
		return leftScore.jitter < rightScore.jitter
	}
	return left.ID < right.ID
}

// remainingNearTie reports whether two remaining values are close enough that
// free-pool load should prefer hash jitter over tiny quota differences.
func remainingNearTie(left, right, ratio float64) bool {
	if left == right {
		return true
	}
	diff := left - right
	if diff < 0 {
		diff = -diff
	}
	scale := left
	if right > scale {
		scale = right
	}
	if scale < 1 {
		scale = 1
	}
	return diff <= scale*ratio
}

// selectionJitter returns a stable [0,1) value for accountID and salt.
func selectionJitter(accountID uint64, salt string) float64 {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", salt, accountID)))
	// 53-bit fraction fits float64 mantissa without overflow.
	var n uint64
	for i := 0; i < 7; i++ {
		n = (n << 8) | uint64(sum[i])
	}
	n >>= 3 // 56-3 = 53 bits
	return float64(n) / float64(1<<53)
}

// planCandidates 批量读取动态并发状态，并以 O(n) 建堆生成保持原比较规则的候选计划。
func (s *Selector) planCandidates(ctx context.Context, values []account.RoutingCandidate, now time.Time, tierOrder []account.WebTier) (*candidatePlan, error) {
	return s.planCandidateIndexes(ctx, values, nil, now, tierOrder)
}

// planCandidateIndexes 在不可变候选快照上按下标规划，避免过滤阶段复制完整账号结构。
// indexes 为 nil 时表示使用 values 的全部元素。
func (s *Selector) planCandidateIndexes(ctx context.Context, values []account.RoutingCandidate, indexes []int, now time.Time, tierOrder []account.WebTier) (*candidatePlan, error) {
	return s.planCandidateIndexesWithHints(ctx, values, indexes, now, tierOrder, nil, s.preferFreeBuildEnabled())
}

func (s *Selector) planCandidateIndexesWithHints(ctx context.Context, values []account.RoutingCandidate, indexes []int, now time.Time, tierOrder []account.WebTier, concurrencyHints []int, preferFreeBuild bool) (*candidatePlan, error) {
	length := len(indexes)
	if indexes == nil {
		length = len(values)
	}
	inFlight := make([]int, length)
	if concurrencyHints == nil {
		keys := make([]string, length)
		for position := range length {
			index := position
			if indexes != nil {
				index = indexes[position]
			}
			keys[position] = accountConcurrencyKey(values[index].Credential.ID)
		}
		concurrencySnapshot, err := s.loadConcurrencySnapshot(ctx, keys)
		if err != nil {
			return nil, err
		}
		for position := range length {
			inFlight[position] = concurrencySnapshot[keys[position]]
		}
	} else {
		missingIndexes := make([]int, 0, length)
		keys := make([]string, 0, length)
		for position := range length {
			index := position
			if indexes != nil {
				index = indexes[position]
			}
			if concurrencyHints[index] != 0 {
				continue
			}
			missingIndexes = append(missingIndexes, index)
			keys = append(keys, accountConcurrencyKey(values[index].Credential.ID))
		}
		if len(keys) > 0 {
			concurrencySnapshot, err := s.loadConcurrencySnapshot(ctx, keys)
			if err != nil {
				return nil, err
			}
			for position, index := range missingIndexes {
				concurrencyHints[index] = concurrencySnapshot[keys[position]] + 1
			}
		}
		for position := range length {
			index := position
			if indexes != nil {
				index = indexes[position]
			}
			inFlight[position] = concurrencyHints[index] - 1
		}
	}

	s.configMu.RLock()
	jitterRatio := s.selectionJitterRatio
	jitterSalt := s.selectionJitterSalt
	cliSelectEnabled := s.cliSelect.Enabled
	cliCallCountWeight := s.cliSelect.CallCountWeight
	s.configMu.RUnlock()
	if jitterSalt == "" {
		// Request-level random salt: concurrent requests see different jitter
		// orderings and spread across accounts instead of all hitting the same
		// heap-top account (which triggers upstream per-SSO rate limits).
		jitterSalt = strconv.FormatUint(rand.Uint64(), 36)
	}
	s.selectionMu.RLock()
	scores := make([]candidateScore, length)
	for position := range length {
		index := position
		if indexes != nil {
			index = indexes[position]
		}
		candidate := values[index]
		score := candidateScore{
			index: index, tier: tierOrderRank(tierOrder, candidate.Credential.WebTier),
			preferFreeBuild: preferFreeBuild && candidate.IsKnownFreeBuild(),
			inFlight:        inFlight[position], lastSelected: s.lastSelectedAt[candidate.Credential.ID],
		}
		if cliSelectEnabled && candidate.Credential.Provider == account.ProviderBuild {
			class := classifyCLICandidate(candidate, now, false)
			score.cliLayer = int(class.Layer)
			score.eligibilityRank = account.EligibilityRank(class.Eligibility)
			score.callCount = candidate.ProfileOrEmpty().CallCount
			_ = cliCallCountWeight
		}
		if jitterRatio > 0 {
			score.jitter = selectionJitter(candidate.Credential.ID, jitterSalt)
		}
		if candidate.Billing != nil {
			score.remaining = candidate.Billing.Remaining()
			score.billingFresh = now.Sub(candidate.Billing.SyncedAt) <= 30*time.Minute
		}
		scores[position] = score
	}
	s.selectionMu.RUnlock()
	plan := &candidatePlan{values: values, scores: scores, jitterRatio: jitterRatio}
	heap.Init(plan)
	return plan, nil
}

// loadConcurrencySnapshot 在极短窗口内合并相同候选池的并发快照读取。
// 快照只参与排序，最终容量仍由原子 Acquire 校验，因此陈旧快照不会突破账号并发上限。
func (s *Selector) loadConcurrencySnapshot(ctx context.Context, keys []string) (map[string]int, error) {
	cacheKey := concurrencySnapshotKey(keys)
	load := func() (map[string]int, error) {
		values := make(map[string]int, len(keys))
		if batchReader, ok := s.concurrency.(repository.ConcurrencySnapshotReader); ok {
			var err error
			values, err = batchReader.CurrentMany(ctx, keys)
			if err != nil {
				return nil, fmt.Errorf("批量读取账号并发租约: %w", err)
			}
		} else {
			for _, key := range keys {
				current, err := s.concurrency.Current(ctx, key)
				if err != nil {
					return nil, fmt.Errorf("读取账号并发租约: %w", err)
				}
				values[key] = current
			}
		}
		return values, nil
	}
	// 仅测试中的手工 Selector 可能没有初始化缓存，保持最小兼容回退。
	if s.concurrencySnapshots == nil {
		return load()
	}
	return s.concurrencySnapshots.Load(ctx, cacheKey, time.Now(), load)
}

func concurrencySnapshotKey(keys []string) [32]byte {
	hash := sha256.New()
	separator := []byte{0}
	for _, key := range keys {
		_, _ = hash.Write([]byte(key))
		_, _ = hash.Write(separator)
	}
	var result [32]byte
	copy(result[:], hash.Sum(nil))
	return result
}

func accountConcurrencyKey(accountID uint64) string {
	return repository.AccountConcurrencyKey(accountID)
}
