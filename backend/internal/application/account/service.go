package account

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	egressapp "github.com/chenyme/grok2api/backend/internal/application/egress"
	accountdomain "github.com/chenyme/grok2api/backend/internal/domain/account"
	"github.com/chenyme/grok2api/backend/internal/infra/config"
	"github.com/chenyme/grok2api/backend/internal/infra/provider"
	webprovider "github.com/chenyme/grok2api/backend/internal/infra/provider/web"
	"github.com/chenyme/grok2api/backend/internal/infra/security"
	"github.com/chenyme/grok2api/backend/internal/pkg/batch"
	"github.com/chenyme/grok2api/backend/internal/pkg/perfmetrics"
	"github.com/chenyme/grok2api/backend/internal/pkg/resultcache"
	"github.com/chenyme/grok2api/backend/internal/repository"
	"golang.org/x/sync/singleflight"
)

var (
	ErrDevicePending  = errors.New("Device OAuth 等待用户授权")
	ErrDeviceSlowDown = errors.New("Device OAuth 轮询过快")
	ErrDeviceDenied   = errors.New("Device OAuth 已拒绝或过期")
	ErrInvalidFilter  = errors.New("账号筛选条件无效")
	ErrInvalidInput   = errors.New("账号参数无效")
	ErrInvalidImport  = errors.New("账号凭据格式无效")
	ErrImportLimit    = errors.New("导入账号数量超过限制")
	ErrExportLimit    = errors.New("导出账号数量超过限制")
	ErrNotFound       = errors.New("账号不存在")
	ErrUnsupported    = errors.New("账号来源不支持该操作")
	ErrConversionBusy = errors.New("账号正在转换为 Grok Build")
	ErrConflict       = errors.New("账号操作存在冲突")
)

var ErrCredentialRefreshPermanent = errors.New("OAuth refresh token 已永久失效")
var errQuotaRefreshBusy = errors.New("额度同步已由其他实例执行")

const (
	estimatedFreeTokenLimit         int64         = 1_000_000
	freeUsageWindow                 time.Duration = 24 * time.Hour
	forcedRefreshMinInterval        time.Duration = 30 * time.Second
	paidProbeRetryInterval          time.Duration = 15 * time.Minute
	credentialRefreshAdvance        time.Duration = 3 * time.Minute
	credentialRefreshSafetyPoll     time.Duration = time.Minute
	credentialRefreshTimeout        time.Duration = 30 * time.Second
	credentialRefreshStateTTL       time.Duration = 5 * time.Second
	credentialStateWriteTimeout     time.Duration = 5 * time.Second
	credentialRefreshBatchSize                    = 100
	managedTaskWorkerCeiling                      = 50
	quotaRefreshQueueSize                         = 4096
	quotaRefreshTimeout                           = 30 * time.Second
	quotaRefreshDirtyTTL                          = 24 * time.Hour
	quotaRefreshPollInterval                      = 500 * time.Millisecond
	quotaRefreshSharedPoll                        = time.Second
	quotaRefreshBackoffBase                       = time.Second
	quotaRefreshBackoffMax                        = time.Minute
	consoleQuotaRefreshMinInterval                = 30 * time.Second
	unknownRemoteQuotaProbeDelay    time.Duration = 5 * time.Minute
	consolePredictedQuotaProbeDelay time.Duration = 24 * time.Hour
	observedModelPersistInterval                  = 30 * time.Minute
	observedModelLocalCacheTTL                    = 5 * time.Second
	observedModelLockShards                       = 64
	maxCredentialExportAccounts                   = 50000
	maxCredentialImportAccounts                   = 50000
	credentialImportChunkSize                     = 100
	maxQuotaResetAccounts                         = 10000
	quotaResetChunkSize                           = 500
	maxBuildConversionAccounts                    = 1000
	maxWebConsoleSyncAccounts                     = 1000
	accountTaskBatchSize                          = 1000
	buildBotFlagCacheTTL            time.Duration = 30 * time.Second
	linkedDeleteRuntimeCleanupLimit               = 3 * time.Second
)

const permanentRefreshExpiredReason = "OAuth refresh token 已永久失效且 access token 已过期"
const buildBotFlagCacheKey = "build-bot-flagged-account-ids"

type quotaRefreshState struct {
	generation          uint64
	publishedGeneration uint64
	sharedGeneration    uint64
	queued              bool
	running             bool
	pending             bool
	failures            int
	nextAttemptAt       time.Time
}

type observedModelState struct {
	model       string
	persistedAt time.Time
}

type observedModelShard struct {
	sync.Mutex
	values        map[uint64]observedModelState
	lastCleanupAt time.Time
}

type quotaRefreshRequest struct {
	key       string
	accountID uint64
	mode      string
}

type quotaRefreshResult struct {
	Credential accountdomain.Credential
	Windows    []accountdomain.QuotaWindow
}

type QuotaRefreshStats struct {
	Pending int
	Queued  int
	Running int
}

type QuotaType string
type QuotaStatus string

const (
	QuotaTypeUnknown        QuotaType   = "unknown"
	QuotaTypeFree           QuotaType   = "free"
	QuotaTypePaid           QuotaType   = "paid"
	QuotaStatusActive       QuotaStatus = "active"
	QuotaStatusWaitingReset QuotaStatus = "waitingReset"
	QuotaStatusProbing      QuotaStatus = "probing"
)

type QuotaView struct {
	Type            QuotaType
	Source          string
	Confidence      string
	Unit            string
	Used            float64
	Limit           float64
	Remaining       float64
	UsagePercent    float64
	LimitKnown      bool
	WindowHours     int
	Observed        bool
	Confirmed       bool
	Status          QuotaStatus
	PeriodStart     string
	PeriodEnd       string
	ExhaustedAt     *time.Time
	NextProbeAt     *time.Time
	LastConfirmedAt *time.Time
}

type View struct {
	Credential      accountdomain.Credential
	Billing         *accountdomain.Billing
	Quota           QuotaView
	QuotaWindows    []accountdomain.QuotaWindow
	BuildBotFlagged bool
	// CLI* are Build-only derived diagnostics (nil/empty for other providers).
	CLIProfile     *accountdomain.CLIProfile
	CLILayer       int
	CLIEligibility string
	CLIWarmBucket  string
}

// CLIWarmSnapshot is the last warm-worker inventory observation (process-local).
type CLIWarmSnapshot struct {
	ReadyTotal    int            `json:"readyTotal"`
	UnprovenReady int            `json:"unprovenReady"`
	UnprovenCap   int            `json:"unprovenCap"`
	Target        int            `json:"target"`
	ReadyByBucket map[string]int `json:"readyByBucket"`
	UpdatedAt     time.Time      `json:"updatedAt"`
}

type UpdateInput struct {
	Name                   *string
	Enabled                *bool
	Priority               *int
	MaxConcurrent          *int
	MinimumRemaining       *float64
	CloudflareCookies      *string
	ClearCloudflareCookies bool
	// BuildSuperEntitled 仅 grok_build 可设置；非 Build 返回业务错误。
	BuildSuperEntitled *bool
	// BuildRouteMode 仅 grok_build 可设置；nil 表示不修改。
	BuildRouteMode *accountdomain.BuildRouteMode
}

type CleanupStatus string

const (
	CleanupStatusCooldown       CleanupStatus = "cooldown"
	CleanupStatusDisabled       CleanupStatus = "disabled"
	CleanupStatusReauthRequired CleanupStatus = "reauthRequired"
)

type DeviceStartResult struct {
	SessionID               string
	UserCode                string
	VerificationURI         string
	VerificationURIComplete string
	Interval                time.Duration
	ExpiresAt               time.Time
}

type ImportResult struct {
	Created    int
	Updated    int
	Skipped    int
	AccountIDs []uint64
	// Console* filled when Web import auto-projects Console (ensure + ciphertext).
	ConsoleCreated int
	ConsoleUpdated int
	ConsoleFailed  int
	ConsoleSkipped int
}

// ImportWebOptions controls Web SSO import side-effects (Console projection, trusted mark).
// Zero value uses config defaults: AutoSyncConsole nil → import.webAutoSyncConsole; TrustedSource false.
type ImportWebOptions struct {
	// AutoSyncConsole overrides config when non-nil.
	AutoSyncConsole *bool
	// TrustedSource adds TagCLITrusted on imported Web accounts for Convert inheritance.
	TrustedSource bool
}

type BuildConversionStrategy string

const (
	BuildConversionAll     BuildConversionStrategy = "all"
	BuildConversionMissing BuildConversionStrategy = "missing"
)

type WebConsoleSyncStrategy string

const (
	WebConsoleSyncAll     WebConsoleSyncStrategy = "all"
	WebConsoleSyncMissing WebConsoleSyncStrategy = "missing"
)

type ImportedAccountObserver func(accountID uint64) error

// BatchProgressObserver 在单个账号任务结束后报告批次完成数。
type BatchProgressObserver func(completed, total int) error

type ExportResult struct {
	Data  []byte
	Count int
}

type ExportPageResult struct {
	ExportResult
	NextID        uint64
	SnapshotMaxID uint64
	HasMore       bool
}

type BuildConversionResult struct {
	Created         int
	Linked          int
	Skipped         int
	Failed          int
	BuildAccountIDs []uint64
	Failures        []BuildConversionFailure
}

type BuildConversionFailure struct {
	AccountID uint64
	Message   string
	Class     string
}

type ListFilter struct {
	Provider  string
	QuotaType string
	Status    string
	Egress    string
	Renewal   string
	Risk      string
	// Agreement applies only to grok_web accounts.
	Agreement string
	// Association values are provider-specific: Web supports build, console, and combined filters;
	// Build and Console support only webLinked and webUnlinked.
	Association string
	// Build CLI list filters (provider must be grok_build when set).
	CLILayer     int // 0 = none; 1..5
	CLITrusted   *bool
	CLIMaybeDead *bool
	Sort         repository.SortQuery
}

type Summary struct {
	Total      int64
	Available  int64
	Recovering int64
	Attention  int64
	Risk       int64
	Providers  map[string]ProviderSummary
	Recovery   RecoverySummary
	Issues     IssueSummary
}

type ProviderSummary struct {
	Total     int64
	Available int64
}

type RecoverySummary struct {
	Cooldown     int64
	WaitingReset int64
	Probing      int64
}

type IssueSummary struct {
	Disabled       int64
	ReauthRequired int64
	// CLIMaybeDead: Build chat-banned (maybe_dead); still active for billing probe but unusable for chat.
	CLIMaybeDead int64
}

func (s *Service) Summary(ctx context.Context) (Summary, error) {
	rows, err := s.accounts.Summarize(ctx, s.now())
	if err != nil {
		return Summary{}, err
	}
	result := Summary{Providers: make(map[string]ProviderSummary, len(accountdomain.Providers()))}
	for _, providerValue := range accountdomain.Providers() {
		result.Providers[string(providerValue)] = ProviderSummary{}
	}
	for _, row := range rows {
		result.Total += row.Total
		result.Available += row.Available
		result.Recovery.Cooldown += row.Cooldown
		result.Recovery.WaitingReset += row.WaitingReset
		result.Recovery.Probing += row.Probing
		result.Issues.Disabled += row.Disabled
		result.Issues.ReauthRequired += row.ReauthRequired
		result.Issues.CLIMaybeDead += row.CLIMaybeDead
		result.Providers[row.Provider] = ProviderSummary{Total: row.Total, Available: row.Available}
	}
	result.Recovering = result.Recovery.Cooldown + result.Recovery.WaitingReset + result.Recovery.Probing
	// Attention = needs ops handling: disabled, reauth, and CLI chat bans (封号).
	result.Attention = result.Issues.Disabled + result.Issues.ReauthRequired + result.Issues.CLIMaybeDead
	flaggedIDs, err := s.buildBotFlaggedAccountIDs(ctx)
	if err != nil {
		return Summary{}, err
	}
	result.Risk = int64(len(flaggedIDs))
	return result, nil
}

// Service 负责 OAuth 账号接入、刷新、额度和持久化生命周期。
type Service struct {
	accounts                  repository.AccountRepository
	audits                    repository.AuditRepository
	deviceSessions            repository.DeviceSessionRepository
	sticky                    repository.StickySessionRepository
	refreshLock               repository.DistributedLock
	concurrency               repository.ConcurrencyLimiter
	quotaQueue                repository.QuotaRecoveryQueue
	quotaRefreshState         repository.QuotaRefreshCoordinator
	providers                 *provider.Registry
	cipher                    *security.Cipher
	refreshes                 singleflight.Group
	billingSyncs              singleflight.Group
	quotaSyncs                singleflight.Group
	identitySyncs             singleflight.Group
	observedModelWrites       singleflight.Group
	observedModelStore        repository.ObservedModelStateRepository
	modelRepo                 repository.ModelRepository
	refreshMu                 sync.Mutex
	lastRefreshAt             map[uint64]time.Time
	observedModelShards       [observedModelLockShards]observedModelShard
	quotaRefreshMu            sync.Mutex
	quotaRefreshes            map[string]*quotaRefreshState
	quotaRefreshQueue         chan quotaRefreshRequest
	quotaRefreshWake          chan struct{}
	conversionPool            *batch.Pool
	syncPool                  *batch.Pool
	refreshPool               *batch.Pool
	// detectPool 专用于管理端「检测账号」，与额度同步/续期隔离，默认并发 32。
	detectPool                *batch.Pool
	credentialRefreshWake     chan struct{}
	webAutoSyncConsole        bool
	cliWarmMu                 sync.RWMutex
	cliWarm                   config.CLIRoutingConfig
	cliWarmWake               chan struct{}
	cliConvertWake            chan struct{}
	cliConvertQueue           chan uint64
	cliConvertInflight        chan struct{}
	cliConvertStarts          []time.Time // sliding 1m window for MaxConvertPerMinute
	cliExploreStarts          []time.Time // sliding 1m window for ExploreMaxPerMinute
	cliBillingCatchupInflight sync.Map    // build accountID -> struct{} while billing catchup runs
	cliSSOLocks               sync.Map    // webAccountID -> *sync.Mutex
	cliWarmSnapshot           CLIWarmSnapshot
	cliWarmLastTickAt         time.Time // last full warm tick (coalesce wake storms)
	cliWarmLastWakeAt         time.Time // last WakeCLIWarm emit
	cliWarmLastStatusLog      time.Time
	cliWarmLastStatusSig      string
	autoRefreshLogAt          time.Time // rate-limit identical credential_auto_refresh batch logs
	autoRefreshLogSig         string
	autoCleanMu               sync.RWMutex
	autoClean                 AutoCleanConfig
	autoCleanRevision         uint64
	autoCleanWake             chan struct{}
	buildBotFlagCache         *resultcache.Cache[string, []uint64]
	// identityMetaWriter optionally coalesces UpdateIdentityMetadata (writequeue).
	identityMetaWriter identityMetadataWriter
	logger             *slog.Logger
	now                func() time.Time
}

func (s *Service) SetQuotaRecoveryQueue(queue repository.QuotaRecoveryQueue) {
	s.quotaQueue = queue
}

func (s *Service) SetQuotaRefreshCoordinator(value repository.QuotaRefreshCoordinator) {
	s.quotaRefreshState = value
}

func (s *Service) QuotaRefreshStats() QuotaRefreshStats {
	s.quotaRefreshMu.Lock()
	defer s.quotaRefreshMu.Unlock()
	result := QuotaRefreshStats{}
	for _, state := range s.quotaRefreshes {
		if state == nil {
			continue
		}
		if state.pending || state.queued || state.running {
			result.Pending++
		}
		if state.queued {
			result.Queued++
		}
		if state.running {
			result.Running++
		}
	}
	return result
}

// SetConcurrencyLimiter 让账号维护任务读取与推理路由相同的活动租约。
func (s *Service) SetConcurrencyLimiter(value repository.ConcurrencyLimiter) {
	s.concurrency = value
}

// SetObservedModelStore enables best-effort cross-instance duplicate suppression.
func (s *Service) SetObservedModelStore(value repository.ObservedModelStateRepository) {
	s.observedModelStore = value
}

// SetModelRepository enables preloaded model capability writes during
// SSO→Build conversion (§16 enrichment data reuse). When set,
// persistSeed writes seed.PreloadedModels to the model capability store,
// avoiding a redundant upstream /v1/models round-trip after conversion.
func (s *Service) SetModelRepository(value repository.ModelRepository) {
	s.modelRepo = value
}

func NewService(accounts repository.AccountRepository, audits repository.AuditRepository, deviceSessions repository.DeviceSessionRepository, sticky repository.StickySessionRepository, providers *provider.Registry, cipher *security.Cipher, refreshLock repository.DistributedLock) *Service {
	return &Service{
		accounts: accounts, audits: audits, deviceSessions: deviceSessions, sticky: sticky,
		providers: providers, cipher: cipher, refreshLock: refreshLock,
		lastRefreshAt: make(map[uint64]time.Time), quotaRefreshes: make(map[string]*quotaRefreshState),
		quotaRefreshQueue:     make(chan quotaRefreshRequest, quotaRefreshQueueSize),
		quotaRefreshWake:      make(chan struct{}, 1),
		credentialRefreshWake: make(chan struct{}, 1),
		cliWarm:               config.DefaultCLIRoutingConfig(),
		cliWarmWake:           make(chan struct{}, 1),
		cliConvertWake:        make(chan struct{}, 1),
		cliConvertQueue:       make(chan uint64, 256),
		autoClean: AutoCleanConfig{
			Enabled: false, Interval: 10 * time.Minute, MinAge: time.Hour, IncludeDisabled: false,
		},
		autoCleanWake:     make(chan struct{}, 1),
		buildBotFlagCache: resultcache.New[string, []uint64](1, buildBotFlagCacheTTL),
		conversionPool:    batch.NewPool(25), syncPool: batch.NewPool(25), refreshPool: batch.NewPool(25), logger: slog.Default(),
		now: func() time.Time { return time.Now().UTC() },
	}
}

func (s *Service) SetBulkPool(pool *batch.Pool) {
	if pool != nil {
		s.conversionPool, s.syncPool, s.refreshPool = pool, pool, pool
	}
}

// SetTaskPools 为转换、同步和凭据刷新绑定独立分类并发池。
func (s *Service) SetTaskPools(conversion, syncPool, refresh *batch.Pool) {
	if conversion != nil {
		s.conversionPool = conversion
	}
	if syncPool != nil {
		s.syncPool = syncPool
	}
	if refresh != nil {
		s.refreshPool = refresh
	}
}

func (s *Service) SetLogger(logger *slog.Logger) {
	if logger != nil {
		s.logger = logger
	}
}

// SetCLIRouting updates Build CLI warm-pool / layering policy (hot-reload safe).
func (s *Service) SetCLIRouting(cfg config.CLIRoutingConfig) {
	s.cliWarmMu.Lock()
	s.cliWarm = cfg
	limit := cfg.MaxConvertInflight
	if limit < 1 {
		limit = 1
	}
	if limit > 32 {
		limit = 32
	}
	s.cliConvertInflight = make(chan struct{}, limit)
	s.cliWarmMu.Unlock()
	s.WakeCLIWarm()
}

// SetImportConfig updates Web import defaults (auto Console projection).
func (s *Service) SetImportConfig(webAutoSyncConsole bool) {
	s.cliWarmMu.Lock()
	s.webAutoSyncConsole = webAutoSyncConsole
	s.cliWarmMu.Unlock()
}

// SetIdentityMetadataWriter routes identity column updates through an optional write queue.
// Nil restores direct repository writes. Auth rejection paths never use this writer.
func (s *Service) SetIdentityMetadataWriter(writer identityMetadataWriter) {
	if s == nil {
		return
	}
	s.cliWarmMu.Lock()
	s.identityMetaWriter = writer
	s.cliWarmMu.Unlock()
}

func (s *Service) importAutoSyncConsole() bool {
	s.cliWarmMu.RLock()
	defer s.cliWarmMu.RUnlock()
	return s.webAutoSyncConsole
}

func (s *Service) cliRouting() config.CLIRoutingConfig {
	s.cliWarmMu.RLock()
	defer s.cliWarmMu.RUnlock()
	return s.cliWarm
}

// WakeCLIWarm merges warm-worker wake signals without blocking callers.
// Emissions within cliWarmWakeMinInterval are coalesced; RunCLIWarm still ticks on its timer
// and convert work still uses cliConvertWake for queue drain.
func (s *Service) WakeCLIWarm() {
	now := s.now()
	s.cliWarmMu.Lock()
	if !s.cliWarmLastWakeAt.IsZero() && now.Sub(s.cliWarmLastWakeAt) < cliWarmWakeMinInterval {
		s.cliWarmMu.Unlock()
		return
	}
	s.cliWarmLastWakeAt = now
	s.cliWarmMu.Unlock()
	select {
	case s.cliWarmWake <- struct{}{}:
	default:
	}
}

// GetCLIWarmSnapshot returns the latest warm inventory observation.
func (s *Service) GetCLIWarmSnapshot() CLIWarmSnapshot {
	s.cliWarmMu.RLock()
	defer s.cliWarmMu.RUnlock()
	out := s.cliWarmSnapshot
	cp := make(map[string]int, len(out.ReadyByBucket))
	for k, v := range out.ReadyByBucket {
		cp[k] = v
	}
	out.ReadyByBucket = cp
	if out.UpdatedAt.IsZero() {
		// Keep JSON decoder friendly for clients that require updatedAt string.
		out.UpdatedAt = time.Unix(0, 0).UTC()
	}
	return out
}

// EnqueueBuildCLIConvert queues a Build account for linked-Web SSO convert (async).
func (s *Service) EnqueueBuildCLIConvert(buildAccountID uint64) {
	if buildAccountID == 0 {
		return
	}
	select {
	case s.cliConvertQueue <- buildAccountID:
	default:
		// queue full: warm tick will rescan RT-dead material
	}
	select {
	case s.cliConvertWake <- struct{}{}:
	default:
	}
	s.WakeCLIWarm()
}

// ProviderDefinition 向账号同步编排层暴露只读生命周期策略，不泄露具体 Adapter。
func (s *Service) ProviderDefinition(value accountdomain.Provider) (provider.Definition, bool) {
	if s.providers == nil {
		return provider.Definition{}, false
	}
	return s.providers.Definition(value)
}

// AccountSnapshot is a provider-scoped admin list payload for client-side paging.
type AccountSnapshot struct {
	Items       []View
	Total       int64
	Revision    int64
	Provider    string
	GeneratedAt time.Time
}

// AccountChanges is a cheap revision probe; FullResync asks the client to reload snapshot.
type AccountChanges struct {
	Revision   int64
	FullResync bool
}

type accountDomainRevisionRepository interface {
	AccountDomainRevision(ctx context.Context) (int64, error)
	BumpAccountDomainRevision(ctx context.Context) (int64, error)
}

func (s *Service) List(ctx context.Context, page, pageSize int, search string, filter ListFilter) ([]View, int64, error) {
	page, pageSize = normalizePage(page, pageSize)
	// CLI layer must match ClassifyCLI badges (JWT bot → L5). SQL layer predicates only see maybe_dead,
	// so layer filters page via full Snapshot then slice (admin FE already uses Snapshot).
	if filter.CLILayer != 0 {
		snap, err := s.Snapshot(ctx, search, filter)
		if err != nil {
			return nil, 0, err
		}
		total := int64(len(snap.Items))
		start := (page - 1) * pageSize
		if start >= len(snap.Items) {
			return []View{}, total, nil
		}
		end := start + pageSize
		if end > len(snap.Items) {
			end = len(snap.Items)
		}
		return snap.Items[start:end], total, nil
	}
	if (filter.Provider != "" && !accountdomain.Provider(filter.Provider).IsValid()) ||
		!oneOf(filter.QuotaType, "", "free", "paid", "unknown", "auto", "basic", "super", "heavy") ||
		!oneOf(filter.Status, "", "active", "disabled", "reauthRequired", "cooldown", "waitingReset", "probing") ||
		!oneOf(filter.Egress, "", "bound", "unbound") ||
		!oneOf(filter.Renewal, "", "refreshable", "unrefreshable") ||
		!oneOf(filter.Risk, "", "flagged", "normal") ||
		(filter.Risk != "" && filter.Provider != string(accountdomain.ProviderBuild)) ||
		!oneOf(filter.Agreement, "", "nsfwEnabled", "nsfwDisabled", "termsAccepted", "termsNotAccepted", "allAccepted", "allNotAccepted") ||
		(filter.Agreement != "" && filter.Provider != string(accountdomain.ProviderWeb)) ||
		!validAssociationFilter(filter.Provider, filter.Association) ||
		!repository.IsValidSort(filter.Sort, "name", "type", "status", "createdAt") {
		return nil, 0, ErrInvalidFilter
	}
	var refreshable *bool
	if filter.Renewal != "" {
		value := filter.Renewal == "refreshable"
		refreshable = &value
	}
	repositoryFilter := repository.AccountListFilter{
		Provider: filter.Provider, QuotaType: filter.QuotaType, Status: filter.Status, Egress: filter.Egress,
		Refreshable: refreshable, Agreement: filter.Agreement, Association: filter.Association, Now: s.now(),
	}
	if filter.Risk != "" {
		flaggedIDs, err := s.buildBotFlaggedAccountIDs(ctx)
		if err != nil {
			return nil, 0, err
		}
		if filter.Risk == "flagged" {
			repositoryFilter.AccountIDs = flaggedIDs
			repositoryFilter.RestrictIDs = true
		} else {
			repositoryFilter.ExcludeIDs = flaggedIDs
		}
	}
	values, total, err := s.accounts.List(ctx, repository.AccountListQuery{
		Page:   repository.PageQuery{Offset: (page - 1) * pageSize, Limit: pageSize, Search: search, Sort: filter.Sort},
		Filter: repositoryFilter,
	})
	if err != nil {
		return nil, 0, err
	}
	accountIDs := make([]uint64, 0, len(values))
	for _, value := range values {
		accountIDs = append(accountIDs, value.ID)
	}
	observedTokens, err := s.audits.SumTokensByAccountsSince(ctx, accountIDs, time.Now().UTC().Add(-freeUsageWindow))
	if err != nil {
		return nil, 0, err
	}
	billings, err := s.accounts.GetBillings(ctx, accountIDs)
	if err != nil {
		return nil, 0, err
	}
	recoveries, err := s.accounts.GetQuotaRecoveries(ctx, accountIDs)
	if err != nil {
		return nil, 0, err
	}
	quotaWindows, err := s.accounts.GetQuotaWindows(ctx, accountIDs)
	if err != nil {
		return nil, 0, err
	}
	views := make([]View, 0, len(values))
	for _, value := range values {
		metadata := s.credentialMetadata(value)
		view := View{Credential: value, BuildBotFlagged: metadata.BuildBotFlagged}
		if billing, ok := billings[value.ID]; ok {
			view.Billing = &billing
		}
		var recovery *accountdomain.QuotaRecovery
		if recoveryValue, ok := recoveries[value.ID]; ok {
			recovery = &recoveryValue
		}
		view.Quota = newQuotaView(view.Billing, observedTokens[value.ID], recovery, value.ObservedModel, value.BuildSuperEntitled && value.Provider == accountdomain.ProviderBuild)
		view.QuotaWindows = quotaWindows[value.ID]
		views = append(views, view)
	}
	return views, total, nil
}

func (s *Service) Snapshot(ctx context.Context, search string, filter ListFilter) (AccountSnapshot, error) {
	if filter.Provider == "" || !accountdomain.Provider(filter.Provider).IsValid() {
		return AccountSnapshot{}, ErrInvalidFilter
	}
	repositoryFilter, err := s.accountListRepositoryFilter(ctx, filter)
	if err != nil {
		return AccountSnapshot{}, err
	}
	// ClassifyCLI is SSOT for layer badges (includes JWT bot). SQL layer filter only uses maybe_dead
	// and diverges → UI looks unfiltered / mixed layers. Drop SQL layer; post-filter after enrich.
	repositoryFilter.CLILayer = 0
	const pageSize = repository.MaxPageSize
	views := make([]View, 0, pageSize)
	var total int64
	for page := 1; ; page++ {
		values, pageTotal, listErr := s.accounts.List(ctx, repository.AccountListQuery{
			Page:   repository.PageQuery{Offset: (page - 1) * pageSize, Limit: pageSize, Search: search, Sort: filter.Sort},
			Filter: repositoryFilter,
		})
		if listErr != nil {
			return AccountSnapshot{}, listErr
		}
		if page == 1 {
			total = pageTotal
		}
		batch, enrichErr := s.enrichAccountViews(ctx, values, filter.Provider)
		if enrichErr != nil {
			return AccountSnapshot{}, enrichErr
		}
		views = append(views, batch...)
		if len(values) < pageSize || int64(len(views)) >= total {
			break
		}
	}
	views = applyCLIViewFilters(views, filter)
	total = int64(len(views))
	revision, _ := s.accountDomainRevision(ctx)
	return AccountSnapshot{
		Items: views, Total: total, Revision: revision,
		Provider: filter.Provider, GeneratedAt: s.now(),
	}, nil
}

// applyCLIViewFilters keeps rows matching ClassifyCLI-derived CLI fields shown in the admin UI.
func applyCLIViewFilters(views []View, filter ListFilter) []View {
	if filter.CLILayer == 0 && filter.CLITrusted == nil && filter.CLIMaybeDead == nil {
		return views
	}
	out := make([]View, 0, len(views))
	for _, view := range views {
		if filter.CLILayer != 0 && view.CLILayer != filter.CLILayer {
			continue
		}
		if filter.CLITrusted != nil {
			trusted := view.CLIProfile != nil && view.CLIProfile.TrustedSource
			if trusted != *filter.CLITrusted {
				continue
			}
		}
		if filter.CLIMaybeDead != nil {
			dead := view.CLIProfile != nil && view.CLIProfile.MaybeDead
			if dead != *filter.CLIMaybeDead {
				continue
			}
		}
		out = append(out, view)
	}
	return out
}

// Changes reports whether the account domain advanced past since. V1 always asks for full resync
// when revision moved (no per-row change log yet).
func (s *Service) Changes(ctx context.Context, since int64) (AccountChanges, error) {
	revision, err := s.accountDomainRevision(ctx)
	if err != nil {
		return AccountChanges{}, err
	}
	if since < 0 {
		since = 0
	}
	if revision <= since {
		return AccountChanges{Revision: revision, FullResync: false}, nil
	}
	return AccountChanges{Revision: revision, FullResync: true}, nil
}

func (s *Service) accountDomainRevision(ctx context.Context) (int64, error) {
	repo, ok := s.accounts.(accountDomainRevisionRepository)
	if !ok {
		return 0, nil
	}
	return repo.AccountDomainRevision(ctx)
}

func (s *Service) bumpAccountDomainRevision(ctx context.Context) {
	repo, ok := s.accounts.(accountDomainRevisionRepository)
	if !ok {
		return
	}
	if _, err := repo.BumpAccountDomainRevision(ctx); err != nil {
		s.logger.Warn("account_domain_revision_bump_failed", "error", err)
	}
}

func (s *Service) accountListRepositoryFilter(ctx context.Context, filter ListFilter) (repository.AccountListFilter, error) {
	cliFilterActive := filter.CLILayer != 0 || filter.CLITrusted != nil || filter.CLIMaybeDead != nil
	if (filter.Provider != "" && !accountdomain.Provider(filter.Provider).IsValid()) ||
		!oneOf(filter.QuotaType, "", "free", "paid", "unknown", "auto", "basic", "super", "heavy") ||
		!oneOf(filter.Status, "", "active", "disabled", "reauthRequired", "cooldown", "waitingReset", "probing") ||
		!oneOf(filter.Renewal, "", "refreshable", "unrefreshable") ||
		!oneOf(filter.Risk, "", "flagged", "normal") ||
		(filter.Risk != "" && filter.Provider != string(accountdomain.ProviderBuild)) ||
		(cliFilterActive && filter.Provider != string(accountdomain.ProviderBuild)) ||
		(filter.CLILayer != 0 && (filter.CLILayer < 1 || filter.CLILayer > 5)) ||
		!repository.IsValidSort(filter.Sort, "name", "type", "status", "createdAt") {
		return repository.AccountListFilter{}, ErrInvalidFilter
	}
	var refreshable *bool
	if filter.Renewal != "" {
		value := filter.Renewal == "refreshable"
		refreshable = &value
	}
	repositoryFilter := repository.AccountListFilter{
		Provider: filter.Provider, QuotaType: filter.QuotaType, Status: filter.Status, Refreshable: refreshable, Now: s.now(),
		CLILayer: filter.CLILayer, CLITrusted: filter.CLITrusted, CLIMaybeDead: filter.CLIMaybeDead,
	}
	if filter.Risk != "" {
		flaggedIDs, err := s.buildBotFlaggedAccountIDs(ctx)
		if err != nil {
			return repository.AccountListFilter{}, err
		}
		if filter.Risk == "flagged" {
			repositoryFilter.AccountIDs = flaggedIDs
			repositoryFilter.RestrictIDs = true
		} else {
			repositoryFilter.ExcludeIDs = flaggedIDs
		}
	}
	return repositoryFilter, nil
}

func (s *Service) enrichAccountViews(ctx context.Context, values []accountdomain.Credential, providerFilter string) ([]View, error) {
	if len(values) == 0 {
		return []View{}, nil
	}
	accountIDs := make([]uint64, 0, len(values))
	for _, value := range values {
		accountIDs = append(accountIDs, value.ID)
	}
	observedTokens, err := s.audits.SumTokensByAccountsSince(ctx, accountIDs, time.Now().UTC().Add(-freeUsageWindow))
	if err != nil {
		return nil, err
	}
	billings, err := s.accounts.GetBillings(ctx, accountIDs)
	if err != nil {
		return nil, err
	}
	recoveries, err := s.accounts.GetQuotaRecoveries(ctx, accountIDs)
	if err != nil {
		return nil, err
	}
	quotaWindows, err := s.accounts.GetQuotaWindows(ctx, accountIDs)
	if err != nil {
		return nil, err
	}
	cliProfiles := map[uint64]accountdomain.CLIProfile{}
	if providerFilter == string(accountdomain.ProviderBuild) || providerFilter == "" {
		buildIDs := make([]uint64, 0, len(values))
		for _, value := range values {
			if value.Provider == accountdomain.ProviderBuild {
				buildIDs = append(buildIDs, value.ID)
			}
		}
		if len(buildIDs) > 0 {
			cliProfiles, err = s.accounts.GetBuildCLIProfiles(ctx, buildIDs)
			if err != nil {
				return nil, err
			}
		}
	}
	now := s.now()
	views := make([]View, 0, len(values))
	for _, value := range values {
		metadata := s.credentialMetadata(value)
		view := View{Credential: value, BuildBotFlagged: metadata.BuildBotFlagged}
		if billing, ok := billings[value.ID]; ok {
			view.Billing = &billing
		}
		var recovery *accountdomain.QuotaRecovery
		if recoveryValue, ok := recoveries[value.ID]; ok {
			recovery = &recoveryValue
		}
		view.Quota = newQuotaView(view.Billing, observedTokens[value.ID], recovery, value.ObservedModel, value.BuildSuperEntitled && value.Provider == accountdomain.ProviderBuild)
		view.QuotaWindows = quotaWindows[value.ID]
		if value.Provider == accountdomain.ProviderBuild {
			profile := cliProfiles[value.ID]
			profile.AccountID = value.ID
			view.CLIProfile = &profile
			class := accountdomain.ClassifyCLI(accountdomain.CLIClassifyInput{
				Credential: value, Billing: view.Billing, Profile: profile, Now: now, BotFlagged: view.BuildBotFlagged,
			})
			view.CLILayer = int(class.Layer)
			view.CLIEligibility = string(class.Eligibility)
			view.CLIWarmBucket = string(class.WarmBucket)
		}
		views = append(views, view)
	}
	return views, nil
}

func (s *Service) buildBotFlaggedAccountIDs(ctx context.Context) ([]uint64, error) {
	if s.buildBotFlagCache == nil {
		return s.loadBuildBotFlaggedAccountIDs(ctx)
	}
	return s.buildBotFlagCache.Load(ctx, buildBotFlagCacheKey, s.now(), func() ([]uint64, error) {
		return s.loadBuildBotFlaggedAccountIDs(ctx)
	})
}

func (s *Service) loadBuildBotFlaggedAccountIDs(ctx context.Context) ([]uint64, error) {
	const batchSize = 500
	result := make([]uint64, 0)
	var afterID uint64
	for {
		values, _, err := s.accounts.ListProviderAccountBatch(ctx, accountdomain.ProviderBuild, afterID, batchSize)
		if err != nil {
			return nil, err
		}
		for _, value := range values {
			if s.credentialMetadata(value).BuildBotFlagged {
				result = append(result, value.ID)
			}
		}
		if len(values) < batchSize {
			return result, nil
		}
		afterID = values[len(values)-1].ID
	}
}

func (s *Service) invalidateBuildBotFlagCache() {
	if s.buildBotFlagCache != nil {
		s.buildBotFlagCache.Delete(buildBotFlagCacheKey)
	}
}

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

// validAssociationFilter validates association filters against the selected provider.
// Web keeps its six Build/Console/combined values; Build and Console filter only by Web links.
func validAssociationFilter(providerValue, association string) bool {
	if association == "" {
		return true
	}
	switch providerValue {
	case string(accountdomain.ProviderWeb):
		return oneOf(association, "buildLinked", "buildUnlinked", "consoleLinked", "consoleUnlinked", "allLinked", "allUnlinked")
	case string(accountdomain.ProviderBuild), string(accountdomain.ProviderConsole):
		return oneOf(association, "webLinked", "webUnlinked")
	default:
		return false
	}
}

// BatchUpdate 对一组账号应用同一组路由参数，单次最多处理一个管理端最大分页。
func (s *Service) BatchUpdate(ctx context.Context, ids []uint64, input UpdateInput) (int64, error) {
	ids, err := normalizeBatchIDs(ids)
	if err != nil {
		return 0, err
	}
	if input.MaxConcurrent != nil && (*input.MaxConcurrent < 1 || *input.MaxConcurrent > accountdomain.MaxConcurrent) {
		return 0, invalidInput("maxConcurrent 必须在 1 到 256 之间")
	}
	if input.MinimumRemaining != nil && *input.MinimumRemaining < 0 {
		return 0, invalidInput("minimumRemaining 不能小于零")
	}
	if input.Name != nil {
		return 0, invalidInput("批量更新不支持修改账号名称")
	}
	updated, err := s.accounts.UpdateMany(ctx, ids, repository.AccountUpdates{Enabled: input.Enabled, Priority: input.Priority, MaxConcurrent: input.MaxConcurrent, MinimumRemaining: input.MinimumRemaining})
	if err != nil {
		return 0, err
	}
	if input.Enabled != nil && !*input.Enabled {
		for _, id := range ids {
			_ = s.sticky.DeleteByAccount(ctx, id)
		}
	}
	if updated > 0 {
		s.bumpAccountDomainRevision(ctx)
	}
	return updated, nil
}

// AccountDeleteResult summarizes a single/batch delete with optional linked peers.
type AccountDeleteResult struct {
	Deleted           int64
	RootsDeleted      int64
	LinkedDeleted     int64
	Skipped           int64
	DeletedByProvider map[accountdomain.Provider]int64
}

// accountDeleteResultFromOutcome converts repository results using rows actually deleted.
func accountDeleteResultFromOutcome(providerValue accountdomain.Provider, outcome repository.LinkedDeleteOutcome) AccountDeleteResult {
	out := AccountDeleteResult{
		Deleted:           outcome.Deleted,
		RootsDeleted:      outcome.RootsDeleted,
		LinkedDeleted:     outcome.Deleted - outcome.RootsDeleted,
		Skipped:           int64(len(outcome.SkippedRoots)),
		DeletedByProvider: map[accountdomain.Provider]int64{},
	}
	if providerValue.IsValid() && outcome.RootsDeleted > 0 {
		out.DeletedByProvider[providerValue] = outcome.RootsDeleted
	}
	for provider, count := range outcome.LinkedDeletedByProvider {
		out.DeletedByProvider[provider] += count
	}
	return out
}

// deleteStickyAccounts uses the optional batch capability and falls back for custom stores.
func (s *Service) deleteStickyAccounts(ctx context.Context, accountIDs []uint64) (int, error) {
	if s.sticky == nil || len(accountIDs) == 0 {
		return 0, nil
	}
	if batchDeleter, ok := s.sticky.(repository.StickySessionBatchDeleter); ok {
		if err := batchDeleter.DeleteByAccounts(ctx, accountIDs); err != nil {
			return len(accountIDs), err
		}
		return 0, nil
	}
	failures := 0
	var firstErr error
	for _, id := range accountIDs {
		if err := s.sticky.DeleteByAccount(ctx, id); err != nil {
			failures++
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return failures, firstErr
}

// finishLinkedDelete clears runtime state after the database transaction commits.
func (s *Service) finishLinkedDelete(ctx context.Context, deletedIDs []uint64) {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), linkedDeleteRuntimeCleanupLimit)
	defer cancel()
	if failures, err := s.deleteStickyAccounts(cleanupCtx, deletedIDs); err != nil && s.logger != nil {
		s.logger.Warn("linked_account_runtime_cleanup_failed", "accounts", len(deletedIDs), "failures", failures, "error", err)
	}
	for _, id := range deletedIDs {
		s.clearRefreshState(id)
	}
}

// BatchDelete atomically removes roots and quota state without expanding linked accounts.
func (s *Service) BatchDelete(ctx context.Context, ids []uint64) (int64, error) {
	result, err := s.batchDeleteWithLinkedMode(ctx, accountdomain.Provider(""), ids, nil, true)
	return result.Deleted, err
}

// BatchDeleteWithLinked deletes root accounts and optional linked peers resolved from binding tables.
// Roots with active video jobs are skipped together with their linked group; other groups are deleted.
func (s *Service) BatchDeleteWithLinked(ctx context.Context, providerValue accountdomain.Provider, ids []uint64, targets []accountdomain.Provider) (AccountDeleteResult, error) {
	return s.batchDeleteWithLinkedMode(ctx, providerValue, ids, targets, true)
}

// batchDeleteWithLinkedMode is the shared atomic path; skipMedia selects reject-all or skip-group behavior.
func (s *Service) batchDeleteWithLinkedMode(ctx context.Context, providerValue accountdomain.Provider, ids []uint64, targets []accountdomain.Provider, skipMedia bool) (AccountDeleteResult, error) {
	var out AccountDeleteResult
	ids, err := normalizeBatchIDs(ids)
	if err != nil {
		return out, err
	}
	if len(ids) == 0 {
		return out, nil
	}
	if len(targets) > 0 && !providerValue.IsValid() {
		return out, invalidInput("账号来源无效")
	}
	// Atomic path: lock roots → expand links → lock final → media handling → delete.
	outcome, err := s.accounts.DeleteManyWithLinked(ctx, providerValue, ids, targets, skipMedia)
	if err != nil {
		return out, mapLinkedDeleteError(err)
	}
	s.finishLinkedDelete(ctx, outcome.DeletedIDs)
	if outcome.Deleted > 0 {
		s.invalidateBuildBotFlagCache()
		s.bumpAccountDomainRevision(ctx)
	}
	return accountDeleteResultFromOutcome(providerValue, outcome), nil
}

// AccountsBelongToProvider 校验批量账号是否全部属于指定号池。
// 该校验只读取账号主表，避免详情页的额度、审计或关联查询影响批量操作。
func (s *Service) AccountsBelongToProvider(ctx context.Context, ids []uint64, providerValue accountdomain.Provider) (bool, error) {
	if !providerValue.IsValid() {
		return false, invalidInput("账号来源无效")
	}
	values, err := normalizeBatchIDs(ids)
	if err != nil {
		return false, err
	}
	count, err := s.accounts.CountProviderAccountsByIDs(ctx, providerValue, values)
	if err != nil {
		return false, err
	}
	return count == int64(len(values)), nil
}

// CleanupResult summarizes rows deleted and root groups skipped by one cleanup operation.
type CleanupResult struct {
	Deleted           int64
	RootsDeleted      int64
	LinkedDeleted     int64
	Skipped           int64
	DeletedByProvider map[accountdomain.Provider]int64
}

// validateCleanupSelection validates cleanup states and linked target providers.
func validateCleanupSelection(providerValue accountdomain.Provider, statuses []CleanupStatus, targets []accountdomain.Provider) (map[CleanupStatus]struct{}, error) {
	if !providerValue.IsValid() {
		return nil, invalidInput("账号来源无效")
	}
	selected := make(map[CleanupStatus]struct{}, len(statuses))
	for _, status := range statuses {
		switch status {
		case CleanupStatusCooldown, CleanupStatusDisabled, CleanupStatusReauthRequired:
			selected[status] = struct{}{}
		default:
			return nil, invalidInput("账号清理状态无效")
		}
	}
	if len(selected) == 0 {
		return nil, invalidInput("至少选择一种账号状态")
	}
	for _, target := range targets {
		if !target.IsValid() {
			return nil, invalidInput("关联删除目标无效")
		}
		if target == providerValue {
			return nil, invalidInput("关联删除目标不能包含当前号池")
		}
	}
	return selected, nil
}

// CleanupAccounts deletes accounts in selected admin states; healthy, waiting-reset, and probing accounts are excluded.
// Linked targets are resolved from binding tables regardless of peer state, and active-media groups are skipped whole.
// The ID cursor always advances, so skipped groups cannot stall a cleanup batch.
func (s *Service) CleanupAccounts(ctx context.Context, providerValue accountdomain.Provider, statuses []CleanupStatus, targets []accountdomain.Provider) (CleanupResult, error) {
	out := CleanupResult{DeletedByProvider: map[accountdomain.Provider]int64{}}
	selected, err := validateCleanupSelection(providerValue, statuses, targets)
	if err != nil {
		return out, err
	}

	const cleanupBatchSize = 500
	now := s.now()
	for _, status := range []CleanupStatus{CleanupStatusDisabled, CleanupStatusReauthRequired, CleanupStatusCooldown} {
		if _, ok := selected[status]; !ok {
			continue
		}
		var afterID uint64
		for {
			outcome, candidates, maxID, err := s.accounts.DeleteAccountStatusBatchWithLinked(ctx, providerValue, string(status), now, afterID, cleanupBatchSize, targets)
			if err != nil {
				return out, mapLinkedDeleteError(err)
			}
			s.finishLinkedDelete(ctx, outcome.DeletedIDs)
			out.Deleted += outcome.Deleted
			out.RootsDeleted += outcome.RootsDeleted
			out.LinkedDeleted += outcome.Deleted - outcome.RootsDeleted
			out.Skipped += int64(len(outcome.SkippedRoots))
			if outcome.RootsDeleted > 0 {
				out.DeletedByProvider[providerValue] += outcome.RootsDeleted
			}
			for provider, count := range outcome.LinkedDeletedByProvider {
				out.DeletedByProvider[provider] += count
			}
			if candidates < cleanupBatchSize {
				break
			}
			afterID = maxID
		}
	}
	if out.Deleted > 0 {
		s.invalidateBuildBotFlagCache()
		s.bumpAccountDomainRevision(ctx)
	}
	return out, nil
}

// PreviewCleanup returns root and linked-peer counts for the cleanup confirmation dialog.
// The preview is informational; deletion revalidates state inside each transaction.
func (s *Service) PreviewCleanup(ctx context.Context, providerValue accountdomain.Provider, statuses []CleanupStatus, targets []accountdomain.Provider) (repository.CleanupPreview, error) {
	selected, err := validateCleanupSelection(providerValue, statuses, targets)
	if err != nil {
		return repository.CleanupPreview{}, err
	}
	raw := make([]string, 0, len(selected))
	for _, status := range []CleanupStatus{CleanupStatusDisabled, CleanupStatusReauthRequired, CleanupStatusCooldown} {
		if _, ok := selected[status]; ok {
			raw = append(raw, string(status))
		}
	}
	preview, err := s.accounts.CountCleanupWithLinked(ctx, providerValue, raw, s.now(), targets)
	if err != nil {
		return repository.CleanupPreview{}, mapLinkedDeleteError(err)
	}
	return preview, nil
}

func (s *Service) Get(ctx context.Context, id uint64) (View, error) {
	value, err := s.accounts.Get(ctx, id)
	if err != nil {
		return View{}, mapRepositoryError(err)
	}
	metadata := s.credentialMetadata(value)
	view := View{Credential: value, BuildBotFlagged: metadata.BuildBotFlagged}
	if billing, err := s.accounts.GetBilling(ctx, id); err == nil {
		view.Billing = &billing
	} else if !errors.Is(err, repository.ErrNotFound) {
		return View{}, err
	}
	observedTokens, err := s.audits.SumTokensByAccountsSince(ctx, []uint64{id}, time.Now().UTC().Add(-freeUsageWindow))
	if err != nil {
		return View{}, err
	}
	var recovery *accountdomain.QuotaRecovery
	if recoveryValue, err := s.accounts.GetQuotaRecovery(ctx, id); err == nil {
		recovery = &recoveryValue
	} else if !errors.Is(err, repository.ErrNotFound) {
		return View{}, err
	}
	view.Quota = newQuotaView(view.Billing, observedTokens[id], recovery, value.ObservedModel, value.BuildSuperEntitled && value.Provider == accountdomain.ProviderBuild)
	if windows, err := s.accounts.GetQuotaWindows(ctx, []uint64{id}); err == nil {
		view.QuotaWindows = windows[id]
	} else {
		return View{}, err
	}
	if value.Provider == accountdomain.ProviderBuild {
		profiles, err := s.accounts.GetBuildCLIProfiles(ctx, []uint64{id})
		if err != nil {
			return View{}, err
		}
		profile := profiles[id]
		profile.AccountID = id
		view.CLIProfile = &profile
		class := accountdomain.ClassifyCLI(accountdomain.CLIClassifyInput{
			Credential: value, Billing: view.Billing, Profile: profile, Now: s.now(), BotFlagged: view.BuildBotFlagged,
		})
		view.CLILayer = int(class.Layer)
		view.CLIEligibility = string(class.Eligibility)
		view.CLIWarmBucket = string(class.WarmBucket)
	}
	return view, nil
}

func (s *Service) credentialMetadata(value accountdomain.Credential) provider.CredentialMetadata {
	if s.providers == nil {
		return provider.CredentialMetadata{}
	}
	return s.providers.CredentialMetadata(value)
}

func (s *Service) ObserveResponseModel(ctx context.Context, id uint64, model string) error {
	model = strings.TrimSpace(model)
	if model == "" {
		return nil
	}
	_, err, _ := s.observedModelWrites.Do(strconv.FormatUint(id, 10)+"\x00"+model, func() (any, error) {
		now := s.now()
		shard := s.observedModelShard(id)
		shard.Lock()
		if shard.values == nil {
			shard.values = make(map[uint64]observedModelState)
		}
		if shard.lastCleanupAt.IsZero() || now.Sub(shard.lastCleanupAt) >= observedModelPersistInterval {
			for accountID, state := range shard.values {
				if now.Sub(state.persistedAt) >= observedModelPersistInterval {
					delete(shard.values, accountID)
				}
			}
			shard.lastCleanupAt = now
		}
		state, exists := shard.values[id]
		localFresh := exists && state.model == model && observedModelStateIsFresh(now, state.persistedAt)
		if localFresh && (s.observedModelStore == nil || now.Sub(state.persistedAt) < observedModelLocalCacheTTL) {
			shard.Unlock()
			return nil, nil
		}
		shard.Unlock()
		if s.observedModelStore != nil {
			shared, ok, sharedErr := s.observedModelStore.GetObservedModelState(ctx, id)
			if sharedErr == nil && ok && shared.Model == model && observedModelStateIsFresh(now, shared.ObservedAt) {
				shard.Lock()
				shard.values[id] = observedModelState{model: model, persistedAt: now}
				shard.Unlock()
				return nil, nil
			}
		}
		updated := true
		if writer, ok := s.accounts.(repository.ObservedModelWriter); ok {
			var err error
			updated, err = writer.UpdateObservedModelIfNewer(ctx, id, model, now)
			if err != nil {
				return nil, err
			}
		} else if err := s.accounts.UpdateObservedModel(ctx, id, model, now); err != nil {
			return nil, err
		}
		if updated && s.observedModelStore != nil {
			_ = s.observedModelStore.SetObservedModelState(ctx, id, repository.ObservedModelState{Model: model, ObservedAt: now}, observedModelPersistInterval)
		}
		shard.Lock()
		current, exists := shard.values[id]
		if !exists || !current.persistedAt.After(now) {
			shard.values[id] = observedModelState{model: model, persistedAt: now}
		}
		shard.Unlock()
		return nil, nil
	})
	return err
}

func (s *Service) observedModelShard(id uint64) *observedModelShard {
	return &s.observedModelShards[id%observedModelLockShards]
}

func observedModelStateIsFresh(now, persistedAt time.Time) bool {
	elapsed := now.Sub(persistedAt)
	return elapsed >= 0 && elapsed < observedModelPersistInterval
}

func newQuotaView(billing *accountdomain.Billing, observedTokens int64, recovery *accountdomain.QuotaRecovery, observedModel string, buildSuperEntitled bool) QuotaView {
	// Upstream paid billing takes precedence and preserves reported quota values.
	if billing != nil && billing.IsPaid() {
		periodStart, periodEnd := billing.BillingPeriodStart, billing.BillingPeriodEnd
		if billing.UsagePeriodType != "" {
			periodStart, periodEnd = billing.UsagePeriodStart, billing.UsagePeriodEnd
		}
		result := QuotaView{Type: QuotaTypePaid, Source: "upstreamBilling", Confidence: "observed", Unit: "credits", UsagePercent: billing.CreditUsagePercent, Status: QuotaStatusActive, PeriodStart: periodStart, PeriodEnd: periodEnd}
		if recovery != nil && recovery.Kind == accountdomain.QuotaRecoveryKindPaid {
			result.Status = QuotaStatusWaitingReset
			if recovery.Status == accountdomain.QuotaRecoveryStatusProbing {
				result.Status = QuotaStatusProbing
			}
			result.ExhaustedAt = recovery.ExhaustedAt
			result.NextProbeAt = recovery.NextProbeAt
			result.LastConfirmedAt = recovery.LastConfirmedAt
		}
		switch {
		case billing.MonthlyLimit > 0:
			result.Used = billing.Used
			result.Limit = billing.MonthlyLimit
			result.Remaining = billing.Remaining()
			result.UsagePercent = billing.Used / billing.MonthlyLimit * 100
			result.LimitKnown = true
		case billing.OnDemandCap > 0:
			result.Limit = billing.OnDemandCap
			result.Used = billing.OnDemandUsed
			if result.Used == 0 && billing.CreditUsagePercent > 0 {
				result.Used = billing.OnDemandCap * billing.CreditUsagePercent / 100
			}
			result.Remaining = billing.OnDemandCap - result.Used
			result.LimitKnown = true
			if result.Remaining < 0 {
				result.Remaining = 0
			}
		case billing.PrepaidBalance > 0:
			result.Remaining = billing.PrepaidBalance
		case billing.UsagePeriodType != "":
			result.Unit = "percent"
			result.Used = billing.CreditUsagePercent
			result.Limit = 100
			result.Remaining = max(0, 100-billing.CreditUsagePercent)
			result.LimitKnown = true
		}
		return result
	}
	// 管理员确认的 Build Super entitlement：覆盖 Free recovery / profile / observed free 等弱信号。
	// 不伪造额度、余额、使用率或账期；Billing 数值保持未知/零。
	if buildSuperEntitled {
		return QuotaView{
			Type: QuotaTypePaid, Source: "buildSuperEntitlement", Confidence: "confirmed",
			Confirmed: true, Status: QuotaStatusActive,
		}
	}
	if recovery != nil && recovery.Status != accountdomain.QuotaRecoveryStatusActive && (recovery.Kind == "" || recovery.Kind == accountdomain.QuotaRecoveryKindFree) {
		limit := recovery.ConfirmedLimit
		used := recovery.ConfirmedUsed
		if used <= 0 {
			used = observedTokens
		}
		status := QuotaStatusWaitingReset
		if recovery.Status == accountdomain.QuotaRecoveryStatusProbing {
			status = QuotaStatusProbing
		}
		remaining := int64(0)
		usagePercent := 0.0
		if limit > 0 {
			remaining = limit - used
			if remaining < 0 {
				remaining = 0
			}
			usagePercent = float64(used) / float64(limit) * 100
		}
		return QuotaView{
			Type: QuotaTypeFree, Source: "upstreamExhaustion", Confidence: "confirmed", Unit: "tokens", Used: float64(used), Limit: float64(limit), LimitKnown: limit > 0,
			Remaining: float64(remaining), UsagePercent: usagePercent,
			WindowHours: int(freeUsageWindow / time.Hour), Confirmed: true, Status: status,
			ExhaustedAt: recovery.ExhaustedAt, NextProbeAt: recovery.NextProbeAt, LastConfirmedAt: recovery.LastConfirmedAt,
		}
	}
	freeSource := ""
	confidence := ""
	if strings.HasSuffix(strings.ToLower(strings.TrimSpace(observedModel)), "-build-free") {
		freeSource = "responseModel"
		confidence = "observed"
	} else if isEstimatedFreeBillingProfile(billing) {
		freeSource = "billingProfile"
		confidence = "estimated"
	}
	if freeSource == "" {
		return QuotaView{Type: QuotaTypeUnknown, Source: "unknown", Status: QuotaStatusActive}
	}
	if observedTokens < 0 {
		observedTokens = 0
	}
	remaining := estimatedFreeTokenLimit - observedTokens
	if remaining < 0 {
		remaining = 0
	}
	return QuotaView{
		Type:         QuotaTypeFree,
		Source:       freeSource,
		Confidence:   confidence,
		Unit:         "tokens",
		Used:         float64(observedTokens),
		Limit:        float64(estimatedFreeTokenLimit),
		Remaining:    float64(remaining),
		UsagePercent: float64(observedTokens) / float64(estimatedFreeTokenLimit) * 100,
		LimitKnown:   false,
		WindowHours:  int(freeUsageWindow / time.Hour),
		Observed:     true,
		Status:       QuotaStatusActive,
	}
}

func isEstimatedFreeBillingProfile(billing *accountdomain.Billing) bool {
	return billing != nil && (billing.HasFreeProfileSignal() || billing.HasInferredFreeProfileSignal())
}

// StartDeviceLogin 启动短期 Device OAuth，会话只保存在有界运行态存储中。
func (s *Service) StartDeviceLogin(ctx context.Context) (DeviceStartResult, error) {
	adapter, ok := s.providers.DeviceOAuth(accountdomain.ProviderBuild)
	if !ok {
		return DeviceStartResult{}, fmt.Errorf("CLI Provider 未注册")
	}
	authorization, err := adapter.StartDeviceAuthorization(ctx)
	if err != nil {
		return DeviceStartResult{}, err
	}
	sessionID, err := security.NewOpaqueToken(18)
	if err != nil {
		return DeviceStartResult{}, err
	}
	now := time.Now().UTC()
	session := accountdomain.DeviceSession{ID: sessionID, DeviceCode: authorization.DeviceCode, UserCode: authorization.UserCode, VerificationURI: authorization.VerificationURI, VerificationURIComplete: authorization.VerificationURIComplete, Interval: authorization.Interval, NextPollAt: now.Add(authorization.Interval), ExpiresAt: now.Add(authorization.ExpiresIn)}
	if err := s.deviceSessions.Create(ctx, session); err != nil {
		return DeviceStartResult{}, err
	}
	return DeviceStartResult{SessionID: sessionID, UserCode: session.UserCode, VerificationURI: session.VerificationURI, VerificationURIComplete: session.VerificationURIComplete, Interval: session.Interval, ExpiresAt: session.ExpiresAt}, nil
}

// PollDeviceLogin 执行一次上游轮询，成功后立即加密并写入账号仓储。
func (s *Service) PollDeviceLogin(ctx context.Context, sessionID string) (View, error) {
	now := time.Now().UTC()
	session, err := s.deviceSessions.Get(ctx, sessionID, now)
	if err != nil {
		return View{}, ErrDeviceDenied
	}
	if now.Before(session.NextPollAt) {
		return View{}, ErrDeviceSlowDown
	}
	adapter, ok := s.providers.DeviceOAuth(accountdomain.ProviderBuild)
	if !ok {
		return View{}, fmt.Errorf("CLI Provider 未注册")
	}
	seed, err := adapter.PollDeviceAuthorization(ctx, session.DeviceCode)
	session.NextPollAt = now.Add(session.Interval)
	_ = s.deviceSessions.Update(ctx, session)
	if errors.Is(err, provider.ErrAuthorizationPending) {
		return View{}, ErrDevicePending
	}
	if errors.Is(err, provider.ErrSlowDown) {
		session.Interval += 5 * time.Second
		session.NextPollAt = now.Add(session.Interval)
		_ = s.deviceSessions.Update(ctx, session)
		return View{}, ErrDeviceSlowDown
	}
	if errors.Is(err, provider.ErrAuthorizationDenied) {
		_ = s.deviceSessions.Delete(ctx, sessionID)
		return View{}, ErrDeviceDenied
	}
	if err != nil {
		return View{}, err
	}
	value, _, err := s.persistSeed(ctx, seed)
	if err != nil {
		return View{}, err
	}
	s.reconcileProviderLinksBestEffort(ctx, value.ID)
	_ = s.deviceSessions.Delete(ctx, sessionID)
	return s.Get(ctx, value.ID)
}

// ImportCredentials 导入用户上传的 OAuth 账号凭据。
func (s *Service) ImportCredentials(ctx context.Context, data []byte) (ImportResult, error) {
	return s.ImportCredentialsWithObserver(ctx, data, nil)
}

func (s *Service) ImportCredentialsWithObserver(ctx context.Context, data []byte, observer ImportedAccountObserver) (ImportResult, error) {
	return s.ImportCredentialsWithProgress(ctx, data, observer, nil)
}

// ImportCredentialsWithProgress 导入 Build 凭据并报告已写入流水线的账号数。
func (s *Service) ImportCredentialsWithProgress(ctx context.Context, data []byte, observer ImportedAccountObserver, progress BatchProgressObserver) (ImportResult, error) {
	return s.ImportCredentialDocumentsWithProgress(ctx, [][]byte{data}, observer, progress)
}

// ImportCredentialDocumentsWithProgress 合并解析多个 Build 凭据文件，并作为一个批次写入和同步。
func (s *Service) ImportCredentialDocumentsWithProgress(ctx context.Context, documents [][]byte, observer ImportedAccountObserver, progress BatchProgressObserver) (ImportResult, error) {
	adapter, ok := s.providers.CredentialCodec(accountdomain.ProviderBuild)
	if !ok {
		return ImportResult{}, fmt.Errorf("CLI Provider 未注册")
	}
	return s.importCredentialDocumentsWithProgress(ctx, adapter, documents, observer, progress)
}

// ImportWebCredentials 导入版本化或旧号池格式的 Grok Web SSO 凭据。
func (s *Service) ImportWebCredentials(ctx context.Context, data []byte) (ImportResult, error) {
	return s.ImportWebCredentialsWithObserver(ctx, data, nil)
}

func (s *Service) ImportWebCredentialsWithObserver(ctx context.Context, data []byte, observer ImportedAccountObserver) (ImportResult, error) {
	return s.ImportWebCredentialsWithProgress(ctx, data, observer, nil)
}

// ImportWebCredentialsWithProgress 导入 Web 凭据并报告已写入流水线的账号数。
func (s *Service) ImportWebCredentialsWithProgress(ctx context.Context, data []byte, observer ImportedAccountObserver, progress BatchProgressObserver) (ImportResult, error) {
	return s.ImportWebCredentialDocumentsWithOptions(ctx, [][]byte{data}, observer, progress, ImportWebOptions{})
}

// ImportWebCredentialDocumentsWithProgress 合并解析多个 Web JSON 或 SSO 文本文件，并作为一个批次写入和同步。
func (s *Service) ImportWebCredentialDocumentsWithProgress(ctx context.Context, documents [][]byte, observer ImportedAccountObserver, progress BatchProgressObserver) (ImportResult, error) {
	return s.ImportWebCredentialDocumentsWithOptions(ctx, documents, observer, progress, ImportWebOptions{})
}

// ImportWebCredentialDocumentsWithOptions is the full Web import path (options override config defaults).
func (s *Service) ImportWebCredentialDocumentsWithOptions(ctx context.Context, documents [][]byte, observer ImportedAccountObserver, progress BatchProgressObserver, opts ImportWebOptions) (ImportResult, error) {
	adapter, ok := s.providers.CredentialCodec(accountdomain.ProviderWeb)
	if !ok {
		return ImportResult{}, fmt.Errorf("Grok Web Provider 未注册")
	}
	result, err := s.importCredentialDocumentsWithProgress(ctx, adapter, documents, observer, progress)
	if err != nil {
		return result, err
	}
	if opts.TrustedSource && len(result.AccountIDs) > 0 {
		for _, id := range result.AccountIDs {
			if tagErr := s.accounts.AddAccountTag(ctx, id, accountdomain.TagCLITrusted); tagErr != nil {
				s.logger.Warn("web_import_trusted_tag_failed", "account_id", id, "error", tagErr)
			}
		}
	}
	autoSync := s.importAutoSyncConsole()
	if opts.AutoSyncConsole != nil {
		autoSync = *opts.AutoSyncConsole
	}
	if !autoSync || len(result.AccountIDs) == 0 {
		return result, nil
	}
	// Best-effort Console projection on the imported set only.
	// Use All so Updated Web SSO also refreshes linked Console ciphertext (Q3b).
	// Never roll back successful Web import.
	consoleResult, consoleErr := s.SyncWebAccountsToConsoleWithStrategy(ctx, result.AccountIDs, WebConsoleSyncAll, nil, nil)
	if consoleErr != nil {
		s.logger.Warn("web_import_console_projection_failed", "web_accounts", len(result.AccountIDs), "error", consoleErr)
		result.ConsoleFailed = len(result.AccountIDs)
		return result, nil
	}
	result.ConsoleCreated = consoleResult.Created
	result.ConsoleUpdated = consoleResult.Updated
	result.ConsoleSkipped = consoleResult.Skipped
	return result, nil
}

func (s *Service) ImportConsoleCredentials(ctx context.Context, data []byte) (ImportResult, error) {
	return s.ImportConsoleCredentialsWithObserver(ctx, data, nil)
}

func (s *Service) ImportConsoleCredentialsWithObserver(ctx context.Context, data []byte, observer ImportedAccountObserver) (ImportResult, error) {
	return s.ImportConsoleCredentialsWithProgress(ctx, data, observer, nil)
}

func (s *Service) ImportConsoleCredentialsWithProgress(ctx context.Context, data []byte, observer ImportedAccountObserver, progress BatchProgressObserver) (ImportResult, error) {
	return s.ImportConsoleCredentialDocumentsWithProgress(ctx, [][]byte{data}, observer, progress)
}

func (s *Service) ImportConsoleCredentialDocumentsWithProgress(ctx context.Context, documents [][]byte, observer ImportedAccountObserver, progress BatchProgressObserver) (ImportResult, error) {
	adapter, ok := s.providers.CredentialCodec(accountdomain.ProviderConsole)
	if !ok {
		return ImportResult{}, fmt.Errorf("Grok Console Provider 未注册")
	}
	return s.importCredentialDocumentsWithProgress(ctx, adapter, documents, observer, progress)
}

func (s *Service) importCredentialDocumentsWithProgress(ctx context.Context, adapter provider.CredentialCodecAdapter, documents [][]byte, observer ImportedAccountObserver, progress BatchProgressObserver) (ImportResult, error) {
	if len(documents) == 0 {
		return ImportResult{}, fmt.Errorf("%w: 没有可导入的账号文件", ErrInvalidImport)
	}
	seeds := make([]provider.CredentialSeed, 0)
	seen := make(map[string]struct{})
	parsedAccounts := 0
	for index, document := range documents {
		values, err := adapter.ParseImportedCredentials(document)
		if err != nil {
			if errors.Is(err, provider.ErrCredentialLimit) {
				return ImportResult{}, fmt.Errorf("%w: 单次最多导入 %d 个账号", ErrImportLimit, maxCredentialImportAccounts)
			}
			return ImportResult{}, fmt.Errorf("%w: 第 %d 个文件: %v", ErrInvalidImport, index+1, err)
		}
		parsedAccounts += len(values)
		if parsedAccounts > maxCredentialImportAccounts {
			return ImportResult{}, fmt.Errorf("%w: 单次最多导入 %d 个账号", ErrImportLimit, maxCredentialImportAccounts)
		}
		for _, value := range values {
			if value.SourceKey != "" {
				key := string(value.Provider) + "\x00" + value.SourceKey
				if _, exists := seen[key]; exists {
					continue
				}
				seen[key] = struct{}{}
			}
			seeds = append(seeds, value)
		}
	}
	return s.persistImportedSeeds(ctx, seeds, observer, progress)
}

func (s *Service) persistImportedSeeds(ctx context.Context, seeds []provider.CredentialSeed, observer ImportedAccountObserver, progress BatchProgressObserver) (ImportResult, error) {
	result := ImportResult{AccountIDs: make([]uint64, 0, len(seeds))}
	if progress != nil {
		if err := progress(0, len(seeds)); err != nil {
			return ImportResult{}, err
		}
	}
	completed := 0
	for start := 0; start < len(seeds); start += credentialImportChunkSize {
		end := min(start+credentialImportChunkSize, len(seeds))
		values := make([]accountdomain.Credential, 0, end-start)
		for _, seed := range seeds[start:end] {
			value, err := s.credentialFromSeed(seed)
			if err != nil {
				return ImportResult{}, err
			}
			values = append(values, value)
		}
		stored, err := s.accounts.UpsertManyByIdentity(ctx, values)
		if err != nil {
			return ImportResult{}, err
		}
		chunkIDs := make([]uint64, 0, len(stored))
		for _, value := range stored {
			result.AccountIDs = append(result.AccountIDs, value.ID)
			chunkIDs = append(chunkIDs, value.ID)
			if value.Created {
				result.Created++
			} else {
				result.Updated++
			}
		}
		// One (chunked) reconcile batch per UpsertMany chunk — avoids N independent transactions.
		s.reconcileProviderLinksBestEffortMany(ctx, chunkIDs)
		for _, value := range stored {
			if observer != nil {
				if err := observer(value.ID); err != nil {
					return ImportResult{}, err
				}
			}
			completed++
			if progress != nil {
				if err := progress(completed, len(seeds)); err != nil {
					return ImportResult{}, err
				}
			}
		}
	}
	s.WakeCredentialRefresh()
	s.bumpAccountDomainRevision(ctx)
	return result, nil
}

// SyncWebAccountsToConsoleWithProgress 使用 Web 账号的同一份 SSO 创建或更新 Console 账号。
func (s *Service) SyncWebAccountsToConsoleWithProgress(ctx context.Context, ids []uint64, observer ImportedAccountObserver, progress BatchProgressObserver) (ImportResult, error) {
	return s.SyncWebAccountsToConsoleWithStrategy(ctx, ids, WebConsoleSyncAll, observer, progress)
}

func (s *Service) SyncWebAccountsToConsoleWithStrategy(ctx context.Context, ids []uint64, strategy WebConsoleSyncStrategy, observer ImportedAccountObserver, progress BatchProgressObserver) (ImportResult, error) {
	if strategy != WebConsoleSyncAll && strategy != WebConsoleSyncMissing {
		return ImportResult{}, invalidInput("Grok Web 到 Console 同步策略无效")
	}
	ids, err := normalizeIDs(ids, maxWebConsoleSyncAccounts)
	if err != nil {
		return ImportResult{}, err
	}
	if strategy == WebConsoleSyncMissing {
		values, err := s.accounts.ListMissingConsoleSyncAccounts(ctx, ids)
		if err != nil {
			return ImportResult{}, mapRepositoryError(err)
		}
		result, err := s.syncWebCredentialsToConsole(ctx, values, observer, progress)
		result.Skipped = len(ids) - len(values)
		return result, err
	}
	values := make([]accountdomain.Credential, 0, len(ids))
	for _, id := range ids {
		value, getErr := s.accounts.Get(ctx, id)
		if getErr != nil {
			return ImportResult{}, mapRepositoryError(getErr)
		}
		values = append(values, value)
	}
	return s.syncWebCredentialsToConsole(ctx, values, observer, progress)
}

// SyncAllWebAccountsToConsoleWithProgress 同步完整 Web 号池，避免前端分页遗漏账号。
func (s *Service) SyncAllWebAccountsToConsoleWithProgress(ctx context.Context, observer ImportedAccountObserver, progress BatchProgressObserver) (ImportResult, error) {
	return s.SyncAllWebAccountsToConsoleWithStrategy(ctx, WebConsoleSyncAll, observer, progress)
}

func (s *Service) SyncAllWebAccountsToConsoleWithStrategy(ctx context.Context, strategy WebConsoleSyncStrategy, observer ImportedAccountObserver, progress BatchProgressObserver) (ImportResult, error) {
	if strategy != WebConsoleSyncAll && strategy != WebConsoleSyncMissing {
		return ImportResult{}, invalidInput("Grok Web 到 Console 同步策略无效")
	}
	batchSize := accountTaskBatchSize
	result := ImportResult{AccountIDs: make([]uint64, 0)}
	var afterID uint64
	completed := 0
	total := 0
	initialized := false
	for {
		var (
			values  []accountdomain.Credential
			count   int64
			skipped int64
			err     error
		)
		if strategy == WebConsoleSyncMissing {
			values, count, skipped, err = s.accounts.ListMissingConsoleSyncBatch(ctx, afterID, batchSize)
		} else {
			values, count, err = s.accounts.ListProviderAccountBatch(ctx, accountdomain.ProviderWeb, afterID, batchSize)
		}
		if err != nil {
			return result, err
		}
		if !initialized {
			total = int(count)
			result.Skipped = int(skipped)
			initialized = true
			if progress != nil {
				if err := progress(0, total); err != nil {
					return result, err
				}
			}
		}
		if len(values) == 0 {
			return result, nil
		}
		current, err := s.syncWebCredentialsToConsole(ctx, values, observer, offsetBatchProgress(progress, completed, total))
		result.Created += current.Created
		result.Updated += current.Updated
		result.AccountIDs = append(result.AccountIDs, current.AccountIDs...)
		if err != nil {
			return result, err
		}
		completed += len(values)
		afterID = values[len(values)-1].ID
		if len(values) < batchSize {
			return result, nil
		}
	}
}

func (s *Service) syncWebCredentialsToConsole(ctx context.Context, values []accountdomain.Credential, observer ImportedAccountObserver, progress BatchProgressObserver) (ImportResult, error) {
	adapter, ok := s.providers.CredentialCodec(accountdomain.ProviderConsole)
	if !ok {
		return ImportResult{}, fmt.Errorf("Grok Console Provider 未注册")
	}
	seeds := make([]provider.CredentialSeed, 0, len(values))
	for _, value := range values {
		if value.Provider != accountdomain.ProviderWeb || value.AuthType != accountdomain.AuthTypeSSO {
			return ImportResult{}, fmt.Errorf("%w: 仅 Grok Web SSO 账号支持同步到 Console", ErrUnsupported)
		}
		token, err := s.cipher.Decrypt(value.EncryptedAccessToken)
		if err != nil {
			return ImportResult{}, fmt.Errorf("解密 Grok Web SSO: %w", err)
		}
		parsed, err := adapter.ParseImportedCredentials([]byte(token))
		if err != nil {
			return ImportResult{}, fmt.Errorf("生成 Grok Console SSO 凭据: %w", err)
		}
		if len(parsed) != 1 {
			return ImportResult{}, fmt.Errorf("生成 Grok Console SSO 凭据: 预期 1 个账号，实际 %d 个", len(parsed))
		}
		seed := parsed[0]
		seed.Provider = accountdomain.ProviderConsole
		seed.AuthType = accountdomain.AuthTypeSSO
		seed.Name = webConsoleAccountName(value.Name, seed.Name)
		// R3h: project Web identity onto Console so sync does not re-hit upstream session APIs.
		if seed.Email == "" {
			seed.Email = strings.TrimSpace(value.Email)
		}
		if seed.UserID == "" {
			seed.UserID = strings.TrimSpace(value.UserID)
		}
		if seed.TeamID == "" {
			seed.TeamID = strings.TrimSpace(value.TeamID)
		}
		if strings.TrimSpace(value.EncryptedCloudflareCookie) != "" {
			cookies, decryptErr := s.cipher.Decrypt(value.EncryptedCloudflareCookie)
			if decryptErr != nil {
				return ImportResult{}, fmt.Errorf("解密 Grok Web Cloudflare Cookie: %w", decryptErr)
			}
			seed.CloudflareCookies = cookies
		}
		seeds = append(seeds, seed)
	}
	return s.persistImportedSeeds(ctx, seeds, observer, progress)
}

func webConsoleAccountName(webName, fallback string) string {
	name := strings.TrimSpace(webName)
	if name == "" {
		return fallback
	}
	if suffix, ok := strings.CutPrefix(name, "Grok Web "); ok {
		return "Grok Console " + suffix
	}
	return name
}

// ConvertWebAccountsToBuild 使用 Web SSO 自动完成 xAI Device Flow，并建立唯一的 Web/Build 账号关联。
func (s *Service) ConvertWebAccountsToBuild(ctx context.Context, ids []uint64) (BuildConversionResult, error) {
	return s.ConvertWebAccountsToBuildWithStrategy(ctx, ids, BuildConversionMissing, nil, nil)
}

func (s *Service) ConvertWebAccountsToBuildWithObserver(ctx context.Context, ids []uint64, observer ImportedAccountObserver) (BuildConversionResult, error) {
	return s.ConvertWebAccountsToBuildWithStrategy(ctx, ids, BuildConversionMissing, observer, nil)
}

// ConvertWebAccountsToBuildWithProgress 转换指定账号，并向调用方报告真实完成数。
func (s *Service) ConvertWebAccountsToBuildWithProgress(ctx context.Context, ids []uint64, observer ImportedAccountObserver, progress BatchProgressObserver) (BuildConversionResult, error) {
	return s.ConvertWebAccountsToBuildWithStrategy(ctx, ids, BuildConversionMissing, observer, progress)
}

func (s *Service) ConvertWebAccountsToBuildWithStrategy(ctx context.Context, ids []uint64, strategy BuildConversionStrategy, observer ImportedAccountObserver, progress BatchProgressObserver) (BuildConversionResult, error) {
	return s.ConvertWebAccountsToBuildWithStrategyOptions(ctx, ids, strategy, observer, progress, ConvertBuildOptions{})
}

// ConvertBuildOptions controls post-convert CLI profile flags.
type ConvertBuildOptions struct {
	// TrustedSource is deprecated for admin Convert UX (trusted is an SSO/import property).
	// Still honored if true for API compatibility; Convert always inherits Web TagCLITrusted.
	TrustedSource bool
}

func (s *Service) ConvertWebAccountsToBuildWithStrategyOptions(ctx context.Context, ids []uint64, strategy BuildConversionStrategy, observer ImportedAccountObserver, progress BatchProgressObserver, opts ConvertBuildOptions) (BuildConversionResult, error) {
	if strategy != BuildConversionAll && strategy != BuildConversionMissing {
		return BuildConversionResult{}, invalidInput("Grok Web 到 Build 转换策略无效")
	}
	ids, err := normalizeIDs(ids, maxBuildConversionAccounts)
	if err != nil {
		return BuildConversionResult{}, err
	}
	prefilteredSkipped := 0
	if strategy == BuildConversionMissing {
		candidates, err := s.accounts.FilterMissingBuildConversionIDs(ctx, ids)
		if err != nil {
			return BuildConversionResult{}, mapRepositoryError(err)
		}
		prefilteredSkipped = len(ids) - len(candidates)
		ids = candidates
	}
	result, err := s.convertWebAccountsToBuild(ctx, ids, strategy, observer, progress, opts)
	result.Skipped += prefilteredSkipped
	return result, err
}

// ConvertAllWebAccountsToBuild 转换全部尚未建立 Build 关联的 Grok Web 账号。
func (s *Service) ConvertAllWebAccountsToBuild(ctx context.Context) (BuildConversionResult, error) {
	return s.ConvertAllWebAccountsToBuildWithStrategy(ctx, BuildConversionMissing, nil, nil)
}

func (s *Service) ConvertAllWebAccountsToBuildWithObserver(ctx context.Context, observer ImportedAccountObserver) (BuildConversionResult, error) {
	return s.ConvertAllWebAccountsToBuildWithStrategy(ctx, BuildConversionMissing, observer, nil)
}

// ConvertAllWebAccountsToBuildWithProgress 转换完整未关联号池，并向调用方报告真实完成数。
func (s *Service) ConvertAllWebAccountsToBuildWithProgress(ctx context.Context, observer ImportedAccountObserver, progress BatchProgressObserver) (BuildConversionResult, error) {
	return s.ConvertAllWebAccountsToBuildWithStrategy(ctx, BuildConversionMissing, observer, progress)
}

func (s *Service) ConvertAllWebAccountsToBuildWithStrategy(ctx context.Context, strategy BuildConversionStrategy, observer ImportedAccountObserver, progress BatchProgressObserver) (BuildConversionResult, error) {
	return s.ConvertAllWebAccountsToBuildWithStrategyOptions(ctx, strategy, observer, progress, ConvertBuildOptions{})
}

func (s *Service) ConvertAllWebAccountsToBuildWithStrategyOptions(ctx context.Context, strategy BuildConversionStrategy, observer ImportedAccountObserver, progress BatchProgressObserver, opts ConvertBuildOptions) (BuildConversionResult, error) {
	if strategy != BuildConversionAll && strategy != BuildConversionMissing {
		return BuildConversionResult{}, invalidInput("Grok Web 到 Build 转换策略无效")
	}
	batchSize := accountTaskBatchSize
	result := BuildConversionResult{BuildAccountIDs: make([]uint64, 0)}
	seenBuildIDs := make(map[uint64]struct{})
	var observed sync.Map
	batchObserver := observer
	if observer != nil {
		batchObserver = func(accountID uint64) error {
			if _, loaded := observed.LoadOrStore(accountID, struct{}{}); loaded {
				return nil
			}
			return observer(accountID)
		}
	}
	var afterID uint64
	completed := 0
	total := 0
	initialized := false
	for {
		var (
			ids   []uint64
			count int64
			err   error
		)
		if strategy == BuildConversionMissing {
			ids, count, err = s.accounts.ListUnlinkedWebAccountIDs(ctx, afterID, batchSize)
		} else {
			var values []accountdomain.Credential
			values, count, err = s.accounts.ListProviderAccountBatch(ctx, accountdomain.ProviderWeb, afterID, batchSize)
			ids = make([]uint64, 0, len(values))
			for _, value := range values {
				ids = append(ids, value.ID)
			}
		}
		if err != nil {
			return result, err
		}
		if !initialized {
			total = int(count)
			initialized = true
			if progress != nil {
				if err := progress(0, total); err != nil {
					return result, err
				}
			}
		}
		if len(ids) == 0 {
			return result, nil
		}
		current, err := s.convertWebAccountsToBuild(ctx, ids, strategy, batchObserver, offsetBatchProgress(progress, completed, total), opts)
		result.Created += current.Created
		result.Linked += current.Linked
		result.Skipped += current.Skipped
		result.Failed += current.Failed
		result.Failures = append(result.Failures, current.Failures...)
		for _, buildID := range current.BuildAccountIDs {
			if _, exists := seenBuildIDs[buildID]; exists {
				continue
			}
			seenBuildIDs[buildID] = struct{}{}
			result.BuildAccountIDs = append(result.BuildAccountIDs, buildID)
		}
		if err != nil {
			return result, err
		}
		completed += len(ids)
		afterID = ids[len(ids)-1]
		if len(ids) < batchSize {
			return result, nil
		}
	}
}

func offsetBatchProgress(progress BatchProgressObserver, offset, total int) BatchProgressObserver {
	if progress == nil {
		return nil
	}
	return func(completed, _ int) error {
		if completed == 0 {
			return nil
		}
		return progress(offset+completed, total)
	}
}

func (s *Service) convertWebAccountsToBuild(ctx context.Context, ids []uint64, strategy BuildConversionStrategy, observer ImportedAccountObserver, progress BatchProgressObserver, opts ConvertBuildOptions) (BuildConversionResult, error) {
	if progress != nil {
		if err := progress(0, len(ids)); err != nil {
			return BuildConversionResult{}, err
		}
	}
	type outcome struct {
		accountID uint64
		buildID   uint64
		created   bool
		skipped   bool
		err       error
	}
	var observed sync.Map
	var observerMu sync.Mutex
	var observerErr error
	completed := 0
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results, summary, runErr := batch.MapObserved(runCtx, ids, batch.Options{Workers: s.conversionPool.Limit(), Pool: s.conversionPool}, func(workCtx context.Context, id uint64) (outcome, error) {
		buildID, created, skipped, convertErr := s.convertWebAccountToBuild(workCtx, id, strategy, opts)
		return outcome{accountID: id, buildID: buildID, created: created, skipped: skipped, err: convertErr}, nil
	}, func(_ int, execution batch.Result[outcome]) {
		observerMu.Lock()
		defer observerMu.Unlock()
		defer func() {
			completed++
			if progress != nil {
				if err := progress(completed, len(ids)); err != nil && observerErr == nil {
					observerErr = err
					cancel()
				}
			}
		}()
		item := execution.Value
		if execution.Err != nil || item.err != nil || item.skipped || observer == nil {
			return
		}
		if _, loaded := observed.LoadOrStore(item.buildID, struct{}{}); loaded {
			return
		}
		if err := observer(item.buildID); err != nil {
			if observerErr == nil {
				observerErr = err
				cancel()
			}
		}
	})
	s.logBatchSummary("web_to_build", s.conversionPool, summary, runErr)
	result := BuildConversionResult{BuildAccountIDs: make([]uint64, 0, len(ids))}
	seen := make(map[uint64]struct{}, len(ids))
	for index, execution := range results {
		item := execution.Value
		if execution.Err != nil {
			item.accountID = ids[index]
			item.err = execution.Err
		}
		if item.err != nil {
			result.Failed++
			class := string(webprovider.ClassifyConversionError(item.err))
			result.Failures = append(result.Failures, BuildConversionFailure{AccountID: item.accountID, Message: item.err.Error(), Class: class})
			s.logger.Warn("web_account_build_conversion_failed", "account_id", item.accountID, "class", class, "error", item.err)
			continue
		}
		if item.skipped {
			result.Skipped++
			continue
		}
		if item.created {
			result.Created++
		} else {
			result.Linked++
		}
		if _, ok := seen[item.buildID]; !ok {
			seen[item.buildID] = struct{}{}
			result.BuildAccountIDs = append(result.BuildAccountIDs, item.buildID)
		}
	}
	if runErr != nil {
		return result, runErr
	}
	if observerErr != nil {
		return result, observerErr
	}
	if result.Created > 0 || result.Linked > 0 {
		s.bumpAccountDomainRevision(ctx)
	}
	return result, nil
}

func (s *Service) convertWebAccountToBuild(ctx context.Context, id uint64, strategy BuildConversionStrategy, opts ConvertBuildOptions) (uint64, bool, bool, error) {
	value, err := s.accounts.Get(ctx, id)
	if err != nil {
		return 0, false, false, mapRepositoryError(err)
	}
	if value.Provider != accountdomain.ProviderWeb || value.AuthType != accountdomain.AuthTypeSSO {
		return 0, false, false, ErrUnsupported
	}
	if value.LinkedAccountID != 0 && strategy == BuildConversionMissing {
		return value.LinkedAccountID, false, true, nil
	}
	if s.refreshLock == nil {
		return 0, false, false, fmt.Errorf("conversion lock unavailable")
	}
	release, acquired, err := s.refreshLock.Acquire(ctx, "web-build-conversion:"+strconv.FormatUint(id, 10), 2*time.Minute)
	if err != nil {
		return 0, false, false, err
	}
	if !acquired {
		return 0, false, false, ErrConversionBusy
	}
	defer release()
	value, err = s.accounts.Get(ctx, id)
	if err != nil {
		return 0, false, false, mapRepositoryError(err)
	}
	if value.LinkedAccountID != 0 && strategy == BuildConversionMissing {
		return value.LinkedAccountID, false, true, nil
	}
	linkedBuildSourceKey := ""
	if value.LinkedAccountID != 0 {
		linkedBuild, getErr := s.accounts.Get(ctx, value.LinkedAccountID)
		if getErr != nil {
			return 0, false, false, mapRepositoryError(getErr)
		}
		if linkedBuild.Provider != accountdomain.ProviderBuild || strings.TrimSpace(linkedBuild.SourceKey) == "" {
			return 0, false, false, fmt.Errorf("已关联 Grok Build 账号身份无效")
		}
		linkedBuildSourceKey = linkedBuild.SourceKey
	}
	if s.providers == nil {
		return 0, false, false, ErrUnsupported
	}
	converter, ok := s.providers.BuildConverter(accountdomain.ProviderWeb)
	if !ok {
		return 0, false, false, fmt.Errorf("Grok Web SSO 转换能力未注册")
	}
	const maxConvertAttempts = 3
	var seed provider.CredentialSeed
	for attempt := 1; attempt <= maxConvertAttempts; attempt++ {
		seed, err = converter.ConvertToBuild(ctx, value)
		if err == nil {
			break
		}
		if errors.Is(err, provider.ErrUnauthorized) {
			err = errors.Join(err, s.markSSOCredentialRejected(ctx, value, "Grok Web SSO credential rejected"))
			return 0, false, false, err
		}
		if !webprovider.ConversionErrorRetriable(err) || attempt == maxConvertAttempts {
			return 0, false, false, err
		}
		delay := time.Duration(attempt) * 400 * time.Millisecond
		if status, ok := provider.ErrorHTTPStatus(err); ok && status == http.StatusTooManyRequests {
			delay = time.Duration(attempt) * time.Second
		}
		s.logger.Warn("web_account_build_conversion_retry", "account_id", id, "attempt", attempt, "class", string(webprovider.ClassifyConversionError(err)), "error", err, "backoff", delay.String())
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return 0, false, false, ctx.Err()
		case <-timer.C:
		}
	}
	if err != nil {
		return 0, false, false, err
	}
	seed.Provider = accountdomain.ProviderBuild
	seed.AuthType = accountdomain.AuthTypeOAuth
	if linkedBuildSourceKey != "" {
		seed.SourceKey = linkedBuildSourceKey
	}
	buildAccount, created, err := s.persistSeed(ctx, seed)
	if err != nil {
		return 0, false, false, err
	}
	if value.LinkedAccountID != 0 && buildAccount.ID != value.LinkedAccountID {
		return 0, false, false, fmt.Errorf("重新转换后的 Grok Build 账号身份不一致")
	}
	if err := s.accounts.LinkWebToBuild(ctx, id, buildAccount.ID); err != nil {
		return 0, false, false, mapRepositoryError(err)
	}
	// Inherit trusted supply mark into Build CLI profile (never clears proven/other fields).
	if opts.TrustedSource || value.HasAccountTag(accountdomain.TagCLITrusted) {
		if trustErr := s.accounts.SetBuildCLITrustedSource(ctx, buildAccount.ID, true); trustErr != nil {
			s.logger.Warn("build_cli_trusted_source_set_failed", "build_account_id", buildAccount.ID, "web_account_id", id, "error", trustErr)
		}
	}
	return buildAccount.ID, created, false, nil
}

// UpdateBuildCLITrustedSource sets trusted_source on a Build account only.
func (s *Service) UpdateBuildCLITrustedSource(ctx context.Context, id uint64, trusted bool) (View, error) {
	value, err := s.accounts.Get(ctx, id)
	if err != nil {
		return View{}, mapRepositoryError(err)
	}
	if value.Provider != accountdomain.ProviderBuild {
		return View{}, invalidInput("仅 Grok Build 账号支持 CLI trusted 标记")
	}
	if err := s.accounts.SetBuildCLITrustedSource(ctx, id, trusted); err != nil {
		return View{}, err
	}
	return s.Get(ctx, id)
}

// ExportCredentials 保留 Grok Build 默认导出语义，供旧调用方兼容。
func (s *Service) ExportCredentials(ctx context.Context) (ExportResult, error) {
	return s.ExportProviderCredentials(ctx, accountdomain.ProviderBuild)
}

// ExportProviderCredentials 导出可由对应 Provider 导入接口重新读取的凭据文档。
func (s *Service) ExportProviderCredentials(ctx context.Context, providerValue accountdomain.Provider) (ExportResult, error) {
	return s.exportProviderCredentials(ctx, providerValue, repository.AccountListQuery{
		Page:   repository.PageQuery{Limit: maxCredentialExportAccounts + 1},
		Filter: repository.AccountListFilter{Provider: string(providerValue), Now: s.now()},
	}, true, 0)
}

// ExportProviderCredentialsCursor exports a stable provider batch bounded by
// the maximum account ID captured by the first request.
func (s *Service) ExportProviderCredentialsCursor(ctx context.Context, providerValue accountdomain.Provider, afterID, snapshotMaxID uint64, limit int) (ExportPageResult, error) {
	if limit < 1 || limit > maxCredentialExportAccounts {
		return ExportPageResult{}, invalidInput(fmt.Sprintf("单批导出数量必须在 1 到 %d 之间", maxCredentialExportAccounts))
	}
	if afterID > 0 && snapshotMaxID == 0 {
		return ExportPageResult{}, invalidInput("继续导出时必须提供快照上界")
	}
	if snapshotMaxID > 0 && afterID > snapshotMaxID {
		return ExportPageResult{}, invalidInput("导出游标不能超过快照上界")
	}
	if !providerValue.IsValid() {
		return ExportPageResult{}, invalidInput("账号来源无效")
	}
	if snapshotMaxID == 0 {
		values, _, err := s.accounts.List(ctx, repository.AccountListQuery{
			Page:   repository.PageQuery{Limit: 1, Sort: repository.SortQuery{Field: "id", Direction: repository.SortDescending}},
			Filter: repository.AccountListFilter{Provider: string(providerValue), Now: s.now()},
		})
		if err != nil {
			return ExportPageResult{}, err
		}
		if len(values) == 0 {
			result, exportErr := s.marshalProviderCredentials(providerValue, nil)
			return ExportPageResult{ExportResult: result}, exportErr
		}
		snapshotMaxID = values[0].ID
	}
	values, total, err := s.accounts.List(ctx, repository.AccountListQuery{
		Page: repository.PageQuery{Limit: limit, Sort: repository.SortQuery{Field: "id", Direction: repository.SortAscending}},
		Filter: repository.AccountListFilter{
			Provider: string(providerValue), AfterID: afterID, ThroughID: snapshotMaxID, Now: s.now(),
		},
	})
	if err != nil {
		return ExportPageResult{}, err
	}
	result, err := s.marshalProviderCredentials(providerValue, values)
	if err != nil {
		return ExportPageResult{}, err
	}
	nextID := afterID
	if len(values) > 0 {
		nextID = values[len(values)-1].ID
	}
	return ExportPageResult{
		ExportResult: result, NextID: nextID, SnapshotMaxID: snapshotMaxID, HasMore: total > int64(len(values)),
	}, nil
}

// ExportProviderCredentialsByIDs 只导出管理端明确选择且属于指定 Provider 的账号。
func (s *Service) ExportProviderCredentialsByIDs(ctx context.Context, providerValue accountdomain.Provider, ids []uint64) (ExportResult, error) {
	values, err := normalizeIDs(ids, maxCredentialExportAccounts)
	if err != nil {
		return ExportResult{}, err
	}
	return s.exportProviderCredentials(ctx, providerValue, repository.AccountListQuery{
		Page: repository.PageQuery{Limit: len(values)},
		Filter: repository.AccountListFilter{
			Provider: string(providerValue), AccountIDs: values, RestrictIDs: true, Now: s.now(),
		},
	}, false, len(values))
}

func (s *Service) exportProviderCredentials(ctx context.Context, providerValue accountdomain.Provider, query repository.AccountListQuery, enforceTotalLimit bool, expectedCount int) (ExportResult, error) {
	if !providerValue.IsValid() {
		return ExportResult{}, invalidInput("账号来源无效")
	}
	values, total, err := s.accounts.List(ctx, query)
	if err != nil {
		return ExportResult{}, err
	}
	if enforceTotalLimit && total > maxCredentialExportAccounts {
		return ExportResult{}, fmt.Errorf("%w: 单次最多导出 %d 个账号", ErrExportLimit, maxCredentialExportAccounts)
	}
	if err := validateCredentialExportCount(expectedCount, total, len(values)); err != nil {
		return ExportResult{}, err
	}
	return s.marshalProviderCredentials(providerValue, values)
}

func validateCredentialExportCount(expected int, total int64, actual int) error {
	if expected > 0 && (total != int64(expected) || actual != expected) {
		return invalidInput("所选账号包含不存在或不属于当前号池的账号")
	}
	return nil
}

func (s *Service) marshalProviderCredentials(providerValue accountdomain.Provider, values []accountdomain.Credential) (ExportResult, error) {
	if !providerValue.IsValid() {
		return ExportResult{}, invalidInput("账号来源无效")
	}
	if s.providers == nil {
		return ExportResult{}, fmt.Errorf("Provider 注册表未初始化")
	}
	adapter, ok := s.providers.CredentialCodec(providerValue)
	if !ok {
		return ExportResult{}, fmt.Errorf("Provider %s 不支持凭据导出", providerValue)
	}
	var err error
	seeds := make([]provider.CredentialSeed, 0, len(values))
	for _, value := range values {
		if value.Provider != providerValue {
			continue
		}
		accessToken := ""
		if value.EncryptedAccessToken != "" {
			accessToken, err = s.cipher.Decrypt(value.EncryptedAccessToken)
			if err != nil {
				return ExportResult{}, fmt.Errorf("解密账号 %d access token: %w", value.ID, err)
			}
		}
		refreshToken := ""
		if value.EncryptedRefreshToken != "" {
			refreshToken, err = s.cipher.Decrypt(value.EncryptedRefreshToken)
			if err != nil {
				return ExportResult{}, fmt.Errorf("解密账号 %d refresh token: %w", value.ID, err)
			}
		}
		cloudflareCookies := ""
		if value.EncryptedCloudflareCookie != "" {
			cloudflareCookies, err = s.cipher.Decrypt(value.EncryptedCloudflareCookie)
			if err != nil {
				return ExportResult{}, fmt.Errorf("解密账号 %d Cloudflare Cookie: %w", value.ID, err)
			}
		}
		if accessToken == "" && refreshToken == "" {
			return ExportResult{}, fmt.Errorf("账号 %d 没有可导出的凭据", value.ID)
		}
		seeds = append(seeds, provider.CredentialSeed{
			Provider: value.Provider, AuthType: value.AuthType, WebTier: value.WebTier,
			Name: value.Name, Email: value.Email, UserID: value.UserID, TeamID: value.TeamID,
			OIDCClientID: value.OIDCClientID, AccessToken: accessToken, RefreshToken: refreshToken,
			CloudflareCookies: cloudflareCookies, ExpiresAt: value.ExpiresAt,
			WebNSFWEnabledAt: value.WebNSFWEnabledAt, WebTermsAcceptedAt: value.WebTermsAcceptedAt,
			WebTermsAcceptedVersion: value.WebTermsAcceptedVersion, WebBirthDateSetAt: value.WebBirthDateSetAt,
		})
	}
	data, err := adapter.MarshalCredentials(seeds)
	if err != nil {
		return ExportResult{}, err
	}
	return ExportResult{Data: data, Count: len(seeds)}, nil
}

func (s *Service) Update(ctx context.Context, id uint64, input UpdateInput) (View, error) {
	value, err := s.accounts.Get(ctx, id)
	if err != nil {
		return View{}, mapRepositoryError(err)
	}
	if input.Name != nil {
		value.Name = strings.TrimSpace(*input.Name)
		if value.Name == "" {
			return View{}, invalidInput("账号名称不能为空")
		}
	}
	if input.Enabled != nil {
		value.Enabled = *input.Enabled
	}
	if input.Priority != nil {
		value.Priority = *input.Priority
	}
	if input.MaxConcurrent != nil {
		if *input.MaxConcurrent < 1 || *input.MaxConcurrent > accountdomain.MaxConcurrent {
			return View{}, invalidInput("maxConcurrent 必须在 1 到 256 之间")
		}
		value.MaxConcurrent = *input.MaxConcurrent
	}
	if input.MinimumRemaining != nil {
		if *input.MinimumRemaining < 0 {
			return View{}, invalidInput("minimumRemaining 不能小于零")
		}
		value.MinimumRemaining = *input.MinimumRemaining
	}
	if input.ClearCloudflareCookies {
		value.EncryptedCloudflareCookie = ""
	} else if input.CloudflareCookies != nil {
		if value.Provider == accountdomain.ProviderBuild {
			return View{}, invalidInput("Grok Build 账号不使用 Cloudflare Cookie")
		}
		if len(*input.CloudflareCookies) > 16<<10 {
			return View{}, invalidInput("Cloudflare Cookie 不能超过 16 KiB")
		}
		if strings.TrimSpace(*input.CloudflareCookies) != "" {
			cookies := egressapp.SanitizeCloudflareCookies(*input.CloudflareCookies)
			if cookies == "" {
				return View{}, invalidInput("Cloudflare Cookie 中没有有效字段")
			}
			encrypted, encryptErr := s.cipher.Encrypt(cookies)
			if encryptErr != nil {
				return View{}, encryptErr
			}
			value.EncryptedCloudflareCookie = encrypted
		}
	}
	if input.BuildSuperEntitled != nil {
		if value.Provider != accountdomain.ProviderBuild {
			return View{}, invalidInput("仅 Grok Build 账号支持设置 Build Super entitlement")
		}
		value.BuildSuperEntitled = *input.BuildSuperEntitled
	}
	if input.BuildRouteMode != nil {
		if value.Provider != accountdomain.ProviderBuild {
			return View{}, invalidInput("仅 Grok Build 账号支持设置上游地址")
		}
		if !input.BuildRouteMode.IsValid() {
			return View{}, invalidInput("Build 上游地址必须是 auto、build 或 xai")
		}
		value.BuildRouteMode = *input.BuildRouteMode
	}
	updated, err := s.accounts.Update(ctx, value)
	if err != nil {
		return View{}, mapRepositoryError(err)
	}
	if !updated.Enabled && s.sticky != nil {
		_ = s.sticky.DeleteByAccount(ctx, updated.ID)
	} else if updated.Enabled && s.providers != nil && s.providers.SupportsCredentialRefresh(updated.Provider) {
		s.WakeCredentialRefresh()
	}
	s.bumpAccountDomainRevision(ctx)
	return s.Get(ctx, updated.ID)
}

// MarkBuildAPIFallback 幂等写入 Build 账号 XAI 推理回退标记；失败不吞掉，调用方可重试。
func (s *Service) MarkBuildAPIFallback(ctx context.Context, id uint64, enabled bool) error {
	return mapRepositoryError(s.accounts.MarkBuildAPIFallback(ctx, id, enabled))
}

func (s *Service) Delete(ctx context.Context, id uint64) error {
	// Single-account delete must preserve ErrNotFound when the root row is gone
	// (BatchDeleteWithLinked/DeleteMany return deleted=0, nil for missing IDs).
	result, err := s.DeleteWithLinked(ctx, accountdomain.Provider(""), id, nil)
	if err != nil {
		return err
	}
	if result.Deleted == 0 {
		return ErrNotFound
	}
	s.clearRefreshState(id)
	s.invalidateBuildBotFlagCache()
	s.bumpAccountDomainRevision(ctx)
	return nil
}

// DeleteWithLinked deletes one account and optional linked peers.
// A single delete is rejected if any account in the final group has an active video job.
func (s *Service) DeleteWithLinked(ctx context.Context, providerValue accountdomain.Provider, id uint64, targets []accountdomain.Provider) (AccountDeleteResult, error) {
	if id == 0 {
		return AccountDeleteResult{}, invalidInput("账号 ID 无效")
	}
	result, err := s.batchDeleteWithLinkedMode(ctx, providerValue, []uint64{id}, targets, false)
	if err != nil {
		return result, err
	}
	// Fail closed for the single-root API: missing root must not report success.
	if result.Deleted == 0 {
		return result, ErrNotFound
	}
	return result, nil
}

// PreviewLinkedDelete returns root/linked counts for the delete confirmation UI.
func (s *Service) PreviewLinkedDelete(ctx context.Context, providerValue accountdomain.Provider, ids []uint64, targets []accountdomain.Provider) (repository.LinkedDeleteResolution, error) {
	ids, err := normalizeBatchIDs(ids)
	if err != nil {
		return repository.LinkedDeleteResolution{}, err
	}
	if !providerValue.IsValid() {
		return repository.LinkedDeleteResolution{}, invalidInput("账号来源无效")
	}
	resolution, err := s.accounts.ResolveLinkedDeleteIDs(ctx, providerValue, ids, targets)
	if err != nil {
		return repository.LinkedDeleteResolution{}, mapLinkedDeleteError(err)
	}
	return resolution, nil
}

func (s *Service) MarkReauthRequired(ctx context.Context, id uint64, reason string) error {
	value, err := s.accounts.Get(ctx, id)
	if err != nil {
		return mapRepositoryError(err)
	}
	value.AuthStatus = accountdomain.AuthStatusReauthRequired
	value.ReauthReason = accountdomain.InferReauthReason(reason)
	value.LastError = reason
	if len(value.LastError) > 512 {
		value.LastError = value.LastError[:512]
	}
	if _, err := s.accounts.Update(ctx, value); err != nil {
		return mapRepositoryError(err)
	}
	if s.sticky != nil {
		_ = s.sticky.DeleteByAccount(ctx, id)
	}
	return nil
}

// markSSOCredentialRejected 在上游明确返回 401 后可靠持久化失效状态。
// 状态写入不继承客户端取消，避免已经确认失效的账号因请求断开继续留在号池。
func (s *Service) markSSOCredentialRejected(ctx context.Context, value accountdomain.Credential, reason string) error {
	if value.AuthType != accountdomain.AuthTypeSSO {
		return nil
	}
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), credentialStateWriteTimeout)
	defer cancel()
	if err := s.MarkReauthRequired(writeCtx, value.ID, reason); err != nil {
		s.logger.Error("account_reauth_required_write_failed", "account_id", value.ID, "provider", value.Provider, "error", err)
		return err
	}
	return nil
}

// EnsureCredential 在即将过期时刷新 token，同一账号并发请求只执行一次刷新。
func (s *Service) EnsureCredential(ctx context.Context, value accountdomain.Credential, force bool) (accountdomain.Credential, error) {
	return s.ensureCredential(ctx, value, force, false, false)
}

func (s *Service) ensureCredential(ctx context.Context, value accountdomain.Credential, force, bypassCooldown, respectSchedule bool) (accountdomain.Credential, error) {
	if s.providers == nil || !s.providers.SupportsCredentialRefresh(value.Provider) {
		if force {
			return accountdomain.Credential{}, ErrUnsupported
		}
		return value, nil
	}
	now := s.now()
	if credential, err, handled := s.resolvePermanentRefreshFailure(ctx, value, now, force); handled {
		return credential, err
	}
	if !force && value.ExpiresAt.IsZero() && value.EncryptedAccessToken != "" {
		return value, nil
	}
	if !force && value.EncryptedAccessToken != "" && !value.ExpiresAt.IsZero() && now.Add(credentialRefreshAdvance).Before(value.ExpiresAt) {
		return value, nil
	}
	refreshKey := strconv.FormatUint(value.ID, 10)
	if respectSchedule {
		refreshKey += ":scheduled"
	}
	result, err, _ := s.refreshes.Do(refreshKey, func() (any, error) {
		latest, err := s.accounts.Get(ctx, value.ID)
		if err != nil {
			return nil, err
		}
		currentTime := s.now()
		if credential, err, handled := s.resolvePermanentRefreshFailure(ctx, latest, currentTime, force); handled {
			if err != nil {
				return nil, err
			}
			return credential, nil
		}
		if respectSchedule && latest.RefreshDueAt != nil && latest.RefreshDueAt.After(currentTime) {
			return latest, nil
		}
		if force && latest.EncryptedAccessToken != "" && latest.EncryptedAccessToken != value.EncryptedAccessToken {
			return latest, nil
		}
		if !force && latest.EncryptedAccessToken != "" && !latest.ExpiresAt.IsZero() && currentTime.Add(credentialRefreshAdvance).Before(latest.ExpiresAt) {
			return latest, nil
		}
		if force && !bypassCooldown && s.credentialRefreshCoolingDown(latest, currentTime) {
			return latest, nil
		}
		release, err := s.acquireRefreshLock(ctx, latest.ID)
		if err != nil {
			return nil, err
		}
		if release != nil {
			defer release()
			latest, err = s.accounts.Get(ctx, value.ID)
			if err != nil {
				return nil, err
			}
			currentTime = s.now()
			if credential, err, handled := s.resolvePermanentRefreshFailure(ctx, latest, currentTime, force); handled {
				if err != nil {
					return nil, err
				}
				return credential, nil
			}
			if respectSchedule && latest.RefreshDueAt != nil && latest.RefreshDueAt.After(currentTime) {
				return latest, nil
			}
			if force && !bypassCooldown && s.credentialRefreshCoolingDown(latest, currentTime) {
				return latest, nil
			}
			if latest.EncryptedAccessToken != "" && latest.EncryptedAccessToken != value.EncryptedAccessToken {
				return latest, nil
			}
			if !force && latest.EncryptedAccessToken != "" && !latest.ExpiresAt.IsZero() && currentTime.Add(credentialRefreshAdvance).Before(latest.ExpiresAt) {
				return latest, nil
			}
		}
		adapter, ok := s.providers.CredentialRefresh(latest.Provider)
		if !ok {
			return nil, fmt.Errorf("Provider %s 未注册", latest.Provider)
		}
		refreshed, err := adapter.RefreshCredential(ctx, latest)
		if err != nil {
			persistCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), credentialRefreshStateTTL)
			s.recordCredentialRefreshFailure(persistCtx, latest, err)
			cancel()
			return nil, err
		}
		updated, err := s.accounts.UpdateTokens(ctx, latest.ID, refreshed.EncryptedAccessToken, refreshed.EncryptedRefreshToken, refreshed.ExpiresAt)
		if err != nil {
			return nil, err
		}
		s.invalidateBuildBotFlagCache()
		s.markRefreshSuccess(latest.ID, currentTime)
		s.WakeCredentialRefresh()
		return updated, nil
	})
	if err != nil {
		return accountdomain.Credential{}, err
	}
	credential, ok := result.(accountdomain.Credential)
	if !ok {
		return accountdomain.Credential{}, fmt.Errorf("账号凭据刷新返回类型无效")
	}
	return credential, nil
}

// acquireRefreshLock 在 Redis 模式下等待其他实例完成刷新，锁租约过期后可自动接管。
func (s *Service) acquireRefreshLock(ctx context.Context, accountID uint64) (func(), error) {
	if s.refreshLock == nil {
		return nil, nil
	}
	key := "credential-refresh:" + strconv.FormatUint(accountID, 10)
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		release, acquired, err := s.refreshLock.Acquire(ctx, key, 2*time.Minute)
		if err != nil {
			return nil, err
		}
		if acquired {
			return release, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

func (s *Service) RefreshToken(ctx context.Context, id uint64) (View, error) {
	value, err := s.accounts.Get(ctx, id)
	if err != nil {
		return View{}, mapRepositoryError(err)
	}
	if _, err := s.ensureCredential(ctx, value, true, true, false); err != nil {
		return View{}, err
	}
	return s.Get(ctx, id)
}

func (s *Service) refreshCoolingDown(accountID uint64, now time.Time) bool {
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()
	last := s.lastRefreshAt[accountID]
	return !last.IsZero() && now.Sub(last) < forcedRefreshMinInterval
}

func (s *Service) credentialRefreshCoolingDown(credential accountdomain.Credential, now time.Time) bool {
	if credential.LastRefreshAt != nil {
		age := now.Sub(*credential.LastRefreshAt)
		if age >= 0 && age < forcedRefreshMinInterval {
			return true
		}
	}
	return s.refreshCoolingDown(credential.ID, now)
}

func (s *Service) markRefreshSuccess(accountID uint64, now time.Time) {
	s.refreshMu.Lock()
	s.lastRefreshAt[accountID] = now
	s.refreshMu.Unlock()
}

func (s *Service) clearRefreshState(accountID uint64) {
	s.refreshMu.Lock()
	delete(s.lastRefreshAt, accountID)
	s.refreshMu.Unlock()
}

// recordCredentialRefreshFailure persists refresh outcome into the existing credential scheduler
// (refresh_due_at + WakeCredentialRefresh). O2: no new queue/loop — recoverable failures only
// re-arm the DB-driven RunCredentialRefresh timer.
//
// Classification:
//   - client cancel: drop (do not poison schedule)
//   - transport/timeout/oauth_unavailable: non-permanent → backoff due + Wake
//   - credential_decrypt_failed: recoverable even if adapter marks Permanent
//   - true permanent (invalid_grant…): stick permanent; if access token still valid schedule at
//     ExpiresAt then converge to reauth; if expired MarkReauthRequired immediately
//   - prior true permanent sticks across later non-recoverable codes until success clears it
func (s *Service) recordCredentialRefreshFailure(ctx context.Context, credential accountdomain.Credential, refreshErr error) {
	if errors.Is(refreshErr, context.Canceled) || errors.Is(refreshErr, context.DeadlineExceeded) && errors.Is(ctx.Err(), context.Canceled) {
		return
	}
	failureCount := credential.RefreshFailureCount + 1
	errorCode := "oauth_transport_error"
	permanent := false
	retryAfter := time.Duration(0)
	var typed *provider.CredentialRefreshError
	if errors.As(refreshErr, &typed) {
		errorCode = strings.TrimSpace(typed.Code)
		if errorCode == "" {
			errorCode = "oauth_refresh_error"
		}
		permanent = typed.Permanent
		retryAfter = typed.RetryAfter
	} else if errors.Is(refreshErr, context.DeadlineExceeded) {
		errorCode = "oauth_timeout"
	}
	// True OAuth permanent failures (invalid_grant, …) clear only on successful token rotation.
	// credential_decrypt_failed is a recoverable local error: never promote it to permanent, and
	// never let a prior true permanent stick when this code is the current failure.
	if permanent && isRecoverableRefreshErrorCode(errorCode) {
		permanent = false
	}
	if credential.RefreshPermanent && !isRecoverableRefreshErrorCode(credential.LastRefreshErrorCode) && !isRecoverableRefreshErrorCode(errorCode) {
		permanent = true
	}
	now := s.now()
	retryAt := now.Add(credentialRefreshBackoff(credential.ID, failureCount, retryAfter))
	accessTokenAlive := credential.EncryptedAccessToken != "" && !credential.ExpiresAt.IsZero() && credential.ExpiresAt.After(now)
	if permanent && accessTokenAlive {
		// Refresh token is dead; early retries are useless. Re-check at access-token expiry.
		retryAt = credential.ExpiresAt
	} else if permanent {
		retryAt = now
	}
	if err := s.accounts.UpdateCredentialRefreshFailure(ctx, credential.ID, failureCount, retryAt, errorCode, permanent); err != nil {
		s.logger.Warn("credential_refresh_state_write_failed", "account_id", credential.ID, "error", err)
	}
	if permanent && accessTokenAlive {
		s.logger.Warn("credential_refresh_permanent_but_token_alive", "account_id", credential.ID, "error_code", errorCode, "expires_at", credential.ExpiresAt, "retry_at", retryAt)
		s.WakeCredentialRefresh()
		return
	}
	if permanent {
		if credential.Provider == accountdomain.ProviderBuild {
			linked := credential.LinkedAccountID
			if linked == 0 {
				if latest, getErr := s.accounts.Get(ctx, credential.ID); getErr == nil {
					linked = latest.LinkedAccountID
				}
			}
			if linked != 0 {
				s.EnqueueBuildCLIConvert(credential.ID)
				s.WakeCLIWarm()
				// Do not MarkReauthRequired on Build when SSO convert may revive; Web stays usable.
				return
			}
		}
		if err := s.MarkReauthRequired(ctx, credential.ID, "OAuth refresh failed: "+errorCode); err != nil {
			s.logger.Warn("credential_refresh_reauth_mark_failed", "account_id", credential.ID, "error", err)
		}
		return
	}
	s.logger.Warn("credential_refresh_deferred", "account_id", credential.ID, "failure_count", failureCount, "retry_at", retryAt, "error_code", errorCode)
	s.WakeCredentialRefresh()
}

// resolvePermanentRefreshFailure 阻止再次请求已确认失效的 refresh token，并在 access token 到期后收敛账号状态。
// credential_decrypt_failed 属于本地密钥问题，允许手动 force / 调度重试（密钥恢复后可自愈）；
// invalid_grant 等真正 OAuth 永久失败仍保持阻断。
func (s *Service) resolvePermanentRefreshFailure(ctx context.Context, credential accountdomain.Credential, now time.Time, force bool) (accountdomain.Credential, error, bool) {
	if !credential.RefreshPermanent {
		return accountdomain.Credential{}, nil, false
	}
	if isRecoverableRefreshErrorCode(credential.LastRefreshErrorCode) {
		// 允许 force 或到期调度再次尝试解密/刷新；成功后会 clear permanent 标记。
		return accountdomain.Credential{}, nil, false
	}
	accessTokenAlive := credential.EncryptedAccessToken != "" && !credential.ExpiresAt.IsZero() && credential.ExpiresAt.After(now)
	if accessTokenAlive && !force {
		return credential, nil, true
	}
	if !accessTokenAlive {
		// Build with linked Web: async Convert revive instead of parking as reauth (Web untouched).
		if credential.Provider == accountdomain.ProviderBuild {
			// Ensure LinkedAccountID is present (caller may pass routing candidate without links).
			linked := credential.LinkedAccountID
			if linked == 0 {
				if latest, getErr := s.accounts.Get(ctx, credential.ID); getErr == nil {
					linked = latest.LinkedAccountID
				}
			}
			if linked != 0 {
				s.EnqueueBuildCLIConvert(credential.ID)
				s.WakeCLIWarm()
				if credential.LastRefreshErrorCode == "" {
					return accountdomain.Credential{}, ErrCredentialRefreshPermanent, true
				}
				return accountdomain.Credential{}, fmt.Errorf("%w: %s", ErrCredentialRefreshPermanent, credential.LastRefreshErrorCode), true
			}
		}
		if err := s.MarkReauthRequired(ctx, credential.ID, permanentRefreshExpiredReason); err != nil {
			return accountdomain.Credential{}, err, true
		}
	}
	if credential.LastRefreshErrorCode == "" {
		return accountdomain.Credential{}, ErrCredentialRefreshPermanent, true
	}
	return accountdomain.Credential{}, fmt.Errorf("%w: %s", ErrCredentialRefreshPermanent, credential.LastRefreshErrorCode), true
}

// isRecoverableRefreshErrorCode marks local/self-heal errors that must never stick as true
// permanent OAuth death. Transport/timeout codes are NOT listed here: they are already
// non-permanent via typed.Permanent=false, and listing them would clear a prior invalid_grant
// sticky permanent on a later 503/timeout write.
func isRecoverableRefreshErrorCode(code string) bool {
	switch strings.TrimSpace(code) {
	case "credential_decrypt_failed":
		return true
	default:
		return false
	}
}

func credentialRefreshBackoff(accountID uint64, failureCount int, retryAfter time.Duration) time.Duration {
	delays := [...]time.Duration{30 * time.Second, 2 * time.Minute, 5 * time.Minute, 10 * time.Minute, 15 * time.Minute}
	index := max(0, min(failureCount-1, len(delays)-1))
	delay := delays[index]
	if retryAfter > delay {
		delay = min(retryAfter, 30*time.Minute)
	}
	return delay + time.Duration((accountID*37)%16)*time.Second
}

func (s *Service) RefreshBilling(ctx context.Context, id uint64) (accountdomain.Billing, error) {
	result, err, _ := s.billingSyncs.Do(strconv.FormatUint(id, 10), func() (any, error) {
		return s.refreshBilling(ctx, id)
	})
	if err != nil {
		return accountdomain.Billing{}, err
	}
	billing, ok := result.(accountdomain.Billing)
	if !ok {
		return accountdomain.Billing{}, fmt.Errorf("额度同步返回类型无效")
	}
	return billing, nil
}

func (s *Service) refreshBilling(ctx context.Context, id uint64) (accountdomain.Billing, error) {
	value, billing, err := s.fetchAndSaveBilling(ctx, id)
	if err != nil {
		return accountdomain.Billing{}, err
	}
	if err := s.reconcilePaidQuotaRecovery(ctx, value, billing, false); err != nil {
		return accountdomain.Billing{}, err
	}
	return billing, nil
}

func (s *Service) fetchAndSaveBilling(ctx context.Context, id uint64) (accountdomain.Credential, accountdomain.Billing, error) {
	value, err := s.accounts.Get(ctx, id)
	if err != nil {
		return accountdomain.Credential{}, accountdomain.Billing{}, mapRepositoryError(err)
	}
	value, err = s.EnsureCredential(ctx, value, false)
	if err != nil {
		return accountdomain.Credential{}, accountdomain.Billing{}, err
	}
	adapter, ok := s.providers.Billing(value.Provider)
	if !ok {
		return accountdomain.Credential{}, accountdomain.Billing{}, fmt.Errorf("Provider %s 未注册", value.Provider)
	}
	billing, err := adapter.GetBilling(ctx, value)
	if err != nil {
		return accountdomain.Credential{}, accountdomain.Billing{}, err
	}
	billing.AccountID = id
	if err := s.accounts.SaveBilling(ctx, billing); err != nil {
		return accountdomain.Credential{}, accountdomain.Billing{}, err
	}
	return value, billing, nil
}

// ProbePaidQuota 在真实账期到期后执行一次 Billing 探测，不消耗模型额度。
func (s *Service) ProbePaidQuota(ctx context.Context, value accountdomain.Credential) (bool, error) {
	latest, billing, err := s.fetchAndSaveBilling(ctx, value.ID)
	if err != nil {
		now := time.Now().UTC()
		next := now.Add(paidProbeRetryInterval)
		_ = s.accounts.SaveQuotaRecovery(ctx, accountdomain.QuotaRecovery{AccountID: value.ID, Kind: accountdomain.QuotaRecoveryKindPaid, Status: accountdomain.QuotaRecoveryStatusExhausted, NextProbeAt: &next, UpdatedAt: now})
		return false, err
	}
	if err := s.reconcilePaidQuotaRecovery(ctx, latest, billing, true); err != nil {
		return false, err
	}
	return !billing.IsExhausted(latest.MinimumRemaining), nil
}

func (s *Service) reconcilePaidQuotaRecovery(ctx context.Context, credential accountdomain.Credential, billing accountdomain.Billing, afterProbe bool) error {
	if !billing.IsPaid() || !billing.IsExhausted(credential.MinimumRemaining) {
		recovery, err := s.accounts.GetQuotaRecovery(ctx, credential.ID)
		if errors.Is(err, repository.ErrNotFound) || (err == nil && recovery.Kind != accountdomain.QuotaRecoveryKindPaid) {
			return nil
		}
		if err != nil {
			return err
		}
		return s.accounts.ClearQuotaRecovery(ctx, credential.ID)
	}
	periodEnd, ok := billing.PeriodEnd()
	if !ok {
		return nil
	}
	now := time.Now().UTC()
	next := periodEnd
	if !next.After(now) && afterProbe {
		next = now.Add(paidProbeRetryInterval)
	}
	exhaustedAt := now
	return s.accounts.SaveQuotaRecovery(ctx, accountdomain.QuotaRecovery{
		AccountID: credential.ID, Kind: accountdomain.QuotaRecoveryKindPaid, Status: accountdomain.QuotaRecoveryStatusExhausted,
		ExhaustedAt: &exhaustedAt, NextProbeAt: &next, LastConfirmedAt: &now, UpdatedAt: now,
	})
}

// HasBillingSnapshot 判断账号是否已经完成过一次额度同步，不触发任何上游请求。
func (s *Service) HasBillingSnapshot(ctx context.Context, id uint64) (bool, error) {
	_, err := s.accounts.GetBilling(ctx, id)
	if errors.Is(err, repository.ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}

func (s *Service) HasQuotaWindows(ctx context.Context, id uint64) (bool, error) {
	return s.accounts.HasQuotaWindows(ctx, id)
}

func (s *Service) DecrementQuota(ctx context.Context, id uint64, mode string, amount int) (bool, error) {
	if amount <= 0 {
		amount = 1
	}
	if repository, ok := s.accounts.(interface {
		DecrementQuotaWindowBy(context.Context, uint64, string, int, time.Time) (bool, error)
	}); ok {
		return repository.DecrementQuotaWindowBy(ctx, id, mode, amount, s.now())
	}
	updated := false
	for range amount {
		decremented, err := s.accounts.DecrementQuotaWindow(ctx, id, mode, s.now())
		if err != nil {
			return updated, err
		}
		if !decremented {
			break
		}
		updated = true
	}
	return updated, nil
}

func (s *Service) DecrementWebQuota(ctx context.Context, id uint64, mode string, amount int) (bool, error) {
	return s.DecrementQuota(ctx, id, mode, amount)
}

func (s *Service) ExhaustQuota(ctx context.Context, id uint64, mode string, resetAt *time.Time) error {
	if resetAt == nil {
		windows, err := s.accounts.GetQuotaWindows(ctx, []uint64{id})
		if err == nil {
			for _, window := range windows[id] {
				if window.Mode != mode {
					continue
				}
				resetAt = quotaRecoveryDueAt(window, s.now(), true)
				break
			}
		}
	}
	if err := s.accounts.ExhaustQuotaWindow(ctx, id, mode, resetAt, s.now()); err != nil {
		return err
	}
	if resetAt != nil && s.quotaQueue != nil {
		return s.quotaQueue.ScheduleQuotaRecovery(ctx, accountdomain.QuotaRecoveryEvent{AccountID: id, Mode: mode, DueAt: *resetAt})
	}
	return nil
}

func (s *Service) ExhaustWebQuota(ctx context.Context, id uint64, mode string, resetAt *time.Time) error {
	return s.ExhaustQuota(ctx, id, mode, resetAt)
}

func (s *Service) RefreshQuota(ctx context.Context, id uint64) ([]accountdomain.QuotaWindow, error) {
	result, err, _ := s.quotaSyncs.Do("all:"+strconv.FormatUint(id, 10), func() (any, error) {
		return s.refreshQuota(ctx, id)
	})
	if err != nil {
		return nil, err
	}
	refreshed, ok := result.(quotaRefreshResult)
	if !ok {
		return nil, fmt.Errorf("Provider 额度同步返回类型无效")
	}
	if err := s.reconcileQuotaRecoveryWindows(ctx, refreshed.Credential.Provider, id, refreshed.Windows); err != nil {
		return refreshed.Windows, err
	}
	// 身份补全是非关键操作：只在额度落库和恢复任务调度完成后执行，
	// 并沿用调用方取消语义，不能反向影响额度同步结果。
	value := refreshed.Credential
	if (value.Provider == accountdomain.ProviderWeb || value.Provider == accountdomain.ProviderConsole) && ctx.Err() == nil {
		if strings.TrimSpace(value.UserID) == "" && strings.TrimSpace(value.Email) == "" {
			if identityErr := s.syncAccountIdentityBestEffort(ctx, id); errors.Is(identityErr, provider.ErrUnauthorized) {
				return refreshed.Windows, identityErr
			}
		} else {
			// 已有 Session 身份时只做本地增量关联，不再访问上游。
			s.reconcileProviderLinksBestEffort(ctx, id)
		}
	}
	return refreshed.Windows, nil
}

func (s *Service) RefreshWebQuota(ctx context.Context, id uint64) ([]accountdomain.QuotaWindow, error) {
	return s.RefreshQuota(ctx, id)
}

func (s *Service) refreshQuota(ctx context.Context, id uint64) (quotaRefreshResult, error) {
	value, err := s.accounts.Get(ctx, id)
	if err != nil {
		return quotaRefreshResult{}, mapRepositoryError(err)
	}
	adapter, ok := s.providers.Quota(value.Provider)
	if !ok {
		return quotaRefreshResult{}, fmt.Errorf("%s Quota Provider 未注册", value.Provider)
	}
	snapshot, err := adapter.SyncQuota(ctx, value)
	if err != nil {
		if errors.Is(err, provider.ErrUnauthorized) {
			err = errors.Join(err, s.markSSOCredentialRejected(ctx, value, fmt.Sprintf("%s SSO credential rejected", value.Provider)))
		}
		return quotaRefreshResult{}, err
	}
	quotaKind, _ := s.providers.QuotaKind(value.Provider)
	if quotaKind == provider.QuotaLocalWindow {
		existing, loadErr := s.accounts.GetQuotaWindows(ctx, []uint64{id})
		if loadErr != nil {
			return quotaRefreshResult{}, loadErr
		}
		snapshot.Windows = preserveActiveQuotaWindows(existing[id], snapshot.Windows, s.now())
	}
	if err := s.accounts.ReplaceQuotaWindows(ctx, id, snapshot.Tier, snapshot.SyncedAt, snapshot.Windows); err != nil {
		return quotaRefreshResult{}, err
	}
	return quotaRefreshResult{Credential: value, Windows: snapshot.Windows}, nil
}

func preserveActiveQuotaWindows(existing, incoming []accountdomain.QuotaWindow, now time.Time) []accountdomain.QuotaWindow {
	byMode := make(map[string]accountdomain.QuotaWindow, len(existing))
	for _, window := range existing {
		byMode[window.Mode] = window
	}
	result := append([]accountdomain.QuotaWindow(nil), incoming...)
	for index, window := range result {
		current, ok := byMode[window.Mode]
		if !ok || current.ResetAt == nil || !current.ResetAt.After(now) {
			continue
		}
		result[index] = current
	}
	return result
}

// ReconcileRateLimit 根据额度模式核实 429；Web 周池继续以上游快照为准。
func (s *Service) ReconcileRateLimit(ctx context.Context, id uint64, mode string, retryAfter time.Duration) (bool, error) {
	if mode == "weekly" {
		window, err := s.RefreshQuotaMode(ctx, id, mode)
		if err != nil {
			return false, err
		}
		return window.Remaining == 0 || window.UsagePercent >= 100, nil
	}
	var resetAt *time.Time
	if retryAfter > 0 {
		value := s.now().Add(retryAfter)
		resetAt = &value
	}
	if err := s.ExhaustQuota(ctx, id, mode, resetAt); err != nil {
		return false, err
	}
	return true, nil
}

func (s *Service) ReconcileWebRateLimit(ctx context.Context, id uint64, mode string, retryAfter time.Duration) (bool, error) {
	return s.ReconcileRateLimit(ctx, id, mode, retryAfter)
}

func (s *Service) RefreshQuotaMode(ctx context.Context, id uint64, mode string) (accountdomain.QuotaWindow, error) {
	mode = strings.TrimSpace(mode)
	key := quotaSyncKey(id, mode)
	result, err, _ := s.quotaSyncs.Do(key, func() (any, error) {
		return s.refreshQuotaMode(ctx, id, mode)
	})
	if err != nil {
		return accountdomain.QuotaWindow{}, err
	}
	refreshed, ok := result.(quotaRefreshResult)
	if !ok {
		return accountdomain.QuotaWindow{}, fmt.Errorf("Provider 模式额度同步返回类型无效")
	}
	window, ok := quotaWindowByMode(refreshed.Windows, mode)
	if !ok {
		return accountdomain.QuotaWindow{}, fmt.Errorf("Provider usage 响应缺少 %s 额度", mode)
	}
	if err := s.reconcileQuotaRecoveryWindow(ctx, refreshed.Credential.Provider, id, window); err != nil {
		return window, err
	}
	return window, nil
}

// ProbeQuotaMode refreshes a claimed recovery event without scheduling a
// second event for the same account and mode. The recovery worker owns the
// current claim and is responsible for acknowledging or rescheduling it.
func (s *Service) ProbeQuotaMode(ctx context.Context, id uint64, mode string) (accountdomain.QuotaWindow, error) {
	mode = strings.TrimSpace(mode)
	key := quotaSyncKey(id, mode)
	result, err, _ := s.quotaSyncs.Do(key, func() (any, error) {
		return s.refreshQuotaMode(ctx, id, mode)
	})
	if err != nil {
		return accountdomain.QuotaWindow{}, err
	}
	refreshed, ok := result.(quotaRefreshResult)
	if !ok {
		return accountdomain.QuotaWindow{}, fmt.Errorf("Provider 模式额度探测返回类型无效")
	}
	window, ok := quotaWindowByMode(refreshed.Windows, mode)
	if !ok {
		return accountdomain.QuotaWindow{}, fmt.Errorf("Provider usage 响应缺少 %s 额度", mode)
	}
	return window, nil
}

func (s *Service) refreshQuotaMode(ctx context.Context, id uint64, mode string) (quotaRefreshResult, error) {
	value, err := s.accounts.Get(ctx, id)
	if err != nil {
		return quotaRefreshResult{}, mapRepositoryError(err)
	}
	adapter, ok := s.providers.Quota(value.Provider)
	if !ok {
		return quotaRefreshResult{}, fmt.Errorf("%s Quota Provider 未注册", value.Provider)
	}
	var window accountdomain.QuotaWindow
	var windows []accountdomain.QuotaWindow
	var syncedAt time.Time
	var tier accountdomain.WebTier
	if value.Provider == accountdomain.ProviderConsole {
		// Console /usage always returns Chat, Image and Video together. Persist the
		// response as one authoritative snapshot so informational media quotas do
		// not remain stale while only Chat participates in routing and recovery.
		var snapshot provider.QuotaSnapshot
		snapshot, err = adapter.SyncQuota(ctx, value)
		if err == nil {
			windows = snapshot.Windows
			syncedAt = snapshot.SyncedAt
			for _, candidate := range windows {
				if candidate.Mode == mode {
					window = candidate
					break
				}
			}
			if window.Mode == "" {
				err = fmt.Errorf("Console usage 响应缺少 %s 额度", mode)
			}
		}
	} else {
		window, err = adapter.SyncQuotaMode(ctx, value, mode)
		windows = []accountdomain.QuotaWindow{window}
		syncedAt = s.now()
	}
	if err != nil {
		if errors.Is(err, provider.ErrUnauthorized) {
			err = errors.Join(err, s.markSSOCredentialRejected(ctx, value, fmt.Sprintf("%s SSO credential rejected", value.Provider)))
		}
		return quotaRefreshResult{}, err
	}
	quotaKind, _ := s.providers.QuotaKind(value.Provider)
	if quotaKind == provider.QuotaRemoteWindow {
		// Web reconciliation updates one mode; Console already supplied and
		// persisted its complete /usage snapshot above.
		tier = value.WebTier
	}
	if syncedAt.IsZero() {
		syncedAt = s.now()
	}
	if value.Provider == accountdomain.ProviderConsole {
		if err := s.accounts.ReplaceQuotaWindows(ctx, id, tier, syncedAt, windows); err != nil {
			return quotaRefreshResult{}, err
		}
	} else if err := s.accounts.SaveQuotaWindows(ctx, id, tier, syncedAt, windows); err != nil {
		return quotaRefreshResult{}, err
	}
	return quotaRefreshResult{Credential: value, Windows: windows}, nil
}

func quotaSyncKey(accountID uint64, mode string) string {
	mode = strings.TrimSpace(mode)
	if mode == "console" || mode == "console_image" || mode == "console_video" {
		return "all:" + strconv.FormatUint(accountID, 10)
	}
	return mode + ":" + strconv.FormatUint(accountID, 10)
}

func quotaWindowByMode(windows []accountdomain.QuotaWindow, mode string) (accountdomain.QuotaWindow, bool) {
	for _, window := range windows {
		if window.Mode == mode {
			return window, true
		}
	}
	return accountdomain.QuotaWindow{}, false
}

func (s *Service) reconcileQuotaRecoveryWindows(ctx context.Context, providerValue accountdomain.Provider, accountID uint64, windows []accountdomain.QuotaWindow) error {
	for _, window := range windows {
		if err := s.reconcileQuotaRecoveryWindow(ctx, providerValue, accountID, window); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) reconcileQuotaRecoveryWindow(ctx context.Context, providerValue accountdomain.Provider, accountID uint64, window accountdomain.QuotaWindow) error {
	if s.quotaQueue == nil || !quotaWindowControlsRouting(providerValue, window.Mode) {
		return nil
	}
	if dueAt := quotaRecoveryDueAt(window, s.now(), window.Remaining == 0); dueAt != nil {
		if err := s.quotaQueue.ScheduleQuotaRecovery(ctx, accountdomain.QuotaRecoveryEvent{AccountID: accountID, Mode: window.Mode, DueAt: *dueAt}); err != nil {
			return fmt.Errorf("安排额度恢复事件: %w", err)
		}
		return nil
	}
	if err := s.quotaQueue.CancelQuotaRecovery(ctx, accountID, window.Mode); err != nil {
		return fmt.Errorf("取消额度恢复事件: %w", err)
	}
	return nil
}

// quotaRecoveryDueAt keeps upstream quota exhaustion recoverable even when
// the Provider reports no reset timestamp. Console uses a conservative
// predicted 24-hour probe window; generic remote windows retain the shorter
// fallback and transport failures use the recovery queue's bounded backoff.
func quotaRecoveryDueAt(window accountdomain.QuotaWindow, now time.Time, exhausted bool) *time.Time {
	if !exhausted {
		return nil
	}
	if window.ResetAt != nil && window.ResetAt.After(now) {
		value := *window.ResetAt
		return &value
	}
	if window.Mode == "console" {
		value := now.Add(consolePredictedQuotaProbeDelay)
		return &value
	}
	if window.Source == accountdomain.QuotaSourceUpstream {
		value := now.Add(unknownRemoteQuotaProbeDelay)
		return &value
	}
	return nil
}

// QueueQuotaRefresh asynchronously refreshes the remote quota window after a successful request.
func (s *Service) QueueQuotaRefresh(id uint64, mode string) {
	mode = strings.TrimSpace(mode)
	if id == 0 || (mode != "console" && mode != "weekly" && !isWebChatQuotaMode(mode)) {
		return
	}
	key := strconv.FormatUint(id, 10) + ":" + mode
	s.quotaRefreshMu.Lock()
	state := s.quotaRefreshes[key]
	now := s.now().UTC()
	if state != nil && !state.pending && !state.queued && !state.running && !now.Before(state.nextAttemptAt) {
		delete(s.quotaRefreshes, key)
		state = nil
	}
	if state == nil {
		state = &quotaRefreshState{}
		s.quotaRefreshes[key] = state
	}
	state.generation++
	state.pending = true
	enqueued := state.queued || state.running || now.Before(state.nextAttemptAt) || s.enqueueQuotaRefreshLocked(quotaRefreshRequest{key: key, accountID: id, mode: mode}, state)
	s.quotaRefreshMu.Unlock()
	if !enqueued {
		perfmetrics.Default.Add("quota_refresh_events", perfmetrics.Labels{Subsystem: "quota", Stage: "enqueue", Outcome: "queue_full"}, 1)
		s.logger.Warn("quota_refresh_queue_full", "account_id", id, "mode", mode)
		s.wakeQuotaRefreshRecovery()
	}
}

func (s *Service) enqueueQuotaRefreshLocked(request quotaRefreshRequest, state *quotaRefreshState) bool {
	if state == nil || state.queued || state.running {
		return state != nil
	}
	select {
	case s.quotaRefreshQueue <- request:
		state.queued = true
		return true
	default:
		return false
	}
}

func (s *Service) wakeQuotaRefreshRecovery() {
	select {
	case s.quotaRefreshWake <- struct{}{}:
	default:
	}
}

// RunQuotaRefresh uses a fixed worker set to avoid unbounded goroutine creation.
func (s *Service) RunQuotaRefresh(ctx context.Context) {
	var workers sync.WaitGroup
	workers.Add(managedTaskWorkerCeiling + 1)
	for range managedTaskWorkerCeiling {
		go func() {
			defer workers.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case request := <-s.quotaRefreshQueue:
					s.quotaRefreshMu.Lock()
					state := s.quotaRefreshes[request.key]
					if state == nil || state.running {
						s.quotaRefreshMu.Unlock()
						continue
					}
					state.queued = false
					state.running = true
					state.pending = false
					s.quotaRefreshMu.Unlock()
					if err := batch.Do(ctx, func(workCtx context.Context) error {
						s.runQuotaRefresh(workCtx, request)
						return nil
					}); err != nil {
						s.quotaRefreshMu.Lock()
						if state := s.quotaRefreshes[request.key]; state != nil {
							state.running = false
							state.pending = true
							state.failures++
							state.nextAttemptAt = s.now().UTC().Add(quotaRefreshRetryDelay(state.failures))
						}
						s.quotaRefreshMu.Unlock()
						s.wakeQuotaRefreshRecovery()
						if ctx.Err() == nil {
							var panicErr *batch.PanicError
							if errors.As(err, &panicErr) {
								s.logger.Error("quota_refresh_worker_panicked", "account_id", request.accountID, "mode", request.mode, "error", panicErr, "stack", string(panicErr.Stack))
							} else {
								s.logger.Error("quota_refresh_worker_failed", "account_id", request.accountID, "mode", request.mode, "error", err)
							}
						}
					}
				}
			}
		}()
	}
	go func() {
		defer workers.Done()
		s.runQuotaRefreshRecovery(ctx)
	}()
	workers.Wait()
}

func (s *Service) runQuotaRefresh(parent context.Context, request quotaRefreshRequest) {
	for {
		s.quotaRefreshMu.Lock()
		state := s.quotaRefreshes[request.key]
		if state == nil {
			s.quotaRefreshMu.Unlock()
			return
		}
		localGeneration := state.generation
		publishedGeneration := state.publishedGeneration
		sharedGeneration := state.sharedGeneration
		state.pending = false
		s.quotaRefreshMu.Unlock()

		ctx, cancel := context.WithTimeout(parent, quotaRefreshTimeout)
		if s.quotaRefreshState != nil && publishedGeneration < localGeneration {
			generation, err := s.quotaRefreshState.MarkQuotaRefreshDirty(ctx, request.accountID, request.mode, quotaRefreshDirtyTTL)
			if err != nil {
				cancel()
				s.deferQuotaRefresh(request.key)
				perfmetrics.Default.Add("quota_refresh_events", perfmetrics.Labels{Subsystem: "quota", Stage: "publish", Outcome: "failed"}, 1)
				s.logger.Warn("quota_refresh_dirty_publish_failed", "account_id", request.accountID, "mode", request.mode, "error", err)
				return
			}
			sharedGeneration = generation
			s.quotaRefreshMu.Lock()
			if current := s.quotaRefreshes[request.key]; current != nil && current.publishedGeneration < localGeneration {
				current.publishedGeneration = localGeneration
				current.sharedGeneration = generation
			}
			s.quotaRefreshMu.Unlock()
		}
		if s.quotaRefreshState != nil && publishedGeneration >= localGeneration && sharedGeneration > 0 {
			generation, dirty, err := s.quotaRefreshState.QuotaRefreshGeneration(ctx, request.accountID, request.mode)
			if err != nil {
				cancel()
				s.deferQuotaRefresh(request.key)
				return
			}
			if generation > sharedGeneration {
				sharedGeneration = generation
				s.quotaRefreshMu.Lock()
				if current := s.quotaRefreshes[request.key]; current != nil {
					current.sharedGeneration = generation
				}
				s.quotaRefreshMu.Unlock()
			}
			if !dirty && generation == sharedGeneration {
				cancel()
				s.quotaRefreshMu.Lock()
				if current := s.quotaRefreshes[request.key]; current != nil && current.generation == localGeneration {
					delete(s.quotaRefreshes, request.key)
				}
				s.quotaRefreshMu.Unlock()
				return
			}
		}
		refreshMode := request.mode
		skipUpstream := false
		if windows, err := s.accounts.GetQuotaWindows(ctx, []uint64{request.accountID}); err == nil {
			if request.mode == "console" {
				for _, window := range windows[request.accountID] {
					if window.Mode == "console" && window.SyncedAt != nil && s.now().UTC().Sub(window.SyncedAt.UTC()) < consoleQuotaRefreshMinInterval {
						skipUpstream = true
						break
					}
				}
			} else {
				// Weekly remains a Grok Web capability. Console never inherits this
				// legacy mode and always refreshes its authoritative /usage snapshot.
				for _, window := range windows[request.accountID] {
					if window.Mode == "weekly" {
						refreshMode = "weekly"
						break
					}
				}
			}
		}
		var refreshErr error
		acquired := true
		var release func()
		if !skipUpstream && s.refreshLock != nil {
			effectiveKey := strconv.FormatUint(request.accountID, 10) + ":" + refreshMode
			release, acquired, refreshErr = s.refreshLock.Acquire(ctx, "quota-refresh:"+effectiveKey, quotaRefreshTimeout)
		}
		if !skipUpstream && refreshErr == nil && acquired {
			if err := s.syncPool.Do(ctx, func(workCtx context.Context) error {
				_, refreshErr = s.RefreshQuotaMode(workCtx, request.accountID, refreshMode)
				return refreshErr
			}); err != nil {
				refreshErr = err
			}
		}
		if release != nil {
			release()
		}
		cancel()
		if refreshErr != nil || !acquired {
			if refreshErr != nil && !errors.Is(refreshErr, context.Canceled) {
				s.logger.Warn("quota_refresh_failed", "account_id", request.accountID, "mode", refreshMode, "error", refreshErr)
			}
			s.deferQuotaRefresh(request.key)
			perfmetrics.Default.Add("quota_refresh_events", perfmetrics.Labels{Subsystem: "quota", Stage: "refresh", Outcome: "retry"}, 1)
			return
		}

		currentShared := sharedGeneration
		sharedDirty := s.quotaRefreshState != nil
		if s.quotaRefreshState != nil {
			generationCtx, generationCancel := context.WithTimeout(context.WithoutCancel(parent), 3*time.Second)
			var generationErr error
			currentShared, sharedDirty, generationErr = s.quotaRefreshState.QuotaRefreshGeneration(generationCtx, request.accountID, request.mode)
			generationCancel()
			if generationErr != nil {
				s.deferQuotaRefresh(request.key)
				return
			}
		}
		s.quotaRefreshMu.Lock()
		state = s.quotaRefreshes[request.key]
		localChanged := state != nil && state.generation != localGeneration
		s.quotaRefreshMu.Unlock()
		if localChanged || (s.quotaRefreshState != nil && currentShared != sharedGeneration) {
			perfmetrics.Default.Add("quota_refresh_events", perfmetrics.Labels{Subsystem: "quota", Stage: "refresh", Outcome: "trailing"}, 1)
			if request.mode == "console" {
				s.deferSuccessfulQuotaRefresh(request.key, true)
				return
			}
			continue
		}
		if s.quotaRefreshState != nil && sharedDirty {
			clearCtx, clearCancel := context.WithTimeout(context.WithoutCancel(parent), 3*time.Second)
			cleared, clearErr := s.quotaRefreshState.ClearQuotaRefreshDirty(clearCtx, request.accountID, request.mode, sharedGeneration)
			clearCancel()
			if clearErr != nil || !cleared {
				if clearErr != nil {
					s.logger.Warn("quota_refresh_dirty_clear_failed", "account_id", request.accountID, "mode", request.mode, "error", clearErr)
				}
				if request.mode == "console" {
					s.deferSuccessfulQuotaRefresh(request.key, true)
					return
				}
				continue
			}
		}
		s.quotaRefreshMu.Lock()
		state = s.quotaRefreshes[request.key]
		if state != nil && state.generation == localGeneration {
			if request.mode == "console" {
				state.running = false
				state.pending = false
				state.failures = 0
				state.nextAttemptAt = s.now().UTC().Add(consoleQuotaRefreshMinInterval)
			} else {
				delete(s.quotaRefreshes, request.key)
			}
			s.quotaRefreshMu.Unlock()
			perfmetrics.Default.Add("quota_refresh_events", perfmetrics.Labels{Subsystem: "quota", Stage: "refresh", Outcome: "success"}, 1)
			return
		}
		if request.mode == "console" && state != nil {
			state.running = false
			state.pending = true
			state.failures = 0
			state.nextAttemptAt = s.now().UTC().Add(consoleQuotaRefreshMinInterval)
			s.quotaRefreshMu.Unlock()
			s.wakeQuotaRefreshRecovery()
			return
		}
		s.quotaRefreshMu.Unlock()
	}
}

func (s *Service) deferQuotaRefresh(key string) {
	s.quotaRefreshMu.Lock()
	if state := s.quotaRefreshes[key]; state != nil {
		state.running = false
		state.pending = true
		state.failures++
		state.nextAttemptAt = s.now().UTC().Add(quotaRefreshRetryDelay(state.failures))
	}
	s.quotaRefreshMu.Unlock()
	s.wakeQuotaRefreshRecovery()
}

func (s *Service) deferSuccessfulQuotaRefresh(key string, pending bool) {
	s.quotaRefreshMu.Lock()
	if state := s.quotaRefreshes[key]; state != nil {
		state.running = false
		state.pending = pending
		state.failures = 0
		state.nextAttemptAt = s.now().UTC().Add(consoleQuotaRefreshMinInterval)
	}
	s.quotaRefreshMu.Unlock()
	s.wakeQuotaRefreshRecovery()
}

func quotaRefreshRetryDelay(failures int) time.Duration {
	if failures < 1 {
		failures = 1
	}
	shift := min(failures-1, 6)
	delay := quotaRefreshBackoffBase * time.Duration(1<<shift)
	if delay > quotaRefreshBackoffMax {
		delay = quotaRefreshBackoffMax
	}
	// Equal jitter keeps retries bounded away from zero while preventing a
	// shared upstream outage from synchronizing every account worker.
	half := delay / 2
	if half <= 0 {
		return delay
	}
	return half + time.Duration(rand.Int64N(int64(half)+1))
}

func (s *Service) runQuotaRefreshRecovery(ctx context.Context) {
	retryTicker := time.NewTicker(quotaRefreshPollInterval)
	sharedTicker := time.NewTicker(quotaRefreshSharedPoll)
	defer retryTicker.Stop()
	defer sharedTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.quotaRefreshWake:
			s.requeueQuotaRefreshes()
		case <-retryTicker.C:
			s.requeueQuotaRefreshes()
		case now := <-sharedTicker.C:
			s.recoverSharedQuotaRefreshes(ctx, now.UTC())
			s.requeueQuotaRefreshes()
		}
	}
}

func (s *Service) requeueQuotaRefreshes() {
	now := s.now().UTC()
	s.quotaRefreshMu.Lock()
	for key, state := range s.quotaRefreshes {
		if state == nil {
			delete(s.quotaRefreshes, key)
			continue
		}
		if !state.pending {
			if !state.queued && !state.running && !now.Before(state.nextAttemptAt) {
				delete(s.quotaRefreshes, key)
			}
			continue
		}
		if state.queued || state.running || now.Before(state.nextAttemptAt) {
			continue
		}
		separator := strings.IndexByte(key, ':')
		if separator <= 0 || separator == len(key)-1 {
			continue
		}
		accountID, err := strconv.ParseUint(key[:separator], 10, 64)
		if err != nil {
			continue
		}
		if !s.enqueueQuotaRefreshLocked(quotaRefreshRequest{key: key, accountID: accountID, mode: key[separator+1:]}, state) {
			break
		}
	}
	s.quotaRefreshMu.Unlock()
}

func (s *Service) recoverSharedQuotaRefreshes(parent context.Context, now time.Time) {
	if s.quotaRefreshState == nil {
		return
	}
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	values, err := s.quotaRefreshState.ListQuotaRefreshDirty(ctx, now, 100)
	cancel()
	if err != nil {
		s.logger.Warn("quota_refresh_dirty_list_failed", "error", err)
		return
	}
	s.quotaRefreshMu.Lock()
	for _, value := range values {
		key := strconv.FormatUint(value.AccountID, 10) + ":" + value.Mode
		state := s.quotaRefreshes[key]
		if state == nil {
			state = &quotaRefreshState{generation: 1, publishedGeneration: 1, sharedGeneration: value.Generation, pending: true}
			s.quotaRefreshes[key] = state
		} else {
			if value.Generation > state.sharedGeneration {
				state.sharedGeneration = value.Generation
			}
			state.pending = true
		}
		if !state.queued && !state.running && !now.Before(state.nextAttemptAt) && !s.enqueueQuotaRefreshLocked(quotaRefreshRequest{key: key, accountID: value.AccountID, mode: value.Mode}, state) {
			break
		}
	}
	s.quotaRefreshMu.Unlock()
}

func (s *Service) ListDueWebQuotaWindows(ctx context.Context, now time.Time, limit int) ([]accountdomain.QuotaWindow, error) {
	windows, err := s.ListDueQuotaWindows(ctx, now, limit)
	if err != nil {
		return nil, err
	}
	result := make([]accountdomain.QuotaWindow, 0, len(windows))
	for _, window := range windows {
		credential, getErr := s.accounts.Get(ctx, window.AccountID)
		if errors.Is(getErr, repository.ErrNotFound) {
			continue
		}
		if getErr != nil {
			return nil, getErr
		}
		if credential.Provider == accountdomain.ProviderWeb {
			result = append(result, window)
		}
	}
	return result, nil
}

func (s *Service) ListDueQuotaWindows(ctx context.Context, now time.Time, limit int) ([]accountdomain.QuotaWindow, error) {
	return s.accounts.ListDueQuotaWindows(ctx, now, limit)
}

func isWebChatQuotaMode(mode string) bool {
	switch mode {
	case "auto", "fast", "expert", "heavy":
		return true
	default:
		return false
	}
}

func quotaWindowControlsRouting(providerValue accountdomain.Provider, mode string) bool {
	// Console currently routes text responses only. Its image/video usage
	// windows are informational and must not quarantine or recover the account.
	return providerValue != accountdomain.ProviderConsole || mode == "console"
}

// SyncAllBilling 尽力刷新全部启用账号，单个账号失败不阻断其他账号。
func (s *Service) SyncAllBilling(ctx context.Context) (int, int, error) {
	return s.SyncAllBillingWithProgress(ctx, nil)
}

func (s *Service) SyncAllBillingWithProgress(ctx context.Context, progress BatchProgressObserver) (int, int, error) {
	if s.providers == nil {
		return 0, 0, fmt.Errorf("Provider 注册表未初始化")
	}
	ids := make([]uint64, 0)
	for _, providerValue := range s.providers.Providers() {
		quotaKind, ok := s.providers.QuotaKind(providerValue)
		if !ok || quotaKind != provider.QuotaBilling {
			continue
		}
		providerIDs, err := s.accounts.ListEnabledAccountIDs(ctx, providerValue, false)
		if err != nil {
			return 0, 0, err
		}
		ids = append(ids, providerIDs...)
	}
	return s.refreshBillings(ctx, ids, progress)
}

// SyncAllWebQuotas 尽力同步全部启用 Grok Web 账号的分模式额度。
func (s *Service) SyncAllWebQuotas(ctx context.Context) (int, int, error) {
	return s.SyncAllWebQuotasWithProgress(ctx, nil)
}

func (s *Service) SyncAllWebQuotasWithProgress(ctx context.Context, progress BatchProgressObserver) (int, int, error) {
	return s.syncAllQuotasWithProgress(ctx, accountdomain.ProviderWeb, "web_quota_sync", progress)
}

func (s *Service) SyncAllConsoleQuotas(ctx context.Context) (int, int, error) {
	return s.SyncAllConsoleQuotasWithProgress(ctx, nil)
}

func (s *Service) SyncAllConsoleQuotasWithProgress(ctx context.Context, progress BatchProgressObserver) (int, int, error) {
	return s.syncAllQuotasWithProgress(ctx, accountdomain.ProviderConsole, "console_quota_sync", progress)
}

// SyncIncompleteConsoleQuotas replaces pre-/usage synthetic windows and
// partial snapshots without refreshing accounts that already have all three
// authoritative Console quota kinds. It is safe to run periodically and uses
// the shared sync pool to preserve the deployment-wide upstream limit.
func (s *Service) SyncIncompleteConsoleQuotas(ctx context.Context) (int, int, error) {
	const batchSize = 1000
	var succeeded, failed int
	var afterID uint64
	for {
		values, _, err := s.accounts.ListProviderAccountBatch(ctx, accountdomain.ProviderConsole, afterID, batchSize)
		if err != nil {
			return succeeded, failed, err
		}
		if len(values) == 0 {
			return succeeded, failed, nil
		}
		ids := make([]uint64, 0, len(values))
		for _, value := range values {
			if value.Enabled && value.AuthStatus == accountdomain.AuthStatusActive {
				ids = append(ids, value.ID)
			}
		}
		windows, err := s.accounts.GetQuotaWindows(ctx, ids)
		if err != nil {
			return succeeded, failed, err
		}
		pending := make([]uint64, 0, len(ids))
		for _, id := range ids {
			if !completeConsoleUsageSnapshot(windows[id]) {
				pending = append(pending, id)
			}
		}
		var batchSucceeded, batchFailed int
		if len(pending) > 0 {
			batchSucceeded, batchFailed, err = s.runAccountBatch(ctx, "console_usage_migration", pending, s.syncPool, nil, func(workCtx context.Context, id uint64) error {
				var release func()
				if s.refreshLock != nil {
					var acquired bool
					var lockErr error
					release, acquired, lockErr = s.refreshLock.Acquire(workCtx, "quota-refresh:"+strconv.FormatUint(id, 10)+":console", 2*quotaRefreshTimeout)
					if lockErr != nil {
						return lockErr
					}
					if !acquired {
						return errQuotaRefreshBusy
					}
					defer release()
				}
				_, refreshErr := s.RefreshQuotaMode(workCtx, id, "console")
				return refreshErr
			})
		}
		succeeded += batchSucceeded
		failed += batchFailed
		if err != nil {
			return succeeded, failed, err
		}
		afterID = values[len(values)-1].ID
		if len(values) < batchSize {
			return succeeded, failed, nil
		}
	}
}

func completeConsoleUsageSnapshot(windows []accountdomain.QuotaWindow) bool {
	var present uint8
	for _, window := range windows {
		if window.Source != accountdomain.QuotaSourceUpstream || window.SyncedAt == nil {
			continue
		}
		switch window.Mode {
		case "console":
			present |= 1
		case "console_image":
			present |= 2
		case "console_video":
			present |= 4
		}
	}
	return present == 7
}

func (s *Service) syncAllQuotasWithProgress(ctx context.Context, providerValue accountdomain.Provider, operation string, progress BatchProgressObserver) (int, int, error) {
	ids, err := s.accounts.ListEnabledAccountIDs(ctx, providerValue, false)
	if err != nil {
		return 0, 0, err
	}
	return s.runAccountBatch(ctx, operation, ids, s.syncPool, progress, func(workCtx context.Context, id uint64) error {
		_, err := s.RefreshQuota(workCtx, id)
		return err
	})
}

// SyncWebQuotaAccounts 同步指定 Web 账号集合，供启动追赶任务复用共享并发池。
func (s *Service) SyncWebQuotaAccounts(ctx context.Context, ids []uint64) (int, int, error) {
	return s.runAccountBatch(ctx, "web_quota_startup_catchup", ids, s.syncPool, nil, func(workCtx context.Context, id uint64) error {
		_, err := s.RefreshWebQuota(workCtx, id)
		return err
	})
}

// RefreshAllTokens 续期所有声明支持刷新的 Provider 凭据，不可续期账号会被跳过。
func (s *Service) RefreshAllTokens(ctx context.Context) (int, int, int, error) {
	return s.RefreshAllTokensWithProgress(ctx, nil)
}

func (s *Service) RefreshAllTokensWithProgress(ctx context.Context, progress BatchProgressObserver) (int, int, int, error) {
	if s.providers == nil {
		return 0, 0, 0, fmt.Errorf("Provider 注册表未初始化")
	}
	allIDs := make([]uint64, 0)
	ids := make([]uint64, 0)
	for _, providerValue := range s.providers.Providers() {
		if !s.providers.SupportsCredentialRefresh(providerValue) {
			continue
		}
		providerIDs, err := s.accounts.ListEnabledAccountIDs(ctx, providerValue, false)
		if err != nil {
			return 0, 0, 0, err
		}
		refreshableIDs, err := s.accounts.ListEnabledAccountIDs(ctx, providerValue, true)
		if err != nil {
			return 0, 0, 0, err
		}
		allIDs = append(allIDs, providerIDs...)
		ids = append(ids, refreshableIDs...)
	}
	skipped := max(0, len(allIDs)-len(ids))
	succeeded, failed, err := s.refreshTokens(ctx, ids, progress)
	return succeeded, failed, skipped, err
}

func (s *Service) refreshTokens(ctx context.Context, ids []uint64, progress BatchProgressObserver) (int, int, error) {
	return s.runAccountBatch(ctx, "credential_refresh", ids, s.refreshPool, progress, func(workCtx context.Context, id uint64) error {
		value, err := s.accounts.Get(workCtx, id)
		if err == nil {
			_, err = s.ensureCredential(workCtx, value, true, true, false)
		}
		return err
	})
}

// BatchRefreshTokens 续期指定账号的凭据；停用、失效或缺少刷新凭据的账号会被跳过。
func (s *Service) BatchRefreshTokens(ctx context.Context, ids []uint64) (int, int, int, error) {
	values, err := normalizeBatchIDs(ids)
	if err != nil {
		return 0, 0, 0, err
	}
	if s.providers == nil {
		return 0, 0, 0, fmt.Errorf("Provider 注册表未初始化")
	}
	refreshableIDs := make([]uint64, 0, len(values))
	for _, id := range values {
		value, getErr := s.accounts.Get(ctx, id)
		if getErr != nil {
			return 0, 0, 0, getErr
		}
		if !s.providers.SupportsCredentialRefresh(value.Provider) || !value.Enabled || value.AuthStatus != accountdomain.AuthStatusActive || value.EncryptedRefreshToken == "" {
			continue
		}
		refreshableIDs = append(refreshableIDs, id)
	}
	skipped := len(values) - len(refreshableIDs)
	succeeded, failed, err := s.refreshTokens(ctx, refreshableIDs, nil)
	return succeeded, failed, skipped, err
}

// BatchRefreshBilling 使用有限并发刷新选中账号，避免大量账号同步时串行阻塞或无界创建 goroutine。
func (s *Service) BatchRefreshBilling(ctx context.Context, ids []uint64) (int, int, error) {
	values, err := normalizeBatchIDs(ids)
	if err != nil {
		return 0, 0, err
	}
	return s.refreshBillings(ctx, values, nil)
}

// BatchResetQuotaState clears local Build quota recovery state without changing
// upstream billing snapshots or historical audit usage.
func (s *Service) BatchResetQuotaState(ctx context.Context, ids []uint64) (int, error) {
	values, err := normalizeIDs(ids, maxQuotaResetAccounts)
	if err != nil {
		return 0, err
	}
	for start := 0; start < len(values); start += quotaResetChunkSize {
		end := min(start+quotaResetChunkSize, len(values))
		count, countErr := s.accounts.CountProviderAccountsByIDs(ctx, accountdomain.ProviderBuild, values[start:end])
		if countErr != nil {
			return 0, countErr
		}
		if count != int64(end-start) {
			return 0, invalidInput("仅 Grok Build 账号支持手动重置额度状态")
		}
	}
	reset := 0
	for start := 0; start < len(values); start += quotaResetChunkSize {
		if err := ctx.Err(); err != nil {
			return reset, err
		}
		end := min(start+quotaResetChunkSize, len(values))
		if err := s.accounts.ResetQuotaState(ctx, accountdomain.ProviderBuild, values[start:end]); err != nil {
			return reset, err
		}
		reset += end - start
	}
	return reset, nil
}

// ResetAllBuildQuotaState clears local quota state for every enabled Build
// account without materializing the complete account ID set in memory.
func (s *Service) ResetAllBuildQuotaState(ctx context.Context) (int64, error) {
	return s.accounts.ResetProviderQuotaState(ctx, accountdomain.ProviderBuild, true)
}

// BatchRefreshQuota 使用有限并发同步选中 Web 或 Console 账号的额度窗口。
func (s *Service) BatchRefreshQuota(ctx context.Context, ids []uint64) (int, int, error) {
	values, err := normalizeBatchIDs(ids)
	if err != nil {
		return 0, 0, err
	}
	return s.runAccountBatch(ctx, "quota_sync", values, s.syncPool, nil, func(workCtx context.Context, id uint64) error {
		_, err := s.RefreshQuota(workCtx, id)
		return err
	})
}

func (s *Service) refreshBillings(ctx context.Context, ids []uint64, progress BatchProgressObserver) (int, int, error) {
	return s.runAccountBatch(ctx, "billing_sync", ids, s.syncPool, progress, func(workCtx context.Context, id uint64) error {
		_, err := s.RefreshBilling(workCtx, id)
		return err
	})
}

func (s *Service) runAccountBatch(ctx context.Context, operation string, ids []uint64, pool *batch.Pool, progress BatchProgressObserver, work func(context.Context, uint64) error) (int, int, error) {
	if progress != nil {
		if err := progress(0, len(ids)); err != nil {
			return 0, 0, err
		}
	}
	var progressMu sync.Mutex
	var progressErr error
	completed := 0
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results, summary, err := batch.MapObserved(runCtx, ids, batch.Options{Workers: pool.Limit(), Pool: pool}, func(workCtx context.Context, id uint64) (struct{}, error) {
		return struct{}{}, work(workCtx, id)
	}, func(_ int, _ batch.Result[struct{}]) {
		progressMu.Lock()
		defer progressMu.Unlock()
		completed++
		if progress != nil {
			if notifyErr := progress(completed, len(ids)); notifyErr != nil && progressErr == nil {
				progressErr = notifyErr
				cancel()
			}
		}
	})
	for index, result := range results {
		var panicErr *batch.PanicError
		if errors.As(result.Err, &panicErr) {
			s.logger.Error("account_bulk_task_panicked", "operation", operation, "account_id", ids[index], "error", panicErr, "stack", string(panicErr.Stack))
		}
	}
	s.logBatchSummary(operation, pool, summary, err)
	return summary.Succeeded, summary.Failed, errors.Join(err, progressErr)
}

func (s *Service) logBatchSummary(operation string, pool *batch.Pool, summary batch.Summary, err error) {
	// Quiet pure success auto-refresh churn — root fix advances due; this only rate-limits leftover noise.
	if operation == "credential_auto_refresh" && err == nil && summary.Failed == 0 && summary.Panicked == 0 && summary.Total > 0 {
		sig := fmt.Sprintf("%d/%d", summary.Total, summary.Succeeded)
		now := s.now()
		s.cliWarmMu.Lock()
		same := s.autoRefreshLogSig == sig
		recent := !s.autoRefreshLogAt.IsZero() && now.Sub(s.autoRefreshLogAt) < 15*time.Second
		if same && recent {
			s.cliWarmMu.Unlock()
			return
		}
		s.autoRefreshLogSig = sig
		s.autoRefreshLogAt = now
		s.cliWarmMu.Unlock()
	}
	snapshot := pool.Snapshot()
	s.logger.Info("account_bulk_completed", "operation", operation, "total", summary.Total, "submitted", summary.Submitted, "succeeded", summary.Succeeded, "failed", summary.Failed, "panicked", summary.Panicked, "duration_ms", summary.Duration.Milliseconds(), "canceled", summary.Canceled, "pool_limit", snapshot.Limit, "pool_active", snapshot.Active, "pool_queued", snapshot.Queued, "pool_peak", snapshot.Peak, "error", err)
}

func (s *Service) persistSeed(ctx context.Context, seed provider.CredentialSeed) (accountdomain.Credential, bool, error) {
	value, err := s.credentialFromSeed(seed)
	if err != nil {
		return accountdomain.Credential{}, false, err
	}
	stored, created, err := s.accounts.UpsertByIdentity(ctx, value)
	if err == nil {
		s.invalidateBuildBotFlagCache()
		s.WakeCredentialRefresh()
		s.preloadEnrichment(ctx, stored, seed)
	}
	return stored, created, err
}

// preloadEnrichment writes preloaded billing and model data from the
// daemon's enrichment phase to their respective stores, avoiding
// redundant upstream API calls after conversion. Best-effort: errors
// are logged but do not fail the conversion. Only called when the
// daemon path produced enrichment data (seed.PreloadedBilling non-nil
// or seed.PreloadedModels non-empty).
func (s *Service) preloadEnrichment(ctx context.Context, stored accountdomain.Credential, seed provider.CredentialSeed) {
	if seed.PreloadedBilling != nil {
		billing := *seed.PreloadedBilling
		billing.AccountID = stored.ID
		billing.SyncedAt = time.Now().UTC()
		if bErr := s.accounts.SaveBilling(ctx, billing); bErr != nil {
			s.logger.Warn("preload_billing_save_failed", "account_id", stored.ID, "error", bErr)
		}
	}
	if len(seed.PreloadedModels) > 0 && s.modelRepo != nil {
		if mErr := s.modelRepo.ReplaceAccountCapabilities(ctx, stored.ID, seed.PreloadedModels, time.Now().UTC()); mErr != nil {
			s.logger.Warn("preload_models_save_failed", "account_id", stored.ID, "error", mErr)
		}
	}
}

func (s *Service) credentialFromSeed(seed provider.CredentialSeed) (accountdomain.Credential, error) {
	accessEncrypted, err := s.cipher.Encrypt(seed.AccessToken)
	if err != nil {
		return accountdomain.Credential{}, err
	}
	refreshEncrypted, err := s.cipher.Encrypt(seed.RefreshToken)
	if err != nil {
		return accountdomain.Credential{}, err
	}
	cloudflareEncrypted := ""
	if strings.TrimSpace(seed.CloudflareCookies) != "" {
		cookies := egressapp.SanitizeCloudflareCookies(seed.CloudflareCookies)
		if cookies == "" {
			return accountdomain.Credential{}, invalidInput("Cloudflare Cookie 中没有有效字段")
		}
		cloudflareEncrypted, err = s.cipher.Encrypt(cookies)
		if err != nil {
			return accountdomain.Credential{}, err
		}
	}
	sourceKey := seed.SourceKey
	if sourceKey == "" {
		sourceKey = "device:" + security.HashToken(seed.AccessToken)
	}
	providerValue := seed.Provider
	if providerValue == "" {
		providerValue = accountdomain.ProviderBuild
	}
	authType := seed.AuthType
	if authType == "" {
		if s.providers == nil {
			return accountdomain.Credential{}, fmt.Errorf("Provider 注册表未初始化")
		}
		definition, ok := s.providers.Definition(providerValue)
		if !ok {
			return accountdomain.Credential{}, fmt.Errorf("Provider %s 未注册", providerValue)
		}
		authType = definition.Credential.AuthType
	}
	value := accountdomain.Credential{Provider: providerValue, AuthType: authType, WebTier: seed.WebTier, Name: seed.Name, Email: seed.Email, UserID: seed.UserID, TeamID: seed.TeamID, SourceKey: sourceKey, OIDCClientID: seed.OIDCClientID, EncryptedAccessToken: accessEncrypted, EncryptedRefreshToken: refreshEncrypted, EncryptedCloudflareCookie: cloudflareEncrypted, ExpiresAt: seed.ExpiresAt, Enabled: true, AuthStatus: accountdomain.AuthStatusActive, Priority: accountdomain.DefaultPriority, MaxConcurrent: accountdomain.DefaultMaxConcurrent, MinimumRemaining: accountdomain.DefaultMinimumRemaining, WebNSFWEnabledAt: seed.WebNSFWEnabledAt, WebTermsAcceptedAt: seed.WebTermsAcceptedAt, WebTermsAcceptedVersion: seed.WebTermsAcceptedVersion, WebBirthDateSetAt: seed.WebBirthDateSetAt}
	if providerValue == accountdomain.ProviderWeb && strings.TrimSpace(seed.AccessToken) != "" {
		value.EgressIdentity = "sso_" + security.HashToken(seed.AccessToken)[:32]
	}
	return value, nil
}

func normalizePage(page, pageSize int) (int, int) {
	return repository.NormalizePage(page, pageSize, repository.DefaultPageSize)
}

func normalizeBatchIDs(ids []uint64) ([]uint64, error) {
	return normalizeIDs(ids, repository.MaxPageSize)
}

func normalizeIDs(ids []uint64, limit int) ([]uint64, error) {
	if len(ids) == 0 {
		return nil, invalidInput("至少选择一个账号")
	}
	if len(ids) > limit {
		return nil, invalidInput(fmt.Sprintf("单次最多处理 %d 个账号", limit))
	}
	seen := make(map[uint64]struct{}, len(ids))
	result := make([]uint64, 0, len(ids))
	for _, id := range ids {
		if id == 0 {
			return nil, invalidInput("账号 ID 无效")
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		result = append(result, id)
	}
	return result, nil
}

// invalidInput 为可安全返回给管理端的账号参数错误附加稳定语义。
func invalidInput(message string) error {
	return fmt.Errorf("%w: %s", ErrInvalidInput, message)
}

// mapRepositoryError 隔离持久化层错误，避免 transport 依赖仓储实现语义。
func mapLinkedDeleteError(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if strings.Contains(msg, "关联删除目标") || strings.Contains(msg, "账号来源无效") || strings.Contains(msg, "不支持清理账号状态") {
		return invalidInput(msg)
	}
	return mapRepositoryError(err)
}

func mapRepositoryError(err error) error {
	if errors.Is(err, repository.ErrNotFound) {
		return ErrNotFound
	}
	if errors.Is(err, repository.ErrConflict) {
		return fmt.Errorf("%w: %s", ErrConflict, strings.TrimPrefix(err.Error(), repository.ErrConflict.Error()+": "))
	}
	return err
}
