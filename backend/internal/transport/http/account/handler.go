package account

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	accountapp "github.com/chenyme/grok2api/backend/internal/application/account"
	accountsyncapp "github.com/chenyme/grok2api/backend/internal/application/accountsync"
	admintaskapp "github.com/chenyme/grok2api/backend/internal/application/admintask"
	accountdomain "github.com/chenyme/grok2api/backend/internal/domain/account"
	"github.com/chenyme/grok2api/backend/internal/repository"
	"github.com/chenyme/grok2api/backend/internal/shared/response"
	"github.com/gin-gonic/gin"
)

type accountSynchronizer interface {
	Sync(ctx context.Context, accountIDs ...uint64) accountsyncapp.Result
	SyncStream(ctx context.Context, accountIDs <-chan uint64) accountsyncapp.Result
}

type accountSyncProgressor interface {
	SyncStreamObserved(ctx context.Context, accountIDs <-chan uint64, observer func(completed, total int)) accountsyncapp.Result
}

type accountModelSynchronizer interface {
	SyncModels(ctx context.Context, accountID uint64) error
}

const (
	maxAccountImportBytes              = 30 << 20
	maxAccountImportFiles              = 1000
	accountSyncQueueCapacity           = 256
	accountEventHeartbeatInterval      = 15 * time.Second
	accountEventWriteTimeout           = 30 * time.Second
	accountImportInlineSyncMax         = 64
	accountImportBackgroundSyncTimeout = 2 * time.Hour
)

type Handler struct {
	service *accountapp.Service
	sync    accountSynchronizer
	tasks   *admintaskapp.Registry
}

type accountSyncPipeline struct {
	ctx        context.Context
	cancel     context.CancelFunc
	ids        chan uint64
	done       chan accountsyncapp.Result
	progress   func(completed, total int)
	progressMu sync.Mutex
	queued     atomic.Int64
	completed  atomic.Int64
}

func NewHandler(service *accountapp.Service, sync accountSynchronizer, tasks ...*admintaskapp.Registry) *Handler {
	h := &Handler{service: service, sync: sync}
	if len(tasks) > 0 {
		h.tasks = tasks[0]
	}
	return h
}

func (h *Handler) startSyncPipeline(parent context.Context, progress func(completed, total int)) *accountSyncPipeline {
	ctx, cancel := context.WithCancel(parent)
	pipeline := &accountSyncPipeline{ctx: ctx, cancel: cancel, progress: progress}
	if h.sync == nil {
		return pipeline
	}
	pipeline.ids = make(chan uint64, accountSyncQueueCapacity)
	pipeline.done = make(chan accountsyncapp.Result, 1)
	go func() {
		if observed, ok := h.sync.(accountSyncProgressor); ok && progress != nil {
			pipeline.done <- observed.SyncStreamObserved(ctx, pipeline.ids, func(completed, _ int) {
				pipeline.completed.Store(int64(completed))
				pipeline.reportProgress()
			})
			return
		}
		pipeline.done <- h.sync.SyncStream(ctx, pipeline.ids)
	}()
	return pipeline
}

func (p *accountSyncPipeline) Observe(accountID uint64) error {
	if p.ids == nil {
		return nil
	}
	p.queued.Add(1)
	select {
	case p.ids <- accountID:
		return nil
	case <-p.ctx.Done():
		p.queued.Add(-1)
		return p.ctx.Err()
	}
}

func (p *accountSyncPipeline) Finish(abort bool) accountsyncapp.Result {
	if abort {
		p.cancel()
	}
	if p.ids != nil {
		close(p.ids)
	}
	if !abort {
		// 转换阶段结束后不再增加同步任务，先报告一次固定分母，避免前端看到总数跳变。
		p.reportProgress()
	}
	result := accountsyncapp.Result{}
	if p.done != nil {
		result = <-p.done
	}
	if !abort && p.ids != nil {
		p.completed.Store(int64(result.Succeeded + result.Failed))
		p.reportProgress()
	}
	p.cancel()
	return result
}

// reportProgress 使用已进入同步流水线的任务数报告进度；转换结束后该分母保持固定。
func (p *accountSyncPipeline) reportProgress() {
	if p.ids == nil || p.progress == nil {
		return
	}
	p.progressMu.Lock()
	defer p.progressMu.Unlock()
	p.progress(int(p.completed.Load()), int(p.queued.Load()))
}

func (h *Handler) Register(router *gin.RouterGroup) {
	router.GET("/accounts", h.list)
	router.GET("/accounts/snapshot", h.snapshot)
	router.GET("/accounts/changes", h.changes)
	router.GET("/accounts/summary", h.summary)
	router.GET("/accounts/export", h.exportCredentials)
	router.GET("/accounts/cli-pool-snapshot", h.cliPoolSnapshot)
	router.POST("/accounts/export", h.exportSelectedCredentials)
	router.GET("/accounts/:id", h.get)
	router.POST("/accounts/device/start", h.startDevice)
	router.POST("/accounts/device/:sessionId/poll", h.pollDevice)
	router.POST("/accounts/import", h.importAuth)
	router.POST("/accounts/web/import", h.importWebAuth)
	router.POST("/accounts/console/import", h.importConsoleAuth)
	router.POST("/accounts/web/convert-to-build", h.convertWebToBuild)
	router.POST("/accounts/web/sync-to-console", h.syncWebToConsole)
	router.POST("/accounts/web/run-scripts", h.runWebAccountScripts)
	router.POST("/accounts/web/refresh-quotas", h.refreshAllWebQuotas)
	router.POST("/accounts/web/:id/accept-terms", h.acceptWebTerms)
	router.POST("/accounts/web/:id/birth-date", h.setWebBirthDate)
	router.POST("/accounts/web/:id/nsfw", h.enableWebNSFW)
	router.POST("/accounts/console/refresh-quotas", h.refreshAllConsoleQuotas)
	router.POST("/accounts/refresh-billing", h.refreshAllBilling)
	router.POST("/accounts/reset-quota", h.resetAllBuildQuota)
	router.POST("/accounts/refresh-tokens", h.refreshAllTokens)
	router.POST("/accounts/cleanup", h.cleanup)
	router.POST("/accounts/cleanup-preview", h.cleanupPreview)
	router.POST("/accounts/batch/refresh-billing", h.batchRefreshBilling)
	router.POST("/accounts/batch/reset-quota", h.batchResetQuota)
	router.POST("/accounts/batch/refresh-quotas", h.batchRefreshQuotas)
	router.POST("/accounts/batch/refresh-tokens", h.batchRefreshTokens)
	router.PATCH("/accounts/batch", h.batchUpdate)
	router.POST("/accounts/deletion-preview", h.previewDeletion)
	router.DELETE("/accounts", h.batchDelete)
	router.PATCH("/accounts/:id/cli-profile", h.updateCLIProfile)
	router.PATCH("/accounts/:id", h.update)
	router.DELETE("/accounts/:id", h.delete)
	router.POST("/accounts/:id/refresh-token", h.refreshToken)
	router.POST("/accounts/:id/refresh-billing", h.refreshBilling)
	router.POST("/accounts/:id/refresh-quota", h.refreshWebQuota)
}

type updateRequest struct {
	Name                   *string                       `json:"name"`
	Enabled                *bool                         `json:"enabled"`
	Priority               *int                          `json:"priority"`
	MaxConcurrent          *int                          `json:"maxConcurrent"`
	MinimumRemaining       *float64                      `json:"minimumRemaining"`
	CloudflareCookies      *string                       `json:"cloudflareCookies"`
	ClearCloudflareCookies bool                          `json:"clearCloudflareCookies"`
	BuildSuperEntitled     *bool                         `json:"buildSuperEntitled"`
	BuildRouteMode         *accountdomain.BuildRouteMode `json:"buildRouteMode"`
}

type batchUpdateRequest struct {
	IDs              []string `json:"ids" binding:"required"`
	Provider         string   `json:"provider" binding:"required"`
	Enabled          *bool    `json:"enabled"`
	Priority         *int     `json:"priority"`
	MaxConcurrent    *int     `json:"maxConcurrent"`
	MinimumRemaining *float64 `json:"minimumRemaining"`
}

type batchDeleteRequest struct {
	IDs                 []string `json:"ids" binding:"required"`
	Provider            string   `json:"provider" binding:"required"`
	LinkedDeleteTargets []string `json:"linkedDeleteTargets"`
}

type credentialExportRequest struct {
	IDs      []string `json:"ids" binding:"required"`
	Provider string   `json:"provider" binding:"required"`
}

type deletionPreviewRequest struct {
	IDs                 []string `json:"ids" binding:"required"`
	Provider            string   `json:"provider" binding:"required"`
	LinkedDeleteTargets []string `json:"linkedDeleteTargets"`
}

type accountCleanupRequest struct {
	Provider            string                     `json:"provider" binding:"required"`
	Statuses            []accountapp.CleanupStatus `json:"statuses" binding:"required"`
	LinkedDeleteTargets []string                   `json:"linkedDeleteTargets"`
}

type buildConversionRequest struct {
	IDs           []string                           `json:"ids"`
	All           bool                               `json:"all"`
	Strategy      accountapp.BuildConversionStrategy `json:"strategy"`
	TrustedSource bool                               `json:"trustedSource"`
	// Async returns taskId immediately; progress via GET /tasks/:id (R2).
	Async bool `json:"async"`
}

type cliProfileUpdateRequest struct {
	TrustedSource *bool `json:"trustedSource"`
}

type webConsoleSyncRequest struct {
	IDs      []string                          `json:"ids"`
	All      bool                              `json:"all"`
	Strategy accountapp.WebConsoleSyncStrategy `json:"strategy"`
	Async    bool                              `json:"async"`
}

type buildConversionResponse struct {
	Created    int                              `json:"created"`
	Linked     int                              `json:"linked"`
	Skipped    int                              `json:"skipped"`
	Failed     int                              `json:"failed"`
	Synced     int                              `json:"synced"`
	SyncFailed int                              `json:"syncFailed"`
	Failures   []buildConversionFailureResponse `json:"failures,omitempty"`
}

type buildConversionFailureResponse struct {
	AccountID uint64 `json:"accountId"`
	Message   string `json:"message"`
}

type accountTaskProgressResponse struct {
	Completed int    `json:"completed"`
	Total     int    `json:"total"`
	Phase     string `json:"phase,omitempty"`
}

type accountBatchResponse struct {
	Succeeded int `json:"succeeded"`
	Failed    int `json:"failed"`
}

type accountTokenRefreshResponse struct {
	Succeeded int `json:"succeeded"`
	Failed    int `json:"failed"`
	Skipped   int `json:"skipped"`
}

type accountImportResponse struct {
	Created        int `json:"created"`
	Updated        int `json:"updated"`
	Skipped        int `json:"skipped"`
	Synced         int `json:"synced"`
	SyncFailed     int `json:"syncFailed"`
	ConsoleCreated int `json:"consoleCreated,omitempty"`
	ConsoleUpdated int `json:"consoleUpdated,omitempty"`
	ConsoleFailed  int `json:"consoleFailed,omitempty"`
	ConsoleSkipped int `json:"consoleSkipped,omitempty"`
}

type accountResponse struct {
	ID                         uint64                  `json:"id,string"`
	Provider                   string                  `json:"provider"`
	AuthType                   string                  `json:"authType"`
	WebTier                    string                  `json:"webTier,omitempty"`
	WebTierSyncedAt            *time.Time              `json:"webTierSyncedAt,omitempty"`
	WebNSFWEnabledAt           *time.Time              `json:"nsfwEnabledAt,omitempty"`
	WebTermsAcceptedAt         *time.Time              `json:"termsAcceptedAt,omitempty"`
	Name                       string                  `json:"name"`
	Email                      string                  `json:"email,omitempty"`
	UserID                     string                  `json:"userId,omitempty"`
	TeamID                     string                  `json:"teamId,omitempty"`
	Enabled                    bool                    `json:"enabled"`
	AuthStatus                 string                  `json:"authStatus"`
	ReauthReason               string                  `json:"reauthReason,omitempty"`
	ReauthReasonLabel          string                  `json:"reauthReasonLabel,omitempty"`
	ExpiresAt                  *time.Time              `json:"expiresAt,omitempty"`
	Refreshable                bool                    `json:"refreshable"`
	RefreshDueAt               *time.Time              `json:"refreshDueAt,omitempty"`
	LastRefreshAt              *time.Time              `json:"lastRefreshAt,omitempty"`
	RefreshFailures            int                     `json:"refreshFailureCount"`
	LastRefreshError           string                  `json:"lastRefreshErrorCode,omitempty"`
	Priority                   int                     `json:"priority"`
	MaxConcurrent              int                     `json:"maxConcurrent"`
	MinimumRemaining           float64                 `json:"minimumRemaining"`
	FailureCount               int                     `json:"failureCount"`
	CooldownUntil              *time.Time              `json:"cooldownUntil,omitempty"`
	LastError                  string                  `json:"lastError,omitempty"`
	LastUsedAt                 *time.Time              `json:"lastUsedAt,omitempty"`
	LinkedAccountID            uint64                  `json:"linkedAccountId,omitempty,string"`
	LinkedName                 string                  `json:"linkedAccountName,omitempty"`
	LinkedProvider             string                  `json:"linkedProvider,omitempty"`
	LinkedAccounts             []linkedAccountResponse `json:"linkedAccounts,omitempty"`
	CreatedAt                  time.Time               `json:"createdAt"`
	ObservedModel              string                  `json:"observedModel,omitempty"`
	ObservedModelAt            *time.Time              `json:"observedModelAt,omitempty"`
	CloudflareCookieConfigured bool                    `json:"cloudflareCookieConfigured"`
	BuildSuperEntitled         bool                    `json:"buildSuperEntitled"`
	BuildRouteMode             string                  `json:"buildRouteMode"`
	BuildBotFlagged            bool                    `json:"buildBotFlagged"`
	EgressNodeID               uint64                  `json:"egressNodeId,omitempty,string"`
	EgressAssignmentMode       string                  `json:"egressAssignmentMode,omitempty"`
	CLILayer                   int                     `json:"cliLayer,omitempty"`
	CLIEligibility             string                  `json:"cliEligibility,omitempty"`
	CLIWarmBucket              string                  `json:"cliWarmBucket,omitempty"`
	CLILastSuccessAt           *time.Time              `json:"cliLastSuccessAt,omitempty"`
	CLITrustedSource           bool                    `json:"cliTrustedSource,omitempty"`
	CLIMaybeDead               bool                    `json:"cliMaybeDead,omitempty"`
	CLICallCount               int                     `json:"cliCallCount,omitempty"`
	CLITokenGeneration         int                     `json:"cliTokenGeneration,omitempty"`
	ModelSyncFailed            bool                    `json:"modelSyncFailed,omitempty"`
	// Tags are operational markers (cli_trusted, no_image, …) for admin chips/filters.
	Tags         []string              `json:"tags,omitempty"`
	Billing      *billingResponse      `json:"billing,omitempty"`
	Quota        quotaResponse         `json:"quota"`
	QuotaWindows []quotaWindowResponse `json:"quotaWindows,omitempty"`
}

type linkedAccountResponse struct {
	ID       uint64 `json:"id,string"`
	Provider string `json:"provider"`
	Name     string `json:"name"`
	Email    string `json:"email,omitempty"`
	UserID   string `json:"userId,omitempty"`
}

type quotaWindowResponse struct {
	Mode          string                   `json:"mode"`
	Remaining     int                      `json:"remaining"`
	Total         int                      `json:"total"`
	UsagePercent  float64                  `json:"usagePercent"`
	Breakdown     []quotaBreakdownResponse `json:"breakdown,omitempty"`
	WindowSeconds int                      `json:"windowSeconds"`
	ResetAt       *time.Time               `json:"resetAt,omitempty"`
	SyncedAt      *time.Time               `json:"syncedAt,omitempty"`
	Source        string                   `json:"source"`
}

type quotaBreakdownResponse struct {
	ProductCode  int     `json:"productCode"`
	UsagePercent float64 `json:"usagePercent"`
}

type billingResponse struct {
	PlanCode             string                   `json:"planCode,omitempty"`
	PlanName             string                   `json:"planName,omitempty"`
	MonthlyLimit         float64                  `json:"monthlyLimit"`
	Used                 float64                  `json:"used"`
	Remaining            float64                  `json:"remaining"`
	OnDemandCap          float64                  `json:"onDemandCap"`
	OnDemandUsed         float64                  `json:"onDemandUsed"`
	PrepaidBalance       float64                  `json:"prepaidBalance"`
	CreditUsagePercent   float64                  `json:"creditUsagePercent"`
	IsUnifiedBillingUser bool                     `json:"isUnifiedBillingUser"`
	OnDemandEnabled      *bool                    `json:"onDemandEnabled,omitempty"`
	TopUpMethod          string                   `json:"topUpMethod,omitempty"`
	UsagePeriodType      string                   `json:"usagePeriodType,omitempty"`
	UsagePeriodStart     string                   `json:"usagePeriodStart,omitempty"`
	UsagePeriodEnd       string                   `json:"usagePeriodEnd,omitempty"`
	BillingPeriodStart   string                   `json:"billingPeriodStart,omitempty"`
	BillingPeriodEnd     string                   `json:"billingPeriodEnd,omitempty"`
	History              []billingHistoryResponse `json:"history,omitempty"`
	SyncedAt             time.Time                `json:"syncedAt"`
}

type billingHistoryResponse struct {
	Year         int     `json:"year"`
	Month        int     `json:"month"`
	PeriodType   string  `json:"periodType,omitempty"`
	PeriodStart  string  `json:"periodStart,omitempty"`
	PeriodEnd    string  `json:"periodEnd,omitempty"`
	IncludedUsed float64 `json:"includedUsed"`
	OnDemandUsed float64 `json:"onDemandUsed"`
	TotalUsed    float64 `json:"totalUsed"`
}

type quotaResponse struct {
	Type            string     `json:"type"`
	Source          string     `json:"source"`
	Confidence      string     `json:"confidence"`
	Unit            string     `json:"unit,omitempty"`
	Used            float64    `json:"used"`
	Limit           float64    `json:"limit"`
	Remaining       float64    `json:"remaining"`
	UsagePercent    float64    `json:"usagePercent"`
	LimitKnown      bool       `json:"limitKnown"`
	WindowHours     int        `json:"windowHours,omitempty"`
	Observed        bool       `json:"observed"`
	Confirmed       bool       `json:"confirmed"`
	Status          string     `json:"status"`
	PeriodStart     string     `json:"periodStart,omitempty"`
	PeriodEnd       string     `json:"periodEnd,omitempty"`
	ExhaustedAt     *time.Time `json:"exhaustedAt,omitempty"`
	NextProbeAt     *time.Time `json:"nextProbeAt,omitempty"`
	LastConfirmedAt *time.Time `json:"lastConfirmedAt,omitempty"`
}

func (h *Handler) list(c *gin.Context) {
	page, pageSize := pagination(c)
	values, total, err := h.service.List(c.Request.Context(), page, pageSize, c.Query("search"), accountapp.ListFilter{
		Provider: c.Query("provider"), QuotaType: c.Query("type"), Status: c.Query("status"), Egress: c.Query("egress"),
		Renewal: c.Query("renewal"), Risk: c.Query("risk"), Agreement: c.Query("agreement"), Association: c.Query("association"),
		CLILayer:   parseOptionalIntQuery(c.Query("cliLayer")),
		CLITrusted: parseOptionalFormBool(c.Query("cliTrusted")), CLIMaybeDead: parseOptionalFormBool(c.Query("cliMaybeDead")),
		Sort: repository.SortQuery{Field: c.Query("sortBy"), Direction: repository.SortDirection(c.Query("sortOrder"))},
	})
	if errors.Is(err, accountapp.ErrInvalidFilter) {
		response.Error(c, http.StatusBadRequest, "invalidFilter", err.Error())
		return
	}
	if err != nil {
		response.Error(c, http.StatusInternalServerError, "accountListFailed", "读取账号失败")
		return
	}
	items := make([]accountResponse, 0, len(values))
	for _, value := range values {
		items = append(items, newAccountResponse(value))
	}
	response.Success(c, http.StatusOK, gin.H{"items": items, "page": page, "pageSize": pageSize, "total": total})
}

// snapshot returns the full filtered set for one provider so the admin UI can page locally.
func (h *Handler) snapshot(c *gin.Context) {
	providerValue := c.Query("provider")
	if providerValue == "" {
		response.Error(c, http.StatusBadRequest, "invalidFilter", "provider is required")
		return
	}
	value, err := h.service.Snapshot(c.Request.Context(), c.Query("search"), accountapp.ListFilter{
		Provider: providerValue, QuotaType: c.Query("type"), Status: c.Query("status"), Egress: c.Query("egress"),
		Renewal: c.Query("renewal"), Risk: c.Query("risk"), Agreement: c.Query("agreement"), Association: c.Query("association"),
		CLILayer:   parseOptionalIntQuery(c.Query("cliLayer")),
		CLITrusted: parseOptionalFormBool(c.Query("cliTrusted")), CLIMaybeDead: parseOptionalFormBool(c.Query("cliMaybeDead")),
		Sort: repository.SortQuery{Field: c.Query("sortBy"), Direction: repository.SortDirection(c.Query("sortOrder"))},
	})
	if errors.Is(err, accountapp.ErrInvalidFilter) {
		response.Error(c, http.StatusBadRequest, "invalidFilter", err.Error())
		return
	}
	if err != nil {
		response.Error(c, http.StatusInternalServerError, "accountSnapshotFailed", "读取账号快照失败")
		return
	}
	items := make([]accountResponse, 0, len(value.Items))
	for _, item := range value.Items {
		items = append(items, newAccountResponse(item))
	}
	response.Success(c, http.StatusOK, gin.H{
		"items": items, "total": value.Total, "revision": value.Revision,
		"provider": value.Provider, "generatedAt": value.GeneratedAt,
	})
}

// changes is a cheap revision probe; fullResync means clients should reload snapshot.
func (h *Handler) changes(c *gin.Context) {
	sinceRaw := strings.TrimSpace(c.Query("since"))
	var since int64
	if sinceRaw != "" {
		parsed, err := strconv.ParseInt(sinceRaw, 10, 64)
		if err != nil || parsed < 0 {
			response.Error(c, http.StatusBadRequest, "invalidRequest", "since 无效")
			return
		}
		since = parsed
	}
	value, err := h.service.Changes(c.Request.Context(), since)
	if err != nil {
		response.Error(c, http.StatusInternalServerError, "accountChangesFailed", "读取账号变更失败")
		return
	}
	response.Success(c, http.StatusOK, gin.H{"revision": value.Revision, "fullResync": value.FullResync})
}

func (h *Handler) summary(c *gin.Context) {
	value, err := h.service.Summary(c.Request.Context())
	if err != nil {
		response.Error(c, http.StatusInternalServerError, "accountSummaryFailed", "读取账号统计失败")
		return
	}
	build := value.Providers[string(accountdomain.ProviderBuild)]
	web := value.Providers[string(accountdomain.ProviderWeb)]
	console := value.Providers[string(accountdomain.ProviderConsole)]
	response.Success(c, http.StatusOK, gin.H{
		"total": value.Total, "available": value.Available, "recovering": value.Recovering, "attention": value.Attention, "risk": value.Risk,
		"providers": gin.H{
			string(accountdomain.ProviderBuild):   gin.H{"total": build.Total, "available": build.Available},
			string(accountdomain.ProviderWeb):     gin.H{"total": web.Total, "available": web.Available},
			string(accountdomain.ProviderConsole): gin.H{"total": console.Total, "available": console.Available},
		},
		"recovery": gin.H{"cooldown": value.Recovery.Cooldown, "waitingReset": value.Recovery.WaitingReset, "probing": value.Recovery.Probing},
		"issues": gin.H{
			"disabled":       value.Issues.Disabled,
			"reauthRequired": value.Issues.ReauthRequired,
			"cliMaybeDead":   value.Issues.CLIMaybeDead,
		},
	})
}

func (h *Handler) batchUpdate(c *gin.Context) {
	var request batchUpdateRequest
	if c.ShouldBindJSON(&request) != nil {
		response.Error(c, http.StatusBadRequest, "invalidRequest", "请求参数无效")
		return
	}
	ids, err := parseIDs(request.IDs)
	if err != nil {
		response.Error(c, http.StatusBadRequest, "invalidId", err.Error())
		return
	}
	if !h.validateProviderIDs(c, ids, request.Provider) {
		return
	}
	updated, err := h.service.BatchUpdate(c.Request.Context(), ids, accountapp.UpdateInput{Enabled: request.Enabled, Priority: request.Priority, MaxConcurrent: request.MaxConcurrent, MinimumRemaining: request.MinimumRemaining})
	if err != nil {
		h.writeServiceError(c, "accountBatchUpdateFailed", err, http.StatusInternalServerError, "批量更新账号失败")
		return
	}
	response.Success(c, http.StatusOK, gin.H{"updated": updated})
}

func (h *Handler) batchDelete(c *gin.Context) {
	var request batchDeleteRequest
	if c.ShouldBindJSON(&request) != nil {
		response.Error(c, http.StatusBadRequest, "invalidRequest", "请求参数无效")
		return
	}
	ids, err := parseIDs(request.IDs)
	if err != nil {
		response.Error(c, http.StatusBadRequest, "invalidId", err.Error())
		return
	}
	if !h.validateProviderIDs(c, ids, request.Provider) {
		return
	}
	targets, err := parseLinkedDeleteTargets(request.LinkedDeleteTargets)
	if err != nil {
		response.Error(c, http.StatusBadRequest, "invalidLinkedDeleteTargets", err.Error())
		return
	}
	result, err := h.service.BatchDeleteWithLinked(c.Request.Context(), accountdomain.Provider(request.Provider), ids, targets)
	if err != nil {
		h.writeServiceError(c, "accountBatchDeleteFailed", err, http.StatusInternalServerError, "批量删除账号失败")
		return
	}
	response.Success(c, http.StatusOK, newAccountDeleteResponse(result))
}

func (h *Handler) previewDeletion(c *gin.Context) {
	var request deletionPreviewRequest
	if c.ShouldBindJSON(&request) != nil {
		response.Error(c, http.StatusBadRequest, "invalidRequest", "请求参数无效")
		return
	}
	ids, err := parseIDs(request.IDs)
	if err != nil {
		response.Error(c, http.StatusBadRequest, "invalidId", err.Error())
		return
	}
	if !h.validateProviderIDs(c, ids, request.Provider) {
		return
	}
	targets, err := parseLinkedDeleteTargets(request.LinkedDeleteTargets)
	if err != nil {
		response.Error(c, http.StatusBadRequest, "invalidLinkedDeleteTargets", err.Error())
		return
	}
	resolution, err := h.service.PreviewLinkedDelete(c.Request.Context(), accountdomain.Provider(request.Provider), ids, targets)
	if err != nil {
		h.writeServiceError(c, "accountDeletionPreviewFailed", err, http.StatusInternalServerError, "预览删除账号失败")
		return
	}
	linked := gin.H{}
	for provider, count := range resolution.LinkedByProvider {
		linked[string(provider)] = count
	}
	response.Success(c, http.StatusOK, gin.H{
		"rootCount":        len(resolution.RootIDs),
		"linkedByProvider": linked,
		"total":            len(resolution.FinalIDs),
	})
}

func (h *Handler) batchRefreshBilling(c *gin.Context) {
	var request batchDeleteRequest
	if c.ShouldBindJSON(&request) != nil {
		response.Error(c, http.StatusBadRequest, "invalidRequest", "请求参数无效")
		return
	}
	ids, err := parseIDs(request.IDs)
	if err != nil {
		response.Error(c, http.StatusBadRequest, "invalidId", err.Error())
		return
	}
	if request.Provider != string(accountdomain.ProviderBuild) {
		response.Error(c, http.StatusBadRequest, "invalidProvider", "仅 Grok Build 账号支持 Billing 同步")
		return
	}
	if !h.validateProviderIDs(c, ids, request.Provider) {
		return
	}
	succeeded, failed, err := h.service.BatchRefreshBilling(c.Request.Context(), ids)
	if err != nil {
		h.writeServiceError(c, "billingBatchRefreshFailed", err, http.StatusBadGateway, "批量同步 Billing 失败")
		return
	}
	response.Success(c, http.StatusOK, gin.H{"succeeded": succeeded, "failed": failed})
}

func (h *Handler) batchResetQuota(c *gin.Context) {
	var request batchDeleteRequest
	if c.ShouldBindJSON(&request) != nil {
		response.Error(c, http.StatusBadRequest, "invalidRequest", "请求参数无效")
		return
	}
	ids, err := parseIDs(request.IDs)
	if err != nil {
		response.Error(c, http.StatusBadRequest, "invalidId", err.Error())
		return
	}
	if request.Provider != string(accountdomain.ProviderBuild) {
		response.Error(c, http.StatusBadRequest, "invalidProvider", "仅 Grok Build 账号支持手动重置额度状态")
		return
	}
	reset, err := h.service.BatchResetQuotaState(c.Request.Context(), ids)
	if err != nil {
		h.writeServiceError(c, "quotaBatchResetFailed", err, http.StatusInternalServerError, "批量重置额度状态失败")
		return
	}
	response.Success(c, http.StatusOK, gin.H{"reset": reset})
}

func (h *Handler) resetAllBuildQuota(c *gin.Context) {
	reset, err := h.service.ResetAllBuildQuotaState(c.Request.Context())
	if err != nil {
		h.writeServiceError(c, "quotaResetFailed", err, http.StatusInternalServerError, "重置全部 Grok Build 额度状态失败")
		return
	}
	response.Success(c, http.StatusOK, gin.H{"reset": reset})
}

func (h *Handler) cleanup(c *gin.Context) {
	var request accountCleanupRequest
	if c.ShouldBindJSON(&request) != nil {
		response.Error(c, http.StatusBadRequest, "invalidRequest", "请求参数无效")
		return
	}
	targets, err := parseLinkedDeleteTargets(request.LinkedDeleteTargets)
	if err != nil {
		response.Error(c, http.StatusBadRequest, "invalidLinkedDeleteTargets", err.Error())
		return
	}
	result, err := h.service.CleanupAccounts(c.Request.Context(), accountdomain.Provider(request.Provider), request.Statuses, targets)
	if err != nil {
		h.writeServiceError(c, "accountCleanupFailed", err, http.StatusInternalServerError, "清理账号失败")
		return
	}
	byProvider := gin.H{}
	for provider, count := range result.DeletedByProvider {
		byProvider[string(provider)] = count
	}
	response.Success(c, http.StatusOK, gin.H{
		"deleted":           result.Deleted,
		"rootsDeleted":      result.RootsDeleted,
		"linkedDeleted":     result.LinkedDeleted,
		"skipped":           result.Skipped,
		"deletedByProvider": byProvider,
	})
}

// cleanupPreview returns root and linked-peer counts for the cleanup dialog.
func (h *Handler) cleanupPreview(c *gin.Context) {
	var request accountCleanupRequest
	if c.ShouldBindJSON(&request) != nil {
		response.Error(c, http.StatusBadRequest, "invalidRequest", "请求参数无效")
		return
	}
	targets, err := parseLinkedDeleteTargets(request.LinkedDeleteTargets)
	if err != nil {
		response.Error(c, http.StatusBadRequest, "invalidLinkedDeleteTargets", err.Error())
		return
	}
	preview, err := h.service.PreviewCleanup(c.Request.Context(), accountdomain.Provider(request.Provider), request.Statuses, targets)
	if err != nil {
		h.writeServiceError(c, "accountCleanupPreviewFailed", err, http.StatusInternalServerError, "预览清理账号失败")
		return
	}
	rootsByStatus := gin.H{}
	for status, count := range preview.RootsByStatus {
		rootsByStatus[status] = count
	}
	linked := gin.H{}
	for provider, count := range preview.LinkedByProvider {
		linked[string(provider)] = count
	}
	response.Success(c, http.StatusOK, gin.H{
		"rootsByStatus":    rootsByStatus,
		"rootCount":        preview.RootCount,
		"linkedByProvider": linked,
		"total":            preview.Total,
	})
}

func (h *Handler) batchRefreshQuotas(c *gin.Context) {
	var request batchDeleteRequest
	if c.ShouldBindJSON(&request) != nil {
		response.Error(c, http.StatusBadRequest, "invalidRequest", "请求参数无效")
		return
	}
	ids, err := parseIDs(request.IDs)
	if err != nil {
		response.Error(c, http.StatusBadRequest, "invalidId", err.Error())
		return
	}
	providerValue := accountdomain.Provider(request.Provider)
	if !providerValue.IsValid() {
		response.Error(c, http.StatusBadRequest, "invalidProvider", "账号来源无效")
		return
	}
	if !h.validateProviderIDs(c, ids, request.Provider) {
		return
	}
	var succeeded, failed int
	if providerValue == accountdomain.ProviderBuild {
		succeeded, failed, err = h.service.BatchRefreshBilling(c.Request.Context(), ids)
	} else {
		succeeded, failed, err = h.service.BatchRefreshQuota(c.Request.Context(), ids)
	}
	if err != nil {
		h.writeServiceError(c, "quotaBatchRefreshFailed", err, http.StatusBadGateway, "批量同步账号额度失败")
		return
	}
	response.Success(c, http.StatusOK, gin.H{"succeeded": succeeded, "failed": failed})
}

func (h *Handler) batchRefreshTokens(c *gin.Context) {
	var request batchDeleteRequest
	if c.ShouldBindJSON(&request) != nil {
		response.Error(c, http.StatusBadRequest, "invalidRequest", "请求参数无效")
		return
	}
	ids, err := parseIDs(request.IDs)
	if err != nil {
		response.Error(c, http.StatusBadRequest, "invalidId", err.Error())
		return
	}
	if request.Provider != string(accountdomain.ProviderBuild) {
		response.Error(c, http.StatusBadRequest, "invalidProvider", "仅 Grok Build 账号支持凭据刷新")
		return
	}
	if !h.validateProviderIDs(c, ids, request.Provider) {
		return
	}
	succeeded, failed, skipped, err := h.service.BatchRefreshTokens(c.Request.Context(), ids)
	if err != nil {
		h.writeServiceError(c, "tokenRefreshFailed", err, http.StatusBadGateway, "批量刷新账号凭据失败")
		return
	}
	response.Success(c, http.StatusOK, gin.H{"succeeded": succeeded, "failed": failed, "skipped": skipped})
}

func (h *Handler) get(c *gin.Context) {
	id, ok := pathID(c)
	if !ok {
		return
	}
	value, err := h.service.Get(c.Request.Context(), id)
	if err != nil {
		h.writeServiceError(c, "accountGetFailed", err, http.StatusInternalServerError, "读取账号失败")
		return
	}
	response.Success(c, http.StatusOK, newAccountResponse(value))
}

func (h *Handler) startDevice(c *gin.Context) {
	value, err := h.service.StartDeviceLogin(c.Request.Context())
	if err != nil {
		response.Error(c, http.StatusBadGateway, "deviceLoginStartFailed", "启动 Device OAuth 失败")
		return
	}
	response.Success(c, http.StatusCreated, gin.H{"sessionId": value.SessionID, "userCode": value.UserCode, "verificationUri": value.VerificationURI, "verificationUriComplete": value.VerificationURIComplete, "intervalSeconds": int(value.Interval.Seconds()), "expiresAt": value.ExpiresAt})
}

func (h *Handler) pollDevice(c *gin.Context) {
	value, err := h.service.PollDeviceLogin(c.Request.Context(), c.Param("sessionId"))
	if errors.Is(err, accountapp.ErrDevicePending) {
		response.Success(c, http.StatusAccepted, gin.H{"status": "pending"})
		return
	}
	if errors.Is(err, accountapp.ErrDeviceSlowDown) {
		response.Error(c, http.StatusTooManyRequests, "devicePollTooFast", "轮询过快，请稍后重试")
		return
	}
	if errors.Is(err, accountapp.ErrDeviceDenied) {
		response.Error(c, http.StatusGone, "deviceLoginExpired", "Device OAuth 已拒绝或过期")
		return
	}
	if err != nil {
		response.Error(c, http.StatusBadGateway, "deviceLoginFailed", "Device OAuth 登录失败")
		return
	}
	syncResult := h.syncInitial(c.Request.Context(), value.Credential.ID)
	if refreshed, refreshErr := h.service.Get(c.Request.Context(), value.Credential.ID); refreshErr == nil {
		value = refreshed
	}
	status := "succeeded"
	if syncResult.Failed > 0 {
		status = "syncFailed"
	}
	response.Success(c, http.StatusOK, gin.H{"status": status, "account": newAccountResponse(value), "synced": syncResult.Succeeded, "syncFailed": syncResult.Failed})
}

func (h *Handler) importAuth(c *gin.Context) {
	h.importFile(c, accountdomain.ProviderBuild)
}

func (h *Handler) importWebAuth(c *gin.Context) {
	h.importFile(c, accountdomain.ProviderWeb)
}

func (h *Handler) importConsoleAuth(c *gin.Context) {
	h.importFile(c, accountdomain.ProviderConsole)
}

func (h *Handler) convertWebToBuild(c *gin.Context) {
	var request buildConversionRequest
	if c.ShouldBindJSON(&request) != nil {
		response.Error(c, http.StatusBadRequest, "invalidRequest", "转换请求无效")
		return
	}
	if request.All && len(request.IDs) > 0 {
		response.Error(c, http.StatusBadRequest, "invalidRequest", "全部转换与指定账号不能同时提交")
		return
	}
	if request.Strategy == "" {
		request.Strategy = accountapp.BuildConversionMissing
	}
	if request.Strategy != accountapp.BuildConversionAll && request.Strategy != accountapp.BuildConversionMissing {
		response.Error(c, http.StatusBadRequest, "invalidRequest", "转换策略无效")
		return
	}
	var ids []uint64
	if !request.All {
		var err error
		ids, err = parseIDs(request.IDs)
		if err != nil {
			response.Error(c, http.StatusBadRequest, "invalidId", err.Error())
			return
		}
		if !h.validateProviderIDs(c, ids, string(accountdomain.ProviderWeb)) {
			return
		}
	}
	opts := accountapp.ConvertBuildOptions{TrustedSource: request.TrustedSource}
	if request.Async {
		h.startWebToBuildConversionAsync(c, request.All, ids, request.Strategy, opts)
		return
	}
	h.streamWebToBuildConversion(c, request.All, ids, request.Strategy, opts)
}

func (h *Handler) syncWebToConsole(c *gin.Context) {
	var request webConsoleSyncRequest
	if c.ShouldBindJSON(&request) != nil {
		response.Error(c, http.StatusBadRequest, "invalidRequest", "同步请求无效")
		return
	}
	if request.All && len(request.IDs) > 0 {
		response.Error(c, http.StatusBadRequest, "invalidRequest", "全部同步与指定账号不能同时提交")
		return
	}
	if request.Strategy == "" {
		request.Strategy = accountapp.WebConsoleSyncAll
	}
	if request.Strategy != accountapp.WebConsoleSyncAll && request.Strategy != accountapp.WebConsoleSyncMissing {
		response.Error(c, http.StatusBadRequest, "invalidRequest", "同步策略无效")
		return
	}
	var ids []uint64
	if !request.All {
		var err error
		ids, err = parseIDs(request.IDs)
		if err != nil {
			response.Error(c, http.StatusBadRequest, "invalidId", err.Error())
			return
		}
		if !h.validateProviderIDs(c, ids, string(accountdomain.ProviderWeb)) {
			return
		}
	}
	if request.Async {
		h.startWebToConsoleSyncAsync(c, request.All, ids, request.Strategy)
		return
	}
	h.streamWebToConsoleSync(c, request.All, ids, request.Strategy)
}

func (h *Handler) runWebToConsoleSync(ctx context.Context, all bool, ids []uint64, strategy accountapp.WebConsoleSyncStrategy, progress accountapp.BatchProgressObserver, syncProgress func(completed, total int)) (accountapp.ImportResult, accountsyncapp.Result, error) {
	pipeline := h.startSyncPipeline(ctx, syncProgress)
	var (
		result accountapp.ImportResult
		err    error
	)
	if all {
		result, err = h.service.SyncAllWebAccountsToConsoleWithStrategy(pipeline.ctx, strategy, pipeline.Observe, progress)
	} else {
		result, err = h.service.SyncWebAccountsToConsoleWithStrategy(pipeline.ctx, ids, strategy, pipeline.Observe, progress)
	}
	syncResult := pipeline.Finish(err != nil)
	return result, syncResult, err
}

func (h *Handler) streamWebToConsoleSync(c *gin.Context, all bool, ids []uint64, strategy accountapp.WebConsoleSyncStrategy) {
	stream := newAccountEventStream(c)
	defer stream.Close()
	var total atomic.Int64
	progress := stream.PhaseProgressObserver("importing", &total)
	syncProgress := stream.SyncProgressObserver()
	var task *admintaskapp.Task
	if h.tasks != nil {
		task = h.tasks.Start("web_console_sync", webConsoleSyncTaskLabel(all, strategy), 0)
		_ = stream.Write("task", gin.H{"taskId": task.ID()})
		base := progress
		progress = func(completed, total int) error {
			task.SetPhase("importing")
			task.ReportProgress(completed, -1, -1, total)
			if base != nil {
				return base(completed, total)
			}
			return nil
		}
		baseSync := syncProgress
		syncProgress = func(completed, total int) {
			task.SetPhase("syncing")
			task.ReportProgress(completed, -1, -1, total)
			if baseSync != nil {
				baseSync(completed, total)
			}
		}
	}
	result, syncResult, err := h.runWebToConsoleSync(c.Request.Context(), all, ids, strategy, progress, syncProgress)
	if err != nil {
		if task != nil {
			if c.Request.Context().Err() != nil {
				task.MarkCancelled()
			} else {
				task.Fail(err.Error())
			}
		}
		stream.WriteError("accountConsoleSyncFailed", "Grok Web 账号同步到 Console 失败")
		return
	}
	payload := accountImportResponse{Created: result.Created, Updated: result.Updated, Skipped: result.Skipped, Synced: syncResult.Succeeded, SyncFailed: syncResult.Failed}
	if task != nil {
		task.Finish(map[string]any{
			"created": payload.Created, "updated": payload.Updated, "skipped": payload.Skipped,
			"synced": payload.Synced, "syncFailed": payload.SyncFailed,
		})
	}
	_ = stream.Write("complete", payload)
}

func (h *Handler) startWebToConsoleSyncAsync(c *gin.Context, all bool, ids []uint64, strategy accountapp.WebConsoleSyncStrategy) {
	if h.tasks == nil {
		response.Error(c, http.StatusServiceUnavailable, "tasksUnavailable", "任务注册表不可用")
		return
	}
	task := h.tasks.Start("web_console_sync", webConsoleSyncTaskLabel(all, strategy), 0)
	go h.executeWebToConsoleSyncTask(task, all, ids, strategy)
	response.Success(c, http.StatusAccepted, gin.H{"taskId": task.ID(), "status": "accepted", "async": true})
}

func (h *Handler) executeWebToConsoleSyncTask(task *admintaskapp.Task, all bool, ids []uint64, strategy accountapp.WebConsoleSyncStrategy) {
	ctx := task.Context()
	var total atomic.Int64
	progress := func(completed, totalValue int) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		task.SetPhase("importing")
		if totalValue > 0 {
			total.Store(int64(totalValue))
		}
		task.ReportProgress(completed, -1, -1, totalValue)
		return nil
	}
	syncProgress := func(completed, totalValue int) {
		task.SetPhase("syncing")
		task.ReportProgress(completed, -1, -1, totalValue)
	}
	result, syncResult, err := h.runWebToConsoleSync(ctx, all, ids, strategy, progress, syncProgress)
	if err != nil {
		if ctx.Err() != nil {
			task.MarkCancelled()
			return
		}
		task.Fail(err.Error())
		return
	}
	task.Finish(map[string]any{
		"created": result.Created, "updated": result.Updated, "skipped": result.Skipped,
		"synced": syncResult.Succeeded, "syncFailed": syncResult.Failed,
	})
}

func (h *Handler) runWebToBuildConversion(ctx context.Context, all bool, ids []uint64, strategy accountapp.BuildConversionStrategy, progress accountapp.BatchProgressObserver, syncProgress func(completed, total int), opts accountapp.ConvertBuildOptions) (accountapp.BuildConversionResult, accountsyncapp.Result, error) {
	pipeline := h.startSyncPipeline(ctx, syncProgress)
	var (
		result accountapp.BuildConversionResult
		err    error
	)
	if all {
		result, err = h.service.ConvertAllWebAccountsToBuildWithStrategyOptions(pipeline.ctx, strategy, pipeline.Observe, progress, opts)
	} else {
		result, err = h.service.ConvertWebAccountsToBuildWithStrategyOptions(pipeline.ctx, ids, strategy, pipeline.Observe, progress, opts)
	}
	syncResult := pipeline.Finish(err != nil)
	return result, syncResult, err
}

func (h *Handler) streamWebToBuildConversion(c *gin.Context, all bool, ids []uint64, strategy accountapp.BuildConversionStrategy, opts accountapp.ConvertBuildOptions) {
	stream := newAccountEventStream(c)
	defer stream.Close()
	var total atomic.Int64
	progress := stream.PhaseProgressObserver("converting", &total)
	syncProgress := stream.SyncProgressObserver()
	var task *admintaskapp.Task
	if h.tasks != nil {
		task = h.tasks.Start("web_build_convert", webBuildConvertTaskLabel(all, strategy), 0)
		_ = stream.Write("task", gin.H{"taskId": task.ID()})
		base := progress
		progress = func(completed, total int) error {
			task.SetPhase("converting")
			task.ReportProgress(completed, -1, -1, total)
			if base != nil {
				return base(completed, total)
			}
			return nil
		}
		baseSync := syncProgress
		syncProgress = func(completed, total int) {
			task.SetPhase("syncing")
			task.ReportProgress(completed, -1, -1, total)
			if baseSync != nil {
				baseSync(completed, total)
			}
		}
	}
	result, syncResult, err := h.runWebToBuildConversion(c.Request.Context(), all, ids, strategy, progress, syncProgress, opts)
	if err != nil {
		if task != nil {
			if c.Request.Context().Err() != nil {
				task.MarkCancelled()
			} else {
				task.Fail(err.Error())
			}
		}
		stream.WriteError("accountConversionFailed", "Grok Web 账号转换失败")
		return
	}
	payload := newBuildConversionResponse(result, syncResult)
	if task != nil {
		task.Finish(map[string]any{
			"created": payload.Created, "linked": payload.Linked, "skipped": payload.Skipped, "failed": payload.Failed,
			"synced": payload.Synced, "syncFailed": payload.SyncFailed, "failures": payload.Failures,
		})
	}
	_ = stream.Write("complete", payload)
}

func (h *Handler) startWebToBuildConversionAsync(c *gin.Context, all bool, ids []uint64, strategy accountapp.BuildConversionStrategy, opts accountapp.ConvertBuildOptions) {
	if h.tasks == nil {
		response.Error(c, http.StatusServiceUnavailable, "tasksUnavailable", "任务注册表不可用")
		return
	}
	task := h.tasks.Start("web_build_convert", webBuildConvertTaskLabel(all, strategy), 0)
	go h.executeWebToBuildConversionTask(task, all, ids, strategy, opts)
	response.Success(c, http.StatusAccepted, gin.H{"taskId": task.ID(), "status": "accepted", "async": true})
}

func (h *Handler) executeWebToBuildConversionTask(task *admintaskapp.Task, all bool, ids []uint64, strategy accountapp.BuildConversionStrategy, opts accountapp.ConvertBuildOptions) {
	ctx := task.Context()
	progress := func(completed, total int) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		task.SetPhase("converting")
		task.ReportProgress(completed, -1, -1, total)
		return nil
	}
	syncProgress := func(completed, total int) {
		task.SetPhase("syncing")
		task.ReportProgress(completed, -1, -1, total)
	}
	result, syncResult, err := h.runWebToBuildConversion(ctx, all, ids, strategy, progress, syncProgress, opts)
	if err != nil {
		if ctx.Err() != nil {
			task.MarkCancelled()
			return
		}
		task.Fail(err.Error())
		return
	}
	payload := newBuildConversionResponse(result, syncResult)
	task.Finish(map[string]any{
		"created": payload.Created, "linked": payload.Linked, "skipped": payload.Skipped, "failed": payload.Failed,
		"synced": payload.Synced, "syncFailed": payload.SyncFailed, "failures": payload.Failures,
	})
}

func webBuildConvertTaskLabel(all bool, strategy accountapp.BuildConversionStrategy) string {
	scope := "选定"
	if all {
		scope = "全部"
	}
	return "Web→Build 转换（" + scope + "/" + string(strategy) + "）"
}

func webConsoleSyncTaskLabel(all bool, strategy accountapp.WebConsoleSyncStrategy) string {
	scope := "选定"
	if all {
		scope = "全部"
	}
	return "Web→Console 同步（" + scope + "/" + string(strategy) + "）"
}

func (h *Handler) cliPoolSnapshot(c *gin.Context) {
	snap := h.service.GetCLIWarmSnapshot()
	response.Success(c, http.StatusOK, snap)
}

func (h *Handler) updateCLIProfile(c *gin.Context) {
	id, ok := pathID(c)
	if !ok {
		return
	}
	var request cliProfileUpdateRequest
	if c.ShouldBindJSON(&request) != nil || request.TrustedSource == nil {
		response.Error(c, http.StatusBadRequest, "invalidRequest", "CLI profile 更新请求无效")
		return
	}
	value, err := h.service.UpdateBuildCLITrustedSource(c.Request.Context(), id, *request.TrustedSource)
	if err != nil {
		h.writeServiceError(c, "cliProfileUpdateFailed", err, http.StatusBadRequest, "更新 CLI profile 失败")
		return
	}
	response.Success(c, http.StatusOK, newAccountResponse(value))
}

// parseOptionalFormBool returns nil when the form field is empty (use config default).
func parseOptionalFormBool(raw string) *bool {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" {
		return nil
	}
	switch raw {
	case "1", "true", "yes", "on":
		v := true
		return &v
	case "0", "false", "no", "off":
		v := false
		return &v
	default:
		return nil
	}
}

func parseFormBoolDefault(raw string, defaultValue bool) bool {
	if parsed := parseOptionalFormBool(raw); parsed != nil {
		return *parsed
	}
	return defaultValue
}

func parseOptionalIntQuery(raw string) int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0
	}
	return n
}

func newBuildConversionResponse(result accountapp.BuildConversionResult, syncResult accountsyncapp.Result) buildConversionResponse {
	failures := make([]buildConversionFailureResponse, 0, len(result.Failures))
	for _, failure := range result.Failures {
		failures = append(failures, buildConversionFailureResponse{AccountID: failure.AccountID, Message: failure.Message})
	}
	return buildConversionResponse{
		Created: result.Created, Linked: result.Linked, Skipped: result.Skipped, Failed: result.Failed,
		Synced: syncResult.Succeeded, SyncFailed: syncResult.Failed, Failures: failures,
	}
}

func prepareAccountEventStream(c *gin.Context) {
	c.Header("Content-Type", "text/event-stream; charset=utf-8")
	c.Header("Cache-Control", "no-cache, no-transform")
	c.Header("X-Accel-Buffering", "no")
}

type accountEventStream struct {
	context   *gin.Context
	mu        sync.Mutex
	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

func newAccountEventStream(c *gin.Context) *accountEventStream {
	prepareAccountEventStream(c)
	stream := &accountEventStream{context: c, stop: make(chan struct{}), done: make(chan struct{})}
	_ = stream.writeComment("connected")
	go stream.heartbeat()
	return stream
}

func (s *accountEventStream) ProgressObserver() accountapp.BatchProgressObserver {
	return s.PhaseProgressObserver("", nil)
}

func (s *accountEventStream) PhaseProgressObserver(phase string, totalValue *atomic.Int64) accountapp.BatchProgressObserver {
	return func(completed, total int) error {
		if totalValue != nil {
			totalValue.Store(int64(total))
		}
		return s.Write("progress", accountTaskProgressResponse{Completed: completed, Total: total, Phase: phase})
	}
}

func (s *accountEventStream) SyncProgressObserver() func(completed, total int) {
	return func(completed, total int) {
		_ = s.Write("progress", accountTaskProgressResponse{Completed: completed, Total: total, Phase: "syncing"})
	}
}

func (s *accountEventStream) WriteError(code, message string) {
	_ = s.Write("error", gin.H{"code": code, "message": message})
}

func (s *accountEventStream) Write(event string, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := setAccountWriteDeadline(s.context.Writer); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(s.context.Writer, "event: %s\ndata: %s\n\n", event, payload); err != nil {
		return err
	}
	s.context.Writer.Flush()
	return s.context.Request.Context().Err()
}

func (s *accountEventStream) writeComment(comment string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := setAccountWriteDeadline(s.context.Writer); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(s.context.Writer, ": %s\n\n", comment); err != nil {
		return err
	}
	s.context.Writer.Flush()
	return s.context.Request.Context().Err()
}

func (s *accountEventStream) heartbeat() {
	defer close(s.done)
	ticker := time.NewTicker(accountEventHeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-s.context.Request.Context().Done():
			return
		case <-ticker.C:
			if err := s.writeComment("heartbeat"); err != nil {
				return
			}
		}
	}
}

func (s *accountEventStream) Close() {
	s.closeOnce.Do(func() { close(s.stop) })
	<-s.done
}

func setAccountWriteDeadline(writer http.ResponseWriter) error {
	err := http.NewResponseController(writer).SetWriteDeadline(time.Now().Add(accountEventWriteTimeout))
	if errors.Is(err, http.ErrNotSupported) {
		return nil
	}
	return err
}

// writeAccountEvent keeps the event encoder independently testable without starting a heartbeat.
func writeAccountEvent(c *gin.Context, event string, value any) error {
	return (&accountEventStream{context: c}).Write(event, value)
}

func (h *Handler) importFile(c *gin.Context, providerValue accountdomain.Provider) {
	fileDescription := "账号凭据 JSON 或逐行 JSON 文本"
	if providerValue == accountdomain.ProviderWeb {
		fileDescription = "Grok Web JSON、逐行 JSON 或 SSO 文本"
	} else if providerValue == accountdomain.ProviderConsole {
		fileDescription = "Grok Console JSON、逐行 JSON 或 SSO 文本"
	}
	documents, ok := readAccountImportDocuments(c, fileDescription)
	if !ok {
		return
	}
	importOpts := accountapp.ImportWebOptions{
		AutoSyncConsole: parseOptionalFormBool(c.PostForm("autoSyncConsole")),
		TrustedSource:   parseFormBoolDefault(c.PostForm("trustedSource"), false),
	}
	async := parseFormBoolDefault(c.PostForm("async"), false)
	if async {
		h.startImportFileAsync(c, providerValue, documents, importOpts)
		return
	}
	stream := newAccountEventStream(c)
	defer stream.Close()
	var total atomic.Int64
	progress := stream.PhaseProgressObserver("importing", &total)
	var task *admintaskapp.Task
	if h.tasks != nil {
		task = h.tasks.Start(importTaskType(providerValue), importTaskLabel(providerValue), 0)
		_ = stream.Write("task", gin.H{"taskId": task.ID()})
		base := progress
		progress = func(completed, total int) error {
			task.SetPhase("importing")
			task.ReportProgress(completed, -1, -1, total)
			if base != nil {
				return base(completed, total)
			}
			return nil
		}
	}
	result, syncResult, err := h.runImportFile(c.Request.Context(), providerValue, documents, importOpts, progress, stream.SyncProgressObserver())
	if err != nil {
		if task != nil {
			if c.Request.Context().Err() != nil {
				task.MarkCancelled()
			} else {
				task.Fail(err.Error())
			}
		}
		h.writeImportError(stream, providerValue, err)
		return
	}
	payload := accountImportResponse{
		Created: result.Created, Updated: result.Updated, Skipped: result.Skipped,
		Synced: syncResult.Succeeded, SyncFailed: syncResult.Failed,
		ConsoleCreated: result.ConsoleCreated, ConsoleUpdated: result.ConsoleUpdated,
		ConsoleFailed: result.ConsoleFailed, ConsoleSkipped: result.ConsoleSkipped,
	}
	if task != nil {
		task.Finish(importResultMap(payload))
	}
	_ = stream.Write("complete", payload)
}

func (h *Handler) startImportFileAsync(c *gin.Context, providerValue accountdomain.Provider, documents [][]byte, importOpts accountapp.ImportWebOptions) {
	if h.tasks == nil {
		response.Error(c, http.StatusServiceUnavailable, "tasksUnavailable", "任务注册表不可用")
		return
	}
	// Copy docs so caller can release multipart resources; already in memory.
	docs := make([][]byte, len(documents))
	for i, doc := range documents {
		docs[i] = append([]byte(nil), doc...)
	}
	task := h.tasks.Start(importTaskType(providerValue), importTaskLabel(providerValue), 0)
	go h.executeImportFileTask(task, providerValue, docs, importOpts)
	response.Success(c, http.StatusAccepted, gin.H{"taskId": task.ID(), "status": "accepted", "async": true})
}

func (h *Handler) executeImportFileTask(task *admintaskapp.Task, providerValue accountdomain.Provider, documents [][]byte, importOpts accountapp.ImportWebOptions) {
	ctx := task.Context()
	progress := func(completed, total int) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		task.SetPhase("importing")
		task.ReportProgress(completed, -1, -1, total)
		return nil
	}
	syncProgress := func(completed, total int) {
		task.SetPhase("syncing")
		task.ReportProgress(completed, -1, -1, total)
	}
	result, syncResult, err := h.runImportFile(ctx, providerValue, documents, importOpts, progress, syncProgress)
	if err != nil {
		if ctx.Err() != nil {
			task.MarkCancelled()
			return
		}
		task.Fail(err.Error())
		return
	}
	payload := accountImportResponse{
		Created: result.Created, Updated: result.Updated, Skipped: result.Skipped,
		Synced: syncResult.Succeeded, SyncFailed: syncResult.Failed,
		ConsoleCreated: result.ConsoleCreated, ConsoleUpdated: result.ConsoleUpdated,
		ConsoleFailed: result.ConsoleFailed, ConsoleSkipped: result.ConsoleSkipped,
	}
	task.Finish(importResultMap(payload))
}

func (h *Handler) runImportFile(ctx context.Context, providerValue accountdomain.Provider, documents [][]byte, importOpts accountapp.ImportWebOptions, progress accountapp.BatchProgressObserver, syncProgress func(completed, total int)) (accountapp.ImportResult, accountsyncapp.Result, error) {
	// Web/Console SSO files can be 10k–50k free tokens. Persist first; only small batches
	// wait inline for identity/quota so the admin SSE does not stall for hours.
	if providerValue == accountdomain.ProviderWeb || providerValue == accountdomain.ProviderConsole {
		var (
			result accountapp.ImportResult
			err    error
		)
		if providerValue == accountdomain.ProviderWeb {
			result, err = h.service.ImportWebCredentialDocumentsWithOptions(ctx, documents, nil, progress, importOpts)
		} else {
			result, err = h.service.ImportConsoleCredentialDocumentsWithProgress(ctx, documents, nil, progress)
		}
		if err != nil {
			return accountapp.ImportResult{}, accountsyncapp.Result{}, err
		}
		return result, h.finishImportInitialSync(ctx, result.AccountIDs), nil
	}
	pipeline := h.startSyncPipeline(ctx, syncProgress)
	result, err := h.service.ImportCredentialDocumentsWithProgress(pipeline.ctx, documents, pipeline.Observe, progress)
	syncResult := pipeline.Finish(err != nil)
	return result, syncResult, err
}

func importTaskType(providerValue accountdomain.Provider) string {
	switch providerValue {
	case accountdomain.ProviderWeb:
		return "import_web"
	case accountdomain.ProviderConsole:
		return "import_console"
	default:
		return "import_build"
	}
}

func importTaskLabel(providerValue accountdomain.Provider) string {
	switch providerValue {
	case accountdomain.ProviderWeb:
		return "导入 Grok Web"
	case accountdomain.ProviderConsole:
		return "导入 Grok Console"
	default:
		return "导入 Grok Build"
	}
}

func importResultMap(payload accountImportResponse) map[string]any {
	return map[string]any{
		"created": payload.Created, "updated": payload.Updated, "skipped": payload.Skipped,
		"synced": payload.Synced, "syncFailed": payload.SyncFailed,
		"consoleCreated": payload.ConsoleCreated, "consoleUpdated": payload.ConsoleUpdated,
		"consoleFailed": payload.ConsoleFailed, "consoleSkipped": payload.ConsoleSkipped,
	}
}

func (h *Handler) writeImportError(stream *accountEventStream, providerValue accountdomain.Provider, err error) {
	slog.Default().Warn("account_import_failed", "provider", string(providerValue), "error", err)
	msg := err.Error()
	code := "authImportFailed"
	if errors.Is(err, accountapp.ErrInvalidImport) {
		code = "invalidAuthFile"
	} else if errors.Is(err, accountapp.ErrImportLimit) {
		code = "accountImportLimitExceeded"
	}
	stream.WriteError(code, msg)
}

// finishImportInitialSync runs identity/quota bootstrap after SSO import.
// Small batches stay inline for immediate UI feedback; large pools run in background.
func (h *Handler) finishImportInitialSync(ctx context.Context, accountIDs []uint64) accountsyncapp.Result {
	if h.sync == nil || len(accountIDs) == 0 {
		return accountsyncapp.Result{}
	}
	if len(accountIDs) <= accountImportInlineSyncMax {
		return h.sync.Sync(ctx, accountIDs...)
	}
	ids := append([]uint64(nil), accountIDs...)
	slog.Default().Info("account_import_background_sync_started", "total", len(ids))
	go func() {
		bg, cancel := context.WithTimeout(context.Background(), accountImportBackgroundSyncTimeout)
		defer cancel()
		result := h.sync.Sync(bg, ids...)
		slog.Default().Info("account_import_background_sync_finished", "total", len(ids), "succeeded", result.Succeeded, "failed", result.Failed)
	}()
	return accountsyncapp.Result{}
}

func readAccountImportDocuments(c *gin.Context, fileDescription string) ([][]byte, bool) {
	form, err := c.MultipartForm()
	if err != nil {
		var sizeError *http.MaxBytesError
		if errors.As(err, &sizeError) {
			response.Error(c, http.StatusRequestEntityTooLarge, "accountImportFileTooLarge", "账号凭据文件总大小不能超过 30 MiB")
			return nil, false
		}
		response.Error(c, http.StatusBadRequest, "invalidAuthFile", "请选择有效的"+fileDescription)
		return nil, false
	}
	defer form.RemoveAll()
	files := append(form.File["files"], form.File["file"]...)
	if len(files) == 0 {
		response.Error(c, http.StatusBadRequest, "invalidAuthFile", "请选择有效的"+fileDescription)
		return nil, false
	}
	if len(files) > maxAccountImportFiles {
		response.Error(c, http.StatusBadRequest, "invalidAuthFile", "单次最多选择 1000 个账号文件")
		return nil, false
	}
	documents := make([][]byte, 0, len(files))
	totalBytes := int64(0)
	for _, file := range files {
		if file.Size < 0 || totalBytes+file.Size > maxAccountImportBytes {
			response.Error(c, http.StatusRequestEntityTooLarge, "accountImportFileTooLarge", "账号凭据文件总大小不能超过 30 MiB")
			return nil, false
		}
		opened, openErr := file.Open()
		if openErr != nil {
			response.Error(c, http.StatusBadRequest, "invalidAuthFile", "无法读取"+fileDescription)
			return nil, false
		}
		data, readErr := io.ReadAll(io.LimitReader(opened, maxAccountImportBytes-totalBytes+1))
		_ = opened.Close()
		if readErr != nil {
			response.Error(c, http.StatusBadRequest, "invalidAuthFile", "无法读取"+fileDescription)
			return nil, false
		}
		totalBytes += int64(len(data))
		if totalBytes > maxAccountImportBytes {
			response.Error(c, http.StatusRequestEntityTooLarge, "accountImportFileTooLarge", "账号凭据文件总大小不能超过 30 MiB")
			return nil, false
		}
		documents = append(documents, data)
	}
	return documents, true
}

func (h *Handler) refreshWebQuota(c *gin.Context) {
	id, ok := pathID(c)
	if !ok {
		return
	}
	if _, err := h.service.RefreshQuota(c.Request.Context(), id); err != nil {
		h.writeServiceError(c, "quotaRefreshFailed", err, http.StatusBadGateway, "同步 Provider 额度失败")
		return
	}
	value, err := h.service.Get(c.Request.Context(), id)
	if err != nil {
		h.writeServiceError(c, "accountGetFailed", err, http.StatusInternalServerError, "读取账号失败")
		return
	}
	response.Success(c, http.StatusOK, newAccountResponse(value))
}

func (h *Handler) exportCredentials(c *gin.Context) {
	providerValue := accountdomain.Provider(c.DefaultQuery("provider", string(accountdomain.ProviderBuild)))
	if limitText, pagedExport := c.GetQuery("limit"); pagedExport {
		if _, usesOffset := c.GetQuery("offset"); usesOffset {
			response.Error(c, http.StatusBadRequest, "accountExportFailed", "分批导出不支持 offset，请使用服务端返回的 afterId")
			return
		}
		limit, err := strconv.Atoi(strings.TrimSpace(limitText))
		if err != nil {
			response.Error(c, http.StatusBadRequest, "accountExportFailed", "导出数量必须为整数")
			return
		}
		afterID, err := strconv.ParseUint(strings.TrimSpace(c.DefaultQuery("afterId", "0")), 10, 64)
		if err != nil {
			response.Error(c, http.StatusBadRequest, "accountExportFailed", "导出游标必须为非负整数")
			return
		}
		snapshotMaxID, err := strconv.ParseUint(strings.TrimSpace(c.DefaultQuery("snapshotMaxId", "0")), 10, 64)
		if err != nil {
			response.Error(c, http.StatusBadRequest, "accountExportFailed", "导出快照上界必须为非负整数")
			return
		}
		result, exportErr := h.service.ExportProviderCredentialsCursor(c.Request.Context(), providerValue, afterID, snapshotMaxID, limit)
		if exportErr != nil {
			h.writeServiceError(c, "accountExportFailed", exportErr, http.StatusInternalServerError, "导出账号失败")
			return
		}
		c.Header("X-Export-Next-ID", strconv.FormatUint(result.NextID, 10))
		c.Header("X-Export-Snapshot-Max-ID", strconv.FormatUint(result.SnapshotMaxID, 10))
		c.Header("X-Export-Has-More", strconv.FormatBool(result.HasMore))
		h.writeCredentialExport(c, providerValue, result.ExportResult)
		return
	}
	result, err := h.service.ExportProviderCredentials(c.Request.Context(), providerValue)
	if err != nil {
		h.writeServiceError(c, "accountExportFailed", err, http.StatusInternalServerError, "导出账号失败")
		return
	}
	h.writeCredentialExport(c, providerValue, result)
}

func (h *Handler) exportSelectedCredentials(c *gin.Context) {
	var request credentialExportRequest
	if c.ShouldBindJSON(&request) != nil {
		response.Error(c, http.StatusBadRequest, "invalidRequest", "请求参数无效")
		return
	}
	ids, err := parseIDs(request.IDs)
	if err != nil {
		response.Error(c, http.StatusBadRequest, "invalidId", err.Error())
		return
	}
	providerValue := accountdomain.Provider(request.Provider)
	result, err := h.service.ExportProviderCredentialsByIDs(c.Request.Context(), providerValue, ids)
	if err != nil {
		h.writeServiceError(c, "accountExportFailed", err, http.StatusInternalServerError, "导出账号失败")
		return
	}
	h.writeCredentialExport(c, providerValue, result)
}

func (h *Handler) writeCredentialExport(c *gin.Context, providerValue accountdomain.Provider, result accountapp.ExportResult) {
	filename := "grok2api-" + string(providerValue) + "-accounts-" + time.Now().UTC().Format("20060102T150405Z") + ".json"
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	c.Header("Access-Control-Expose-Headers", "Content-Disposition, X-Exported-Accounts, X-Export-Next-ID, X-Export-Snapshot-Max-ID, X-Export-Has-More")
	c.Header("Content-Disposition", `attachment; filename="`+filename+`"`)
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("X-Exported-Accounts", strconv.Itoa(result.Count))
	c.Data(http.StatusOK, "application/json; charset=utf-8", result.Data)
}

func (h *Handler) syncInitial(ctx context.Context, accountIDs ...uint64) accountsyncapp.Result {
	if h.sync == nil {
		return accountsyncapp.Result{}
	}
	return h.sync.Sync(ctx, accountIDs...)
}

func (h *Handler) update(c *gin.Context) {
	id, ok := pathID(c)
	if !ok {
		return
	}
	var request updateRequest
	if c.ShouldBindJSON(&request) != nil {
		response.Error(c, http.StatusBadRequest, "invalidRequest", "请求参数无效")
		return
	}
	value, err := h.service.Update(c.Request.Context(), id, accountapp.UpdateInput{
		Name: request.Name, Enabled: request.Enabled, Priority: request.Priority,
		MaxConcurrent: request.MaxConcurrent, MinimumRemaining: request.MinimumRemaining,
		CloudflareCookies: request.CloudflareCookies, ClearCloudflareCookies: request.ClearCloudflareCookies,
		BuildSuperEntitled: request.BuildSuperEntitled, BuildRouteMode: request.BuildRouteMode,
	})
	if err != nil {
		h.writeServiceError(c, "accountUpdateFailed", err, http.StatusInternalServerError, "更新账号失败")
		return
	}
	result := newAccountResponse(value)
	if request.BuildSuperEntitled != nil {
		if synchronizer, ok := h.sync.(accountModelSynchronizer); ok {
			result.ModelSyncFailed = synchronizer.SyncModels(c.Request.Context(), id) != nil
		}
	}
	response.Success(c, http.StatusOK, result)
}

func (h *Handler) delete(c *gin.Context) {
	id, ok := pathID(c)
	if !ok {
		return
	}
	var request struct {
		Provider            string   `json:"provider"`
		LinkedDeleteTargets []string `json:"linkedDeleteTargets"`
	}
	// Empty body = legacy single-account delete. Non-empty body must bind cleanly
	// so a truncated/malformed linked-delete request cannot silently drop targets.
	raw, err := io.ReadAll(io.LimitReader(c.Request.Body, 1<<20))
	if err != nil {
		response.Error(c, http.StatusBadRequest, "invalidRequest", "请求参数无效")
		return
	}
	if len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, &request); err != nil {
			response.Error(c, http.StatusBadRequest, "invalidRequest", "请求参数无效")
			return
		}
	}
	targets, err := parseLinkedDeleteTargets(request.LinkedDeleteTargets)
	if err != nil {
		response.Error(c, http.StatusBadRequest, "invalidLinkedDeleteTargets", err.Error())
		return
	}
	if len(targets) > 0 {
		if request.Provider == "" {
			response.Error(c, http.StatusBadRequest, "invalidProvider", "删除关联账号时必须指定 provider")
			return
		}
		result, err := h.service.DeleteWithLinked(c.Request.Context(), accountdomain.Provider(request.Provider), id, targets)
		if err != nil {
			h.writeServiceError(c, "accountDeleteFailed", err, http.StatusInternalServerError, "删除账号失败")
			return
		}
		response.Success(c, http.StatusOK, newAccountDeleteResponse(result))
		return
	}
	if err := h.service.Delete(c.Request.Context(), id); err != nil {
		h.writeServiceError(c, "accountDeleteFailed", err, http.StatusInternalServerError, "删除账号失败")
		return
	}
	response.Success(c, http.StatusOK, gin.H{"deleted": true})
}

func parseLinkedDeleteTargets(values []string) ([]accountdomain.Provider, error) {
	if len(values) == 0 {
		return nil, nil
	}
	out := make([]accountdomain.Provider, 0, len(values))
	seen := map[accountdomain.Provider]struct{}{}
	for _, value := range values {
		provider := accountdomain.Provider(strings.TrimSpace(value))
		if !provider.IsValid() {
			return nil, fmt.Errorf("关联删除目标无效")
		}
		if _, ok := seen[provider]; ok {
			continue
		}
		seen[provider] = struct{}{}
		out = append(out, provider)
	}
	return out, nil
}

func newAccountDeleteResponse(result accountapp.AccountDeleteResult) gin.H {
	byProvider := gin.H{}
	for provider, count := range result.DeletedByProvider {
		byProvider[string(provider)] = count
	}
	return gin.H{
		"deleted":           result.Deleted,
		"rootsDeleted":      result.RootsDeleted,
		"linkedDeleted":     result.LinkedDeleted,
		"skipped":           result.Skipped,
		"deletedByProvider": byProvider,
	}
}

// writeServiceError 仅暴露明确的账号业务错误，未知内部错误使用稳定文案。
func (h *Handler) writeServiceError(c *gin.Context, code string, err error, fallbackStatus int, fallbackMessage string) {
	switch {
	case errors.Is(err, accountapp.ErrImportLimit):
		response.Error(c, http.StatusBadRequest, "accountImportLimitExceeded", err.Error())
	case errors.Is(err, accountapp.ErrExportLimit):
		response.Error(c, http.StatusBadRequest, "accountExportLimitExceeded", err.Error())
	case errors.Is(err, accountapp.ErrInvalidInput), errors.Is(err, accountapp.ErrInvalidImport):
		response.Error(c, http.StatusBadRequest, code, err.Error())
	case errors.Is(err, accountapp.ErrConflict):
		response.Error(c, http.StatusConflict, code, err.Error())
	case errors.Is(err, accountapp.ErrNotFound):
		response.Error(c, http.StatusNotFound, "accountNotFound", err.Error())
	case errors.Is(err, accountapp.ErrUnsupported):
		response.Error(c, http.StatusConflict, "accountOperationUnsupported", err.Error())
	case errors.Is(err, accountapp.ErrConversionBusy):
		response.Error(c, http.StatusConflict, "accountConversionBusy", err.Error())
	case errors.Is(err, accountapp.ErrWebAccountScriptBusy):
		response.Error(c, http.StatusConflict, "webAccountScriptBusy", err.Error())
	default:
		response.Error(c, fallbackStatus, code, fallbackMessage)
	}
}

func (h *Handler) refreshToken(c *gin.Context) {
	id, ok := pathID(c)
	if !ok {
		return
	}
	value, err := h.service.RefreshToken(c.Request.Context(), id)
	if err != nil {
		h.writeServiceError(c, "tokenRefreshFailed", err, http.StatusBadGateway, "刷新账号凭据失败")
		return
	}
	response.Success(c, http.StatusOK, newAccountResponse(value))
}

func (h *Handler) acceptWebTerms(c *gin.Context) {
	id, ok := pathID(c)
	if !ok {
		return
	}
	if err := h.service.AcceptWebTerms(c.Request.Context(), id); err != nil {
		h.writeServiceError(c, "webTermsAcceptanceFailed", err, http.StatusBadGateway, "接受 Grok Web 服务协议失败")
		return
	}
	response.Success(c, http.StatusOK, gin.H{"completed": true})
}

func (h *Handler) setWebBirthDate(c *gin.Context) {
	id, ok := pathID(c)
	if !ok {
		return
	}
	if err := h.service.SetWebBirthDate(c.Request.Context(), id); err != nil {
		h.writeServiceError(c, "webBirthDateUpdateFailed", err, http.StatusBadGateway, "设置 Grok Web 账号生日失败")
		return
	}
	response.Success(c, http.StatusOK, gin.H{"completed": true})
}

func (h *Handler) enableWebNSFW(c *gin.Context) {
	id, ok := pathID(c)
	if !ok {
		return
	}
	if err := h.service.EnableWebNSFW(c.Request.Context(), id); err != nil {
		h.writeServiceError(c, "webNSFWEnableFailed", err, http.StatusBadGateway, "开启 Grok Web NSFW 失败")
		return
	}
	response.Success(c, http.StatusOK, gin.H{"completed": true})
}

func (h *Handler) refreshBilling(c *gin.Context) {
	id, ok := pathID(c)
	if !ok {
		return
	}
	value, err := h.service.RefreshBilling(c.Request.Context(), id)
	if err != nil {
		h.writeServiceError(c, "billingRefreshFailed", err, http.StatusBadGateway, "刷新账号额度失败")
		return
	}
	response.Success(c, http.StatusOK, newBillingResponse(value))
}

func (h *Handler) refreshAllBilling(c *gin.Context) {
	stream := newAccountEventStream(c)
	defer stream.Close()
	succeeded, failed, err := h.service.SyncAllBillingWithProgress(c.Request.Context(), stream.ProgressObserver())
	if err != nil {
		stream.WriteError("billingRefreshFailed", "刷新账号额度失败")
		return
	}
	_ = stream.Write("complete", accountBatchResponse{Succeeded: succeeded, Failed: failed})
}

func (h *Handler) refreshAllTokens(c *gin.Context) {
	stream := newAccountEventStream(c)
	defer stream.Close()
	succeeded, failed, skipped, err := h.service.RefreshAllTokensWithProgress(c.Request.Context(), stream.ProgressObserver())
	if err != nil {
		stream.WriteError("tokenRefreshFailed", "续期账号凭据失败")
		return
	}
	_ = stream.Write("complete", accountTokenRefreshResponse{Succeeded: succeeded, Failed: failed, Skipped: skipped})
}

func (h *Handler) refreshAllWebQuotas(c *gin.Context) {
	stream := newAccountEventStream(c)
	defer stream.Close()
	succeeded, failed, err := h.service.SyncAllWebQuotasWithProgress(c.Request.Context(), stream.ProgressObserver())
	if err != nil {
		stream.WriteError("quotaRefreshFailed", "同步 Grok Web 账号额度失败")
		return
	}
	_ = stream.Write("complete", accountBatchResponse{Succeeded: succeeded, Failed: failed})
}

func (h *Handler) refreshAllConsoleQuotas(c *gin.Context) {
	stream := newAccountEventStream(c)
	defer stream.Close()
	succeeded, failed, err := h.service.SyncAllConsoleQuotasWithProgress(c.Request.Context(), stream.ProgressObserver())
	if err != nil {
		stream.WriteError("quotaRefreshFailed", "同步 Grok Console 账号额度失败")
		return
	}
	_ = stream.Write("complete", accountBatchResponse{Succeeded: succeeded, Failed: failed})
}

func newAccountResponse(value accountapp.View) accountResponse {
	c := value.Credential
	buildRouteMode := c.BuildRouteMode
	if c.Provider != accountdomain.ProviderBuild || !buildRouteMode.IsValid() {
		buildRouteMode = accountdomain.BuildRouteAuto
	}
	result := accountResponse{
		ID: c.ID, Provider: string(c.Provider), AuthType: string(c.AuthType), WebTier: string(c.WebTier),
		WebTierSyncedAt: c.WebTierSyncedAt, WebNSFWEnabledAt: c.WebNSFWEnabledAt, WebTermsAcceptedAt: c.WebTermsAcceptedAt, Name: c.Name, Email: c.Email, UserID: c.UserID, TeamID: c.TeamID,
		Enabled: c.Enabled, AuthStatus: string(c.AuthStatus), Refreshable: c.EncryptedRefreshToken != "",
		RefreshDueAt: c.RefreshDueAt, LastRefreshAt: c.LastRefreshAt,
		RefreshFailures: c.RefreshFailureCount, LastRefreshError: c.LastRefreshErrorCode,
		Priority: c.Priority, MaxConcurrent: c.MaxConcurrent, MinimumRemaining: c.MinimumRemaining,
		FailureCount: c.FailureCount, CooldownUntil: c.CooldownUntil, LastError: c.LastError,
		LastUsedAt: c.LastUsedAt, LinkedAccountID: c.LinkedAccountID, LinkedName: c.LinkedAccountName, LinkedProvider: string(c.LinkedProvider),
		CreatedAt: c.CreatedAt, ObservedModel: c.ObservedModel, ObservedModelAt: c.ObservedModelAt,
		CloudflareCookieConfigured: c.EncryptedCloudflareCookie != "",
		BuildSuperEntitled:         c.BuildSuperEntitled && c.Provider == accountdomain.ProviderBuild,
		BuildRouteMode:             string(buildRouteMode),
		BuildBotFlagged:            value.BuildBotFlagged && c.Provider == accountdomain.ProviderBuild,
		EgressNodeID:               c.EgressNodeID,
		EgressAssignmentMode:       string(c.EgressAssignmentMode),
		CLILayer:                   value.CLILayer,
		CLIEligibility:             value.CLIEligibility,
		CLIWarmBucket:              value.CLIWarmBucket,
		Tags:                       append([]string(nil), c.Tags...),
		Quota:                      newQuotaResponse(value.Quota), QuotaWindows: make([]quotaWindowResponse, 0, len(value.QuotaWindows)),
	}
	if value.CLIProfile != nil && c.Provider == accountdomain.ProviderBuild {
		result.CLILastSuccessAt = value.CLIProfile.LastSuccessAt
		result.CLITrustedSource = value.CLIProfile.TrustedSource
		result.CLIMaybeDead = value.CLIProfile.MaybeDead
		result.CLICallCount = value.CLIProfile.CallCount
		result.CLITokenGeneration = value.CLIProfile.TokenGeneration
	}
	if c.AuthStatus == accountdomain.AuthStatusReauthRequired {
		reason := accountdomain.NormalizeReauthReason(string(c.ReauthReason))
		if reason == accountdomain.ReauthReasonNone {
			reason = accountdomain.ReauthReasonUnknown
		}
		result.ReauthReason = string(reason)
		result.ReauthReasonLabel = reason.DisplayLabel()
	}
	for _, linked := range c.LinkedAccounts {
		result.LinkedAccounts = append(result.LinkedAccounts, linkedAccountResponse{ID: linked.ID, Provider: string(linked.Provider), Name: linked.Name, Email: linked.Email, UserID: linked.UserID})
	}
	for _, window := range value.QuotaWindows {
		breakdown := make([]quotaBreakdownResponse, 0, len(window.Breakdown))
		for _, item := range window.Breakdown {
			breakdown = append(breakdown, quotaBreakdownResponse{ProductCode: item.ProductCode, UsagePercent: item.UsagePercent})
		}
		result.QuotaWindows = append(result.QuotaWindows, quotaWindowResponse{
			Mode: window.Mode, Remaining: window.Remaining, Total: window.Total,
			UsagePercent: window.UsagePercent, Breakdown: breakdown,
			WindowSeconds: window.WindowSeconds, ResetAt: window.ResetAt, SyncedAt: window.SyncedAt,
			Source: string(window.Source),
		})
	}
	if !c.ExpiresAt.IsZero() {
		expiresAt := c.ExpiresAt
		result.ExpiresAt = &expiresAt
	}
	if value.Billing != nil {
		billing := newBillingResponse(*value.Billing)
		result.Billing = &billing
	}
	return result
}

func newQuotaResponse(value accountapp.QuotaView) quotaResponse {
	return quotaResponse{Type: string(value.Type), Source: value.Source, Confidence: value.Confidence, Unit: value.Unit, Used: value.Used, Limit: value.Limit, Remaining: value.Remaining, UsagePercent: value.UsagePercent, LimitKnown: value.LimitKnown, WindowHours: value.WindowHours, Observed: value.Observed, Confirmed: value.Confirmed, Status: string(value.Status), PeriodStart: value.PeriodStart, PeriodEnd: value.PeriodEnd, ExhaustedAt: value.ExhaustedAt, NextProbeAt: value.NextProbeAt, LastConfirmedAt: value.LastConfirmedAt}
}

func newBillingResponse(value accountdomain.Billing) billingResponse {
	history := make([]billingHistoryResponse, 0, len(value.History))
	for _, entry := range value.History {
		history = append(history, billingHistoryResponse{
			Year: entry.Year, Month: entry.Month,
			PeriodType: entry.PeriodType, PeriodStart: entry.PeriodStart, PeriodEnd: entry.PeriodEnd,
			IncludedUsed: entry.IncludedUsed, OnDemandUsed: entry.OnDemandUsed, TotalUsed: entry.TotalUsed,
		})
	}
	return billingResponse{PlanCode: value.PlanCode, PlanName: value.PlanName, MonthlyLimit: value.MonthlyLimit, Used: value.Used, Remaining: value.Remaining(), OnDemandCap: value.OnDemandCap, OnDemandUsed: value.OnDemandUsed, PrepaidBalance: value.PrepaidBalance, CreditUsagePercent: value.CreditUsagePercent, IsUnifiedBillingUser: value.IsUnifiedBillingUser, OnDemandEnabled: value.OnDemandEnabled, TopUpMethod: value.TopUpMethod, UsagePeriodType: value.UsagePeriodType, UsagePeriodStart: value.UsagePeriodStart, UsagePeriodEnd: value.UsagePeriodEnd, BillingPeriodStart: value.BillingPeriodStart, BillingPeriodEnd: value.BillingPeriodEnd, History: history, SyncedAt: value.SyncedAt}
}

func pagination(c *gin.Context) (int, int) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	size, _ := strconv.Atoi(c.DefaultQuery("pageSize", "20"))
	return repository.NormalizePage(page, size, repository.DefaultPageSize)
}

func pathID(c *gin.Context) (uint64, bool) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil || id == 0 {
		response.Error(c, http.StatusBadRequest, "invalidId", "ID 无效")
		return 0, false
	}
	return id, true
}

func parseIDs(values []string) ([]uint64, error) {
	ids := make([]uint64, 0, len(values))
	for _, value := range values {
		id, err := strconv.ParseUint(value, 10, 64)
		if err != nil || id == 0 {
			return nil, errors.New("ID 无效")
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func (h *Handler) validateProviderIDs(c *gin.Context, ids []uint64, providerValue string) bool {
	provider := accountdomain.Provider(providerValue)
	if !provider.IsValid() {
		response.Error(c, http.StatusBadRequest, "invalidProvider", "账号来源无效")
		return false
	}
	valid, err := h.service.AccountsBelongToProvider(c.Request.Context(), ids, provider)
	if err != nil {
		h.writeServiceError(c, "accountPoolValidationFailed", err, http.StatusInternalServerError, "校验账号号池失败")
		return false
	}
	if !valid {
		response.Error(c, http.StatusConflict, "accountPoolMismatch", "批量操作包含不属于当前号池的账号")
		return false
	}
	return true
}
