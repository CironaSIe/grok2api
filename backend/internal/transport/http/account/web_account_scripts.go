package account

import (
	"net/http"
	"strings"

	accountapp "github.com/chenyme/grok2api/backend/internal/application/account"
	admintaskapp "github.com/chenyme/grok2api/backend/internal/application/admintask"
	accountdomain "github.com/chenyme/grok2api/backend/internal/domain/account"
	"github.com/chenyme/grok2api/backend/internal/shared/response"
	"github.com/gin-gonic/gin"
)

const maxWebAccountScriptRequestIDs = 1000

type webAccountScriptsRequest struct {
	IDs     []string                       `json:"ids"`
	All     bool                           `json:"all"`
	Scope   string                         `json:"scope"`
	Async   bool                           `json:"async"`
	Actions webAccountScriptActionsRequest `json:"actions"`
}

type webAccountScriptActionsRequest struct {
	AcceptTerms  bool `json:"acceptTerms"`
	SetBirthDate bool `json:"setBirthDate"`
	EnableNSFW   bool `json:"enableNSFW"`
}

func (r webAccountScriptActionsRequest) options() accountapp.WebAccountScriptOptions {
	return accountapp.WebAccountScriptOptions{
		AcceptTerms:  r.AcceptTerms,
		SetBirthDate: r.SetBirthDate,
		EnableNSFW:   r.EnableNSFW,
	}
}

func (r webAccountScriptActionsRequest) empty() bool {
	return !r.AcceptTerms && !r.SetBirthDate && !r.EnableNSFW
}

func (h *Handler) runWebAccountScripts(c *gin.Context) {
	var request webAccountScriptsRequest
	if c.ShouldBindJSON(&request) != nil {
		response.Error(c, http.StatusBadRequest, "invalidRequest", "账号脚本请求无效")
		return
	}
	if request.All && len(request.IDs) > 0 {
		response.Error(c, http.StatusBadRequest, "invalidRequest", "全部账号与指定账号不能同时提交")
		return
	}
	if !request.All && len(request.IDs) == 0 {
		response.Error(c, http.StatusBadRequest, "invalidRequest", "至少选择一个账号")
		return
	}
	if len(request.IDs) > maxWebAccountScriptRequestIDs {
		response.Error(c, http.StatusBadRequest, "invalidRequest", "单次最多处理 1000 个账号")
		return
	}
	if request.Actions.empty() {
		response.Error(c, http.StatusBadRequest, "invalidRequest", "至少选择一个账号脚本")
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
		ids = uniqueWebAccountScriptIDs(ids)
		if !h.validateProviderIDs(c, ids, string(accountdomain.ProviderWeb)) {
			return
		}
	}

	scope, err := accountapp.NormalizeWebAccountScriptScope(request.Scope, request.All, len(ids) > 0)
	if err != nil {
		response.Error(c, http.StatusBadRequest, "invalidRequest", err.Error())
		return
	}
	if !request.All && len(ids) > 0 {
		scope = accountapp.WebScriptScopeIDs
	}

	options := request.Actions.options()
	label := webAccountScriptTaskLabel(options, scope)

	if request.Async {
		if h.tasks == nil {
			response.Error(c, http.StatusServiceUnavailable, "tasksUnavailable", "任务注册表不可用")
			return
		}
		task := h.tasks.Start("web_scripts", label, 0)
		go h.executeWebAccountScriptsTask(task, scope, ids, options)
		response.Success(c, http.StatusAccepted, gin.H{
			"taskId": task.ID(),
			"status": "accepted",
			"scope":  string(scope),
			"async":  true,
		})
		return
	}

	stream := newAccountEventStream(c)
	defer stream.Close()
	progress := stream.ProgressObserver()
	if h.tasks != nil {
		task := h.tasks.Start("web_scripts", label, 0)
		_ = stream.Write("task", gin.H{"taskId": task.ID(), "scope": string(scope)})
		baseProgress := progress
		progress = func(completed, total int) error {
			task.ReportProgress(completed, -1, -1, total)
			if baseProgress != nil {
				return baseProgress(completed, total)
			}
			return nil
		}
		succeeded, failed, runErr := h.service.RunWebAccountScriptsScopedWithProgress(c.Request.Context(), scope, ids, options, progress)
		if runErr != nil {
			if c.Request.Context().Err() != nil {
				task.MarkCancelled()
			} else {
				task.Fail(runErr.Error())
			}
			stream.WriteError("webAccountScriptFailed", "执行 Grok Web 账号脚本失败")
			return
		}
		task.ReportProgress(succeeded+failed, succeeded, failed, succeeded+failed)
		task.Finish(map[string]any{"succeeded": succeeded, "failed": failed})
		_ = stream.Write("complete", accountBatchResponse{Succeeded: succeeded, Failed: failed})
		return
	}

	succeeded, failed, err := h.service.RunWebAccountScriptsScopedWithProgress(c.Request.Context(), scope, ids, options, progress)
	if err != nil {
		stream.WriteError("webAccountScriptFailed", "执行 Grok Web 账号脚本失败")
		return
	}
	_ = stream.Write("complete", accountBatchResponse{Succeeded: succeeded, Failed: failed})
}

func (h *Handler) executeWebAccountScriptsTask(task *admintaskapp.Task, scope accountapp.WebAccountScriptScope, ids []uint64, options accountapp.WebAccountScriptOptions) {
	ctx := task.Context()
	progress := func(completed, total int) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		task.ReportProgress(completed, -1, -1, total)
		return nil
	}
	succeeded, failed, err := h.service.RunWebAccountScriptsScopedWithProgress(ctx, scope, ids, options, progress)
	if err != nil {
		if ctx.Err() != nil {
			task.MarkCancelled()
			return
		}
		task.Fail(err.Error())
		return
	}
	task.ReportProgress(succeeded+failed, succeeded, failed, succeeded+failed)
	task.Finish(map[string]any{"succeeded": succeeded, "failed": failed})
}

func uniqueWebAccountScriptIDs(ids []uint64) []uint64 {
	seen := make(map[uint64]struct{}, len(ids))
	result := make([]uint64, 0, len(ids))
	for _, id := range ids {
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		result = append(result, id)
	}
	return result
}

func webAccountScriptTaskLabel(options accountapp.WebAccountScriptOptions, scope accountapp.WebAccountScriptScope) string {
	parts := make([]string, 0, 3)
	if options.AcceptTerms {
		parts = append(parts, "协议")
	}
	if options.SetBirthDate {
		parts = append(parts, "生日")
	}
	if options.EnableNSFW {
		parts = append(parts, "NSFW")
	}
	action := strings.Join(parts, "/")
	if action == "" {
		action = "脚本"
	}
	switch scope {
	case accountapp.WebScriptScopeAllForce:
		return "Web " + action + "（全量）"
	case accountapp.WebScriptScopePendingNSFW:
		return "Web " + action + "（待 NSFW）"
	case accountapp.WebScriptScopePending:
		return "Web " + action + "（仅待处理）"
	default:
		return "Web " + action
	}
}
