package admintask

import (
	"encoding/json"
	"net/http"
	"time"

	admintaskapp "github.com/chenyme/grok2api/backend/internal/application/admintask"
	"github.com/chenyme/grok2api/backend/internal/shared/response"
	"github.com/gin-gonic/gin"
)

// Handler exposes process-local admin batch tasks (R2).
type Handler struct {
	registry *admintaskapp.Registry
}

// NewHandler constructs the task HTTP API.
func NewHandler(registry *admintaskapp.Registry) *Handler {
	return &Handler{registry: registry}
}

// Register mounts task routes under the admin protected group.
func (h *Handler) Register(router *gin.RouterGroup) {
	if h == nil || h.registry == nil {
		return
	}
	router.GET("/tasks", h.listActive)
	router.GET("/tasks/recent", h.listRecent)
	router.GET("/tasks/:taskId", h.get)
	router.GET("/tasks/:taskId/stream", h.stream)
	router.POST("/tasks/:taskId/cancel", h.cancel)
}

func (h *Handler) listActive(c *gin.Context) {
	response.Success(c, http.StatusOK, gin.H{"tasks": h.registry.ListActive()})
}

func (h *Handler) listRecent(c *gin.Context) {
	response.Success(c, http.StatusOK, gin.H{"tasks": h.registry.ListRecent(50)})
}

func (h *Handler) get(c *gin.Context) {
	task, ok := h.registry.Get(c.Param("taskId"))
	if !ok {
		response.Error(c, http.StatusNotFound, "taskNotFound", "任务不存在或已过期")
		return
	}
	response.Success(c, http.StatusOK, task.Snapshot())
}

func (h *Handler) cancel(c *gin.Context) {
	id := c.Param("taskId")
	if !h.registry.Cancel(id) {
		response.Error(c, http.StatusNotFound, "taskNotFound", "任务不存在或已过期")
		return
	}
	if task, ok := h.registry.Get(id); ok {
		// Cooperative: mark cancelled if worker already stopped; otherwise worker should MarkCancelled.
		if task.Context().Err() != nil && !task.IsTerminal() {
			task.MarkCancelled()
		}
		response.Success(c, http.StatusOK, task.Snapshot())
		return
	}
	response.Success(c, http.StatusOK, gin.H{"taskId": id, "status": "cancelled"})
}

func (h *Handler) stream(c *gin.Context) {
	task, ok := h.registry.Get(c.Param("taskId"))
	if !ok {
		response.Error(c, http.StatusNotFound, "taskNotFound", "任务不存在或已过期")
		return
	}
	c.Header("Content-Type", "text/event-stream; charset=utf-8")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Status(http.StatusOK)
	flusher, _ := c.Writer.(http.Flusher)
	write := func(event string, payload any) error {
		body, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		if _, err := c.Writer.Write([]byte("event: " + event + "\n")); err != nil {
			return err
		}
		if _, err := c.Writer.Write([]byte("data: ")); err != nil {
			return err
		}
		if _, err := c.Writer.Write(body); err != nil {
			return err
		}
		if _, err := c.Writer.Write([]byte("\n\n")); err != nil {
			return err
		}
		if flusher != nil {
			flusher.Flush()
		}
		return nil
	}
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()
	var last string
	for {
		snap := task.Snapshot()
		encoded, _ := json.Marshal(snap)
		if string(encoded) != last {
			last = string(encoded)
			if err := write("progress", snap); err != nil {
				return
			}
			if task.IsTerminal() {
				_ = write("complete", snap)
				return
			}
		}
		select {
		case <-c.Request.Context().Done():
			return
		case <-heartbeat.C:
			_, _ = c.Writer.Write([]byte(": ping\n\n"))
			if flusher != nil {
				flusher.Flush()
			}
		case <-ticker.C:
		}
	}
}
