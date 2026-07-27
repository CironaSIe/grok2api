// Package admintask provides an in-process admin batch task registry (R2).
// Tasks are process-local and lost on restart; use GET/SSE for progress restore within a process.
package admintask

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sort"
	"sync"
	"time"
)

// Status is the lifecycle of a batch task.
type Status string

const (
	StatusQueued    Status = "queued"
	StatusRunning   Status = "running"
	StatusDone      Status = "done"
	StatusError     Status = "error"
	StatusCancelled Status = "cancelled"
)

const (
	defaultRetain = 64
	defaultTTL    = 30 * time.Minute
)

// Snapshot is a JSON-friendly task view.
type Snapshot struct {
	TaskID     string         `json:"taskId"`
	Type       string         `json:"type"`
	Label      string         `json:"label"`
	Status     Status         `json:"status"`
	Total      int            `json:"total"`
	Processed  int            `json:"processed"`
	OK         int            `json:"ok"`
	Fail       int            `json:"fail"`
	Error      string         `json:"error,omitempty"`
	Result     map[string]any `json:"result,omitempty"`
	CreatedAt  time.Time      `json:"createdAt"`
	StartedAt  *time.Time     `json:"startedAt,omitempty"`
	FinishedAt *time.Time     `json:"finishedAt,omitempty"`
	// Phase mirrors legacy SSE phase fields when set by the worker.
	Phase string `json:"phase,omitempty"`
}

// Task is a mutable in-memory batch job.
type Task struct {
	mu         sync.RWMutex
	id         string
	typ        string
	label      string
	status     Status
	total      int
	processed  int
	ok         int
	fail       int
	errMsg     string
	result     map[string]any
	phase      string
	createdAt  time.Time
	startedAt  time.Time
	finishedAt time.Time
	ctx        context.Context
	cancel     context.CancelFunc
}

// Context returns the cancelable worker context.
func (t *Task) Context() context.Context { return t.ctx }

// ID returns the task identifier.
func (t *Task) ID() string { return t.id }

// SetPhase updates an optional progress phase label.
func (t *Task) SetPhase(phase string) {
	t.mu.Lock()
	t.phase = phase
	t.mu.Unlock()
}

// SetTotal updates total when discovered after start (e.g. pending scan).
func (t *Task) SetTotal(total int) {
	if total < 0 {
		total = 0
	}
	t.mu.Lock()
	t.total = total
	t.mu.Unlock()
}

// ReportProgress sets absolute counters (safe to call from workers).
func (t *Task) ReportProgress(processed, ok, fail, total int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if total >= 0 {
		t.total = total
	}
	if processed >= 0 {
		t.processed = processed
	}
	if ok >= 0 {
		t.ok = ok
	}
	if fail >= 0 {
		t.fail = fail
	}
	if t.status == StatusQueued {
		t.status = StatusRunning
		t.startedAt = time.Now().UTC()
	}
}

// Record increments processed and ok/fail by one.
func (t *Task) Record(success bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.processed++
	if success {
		t.ok++
	} else {
		t.fail++
	}
	if t.status == StatusQueued {
		t.status = StatusRunning
		t.startedAt = time.Now().UTC()
	}
}

// Finish marks success with optional result payload.
func (t *Task) Finish(result map[string]any) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.status == StatusCancelled || t.status == StatusError {
		return
	}
	t.status = StatusDone
	t.result = result
	t.finishedAt = time.Now().UTC()
	if t.cancel != nil {
		t.cancel()
	}
}

// Fail marks terminal error.
func (t *Task) Fail(message string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.status == StatusDone || t.status == StatusCancelled {
		return
	}
	t.status = StatusError
	t.errMsg = message
	t.finishedAt = time.Now().UTC()
	if t.cancel != nil {
		t.cancel()
	}
}

// FailWithResult marks terminal error while preserving a result payload (e.g.
// partial failures collected before the overall error). The result is exposed
// via Snapshot.Result, same as Finish, so the UI can read it after the task
// terminates. It does not change the status semantics: callers still observe
// status=="error" and the error message.
func (t *Task) FailWithResult(message string, result map[string]any) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.status == StatusDone || t.status == StatusCancelled {
		return
	}
	t.status = StatusError
	t.errMsg = message
	t.result = result
	t.finishedAt = time.Now().UTC()
	if t.cancel != nil {
		t.cancel()
	}
}

// MarkCancelled records a cooperative cancel finish.
func (t *Task) MarkCancelled() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.status == StatusDone || t.status == StatusError {
		return
	}
	t.status = StatusCancelled
	t.finishedAt = time.Now().UTC()
}

// Snapshot returns a stable copy of task state.
func (t *Task) Snapshot() Snapshot {
	t.mu.RLock()
	defer t.mu.RUnlock()
	snap := Snapshot{
		TaskID: t.id, Type: t.typ, Label: t.label, Status: t.status,
		Total: t.total, Processed: t.processed, OK: t.ok, Fail: t.fail,
		Error: t.errMsg, Phase: t.phase, CreatedAt: t.createdAt,
	}
	if !t.startedAt.IsZero() {
		started := t.startedAt
		snap.StartedAt = &started
	}
	if !t.finishedAt.IsZero() {
		finished := t.finishedAt
		snap.FinishedAt = &finished
	}
	if t.result != nil {
		snap.Result = t.result
	}
	return snap
}

// IsTerminal reports whether the task will no longer change.
func (t *Task) IsTerminal() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.status == StatusDone || t.status == StatusError || t.status == StatusCancelled
}

// Registry stores process-local tasks.
type Registry struct {
	mu     sync.RWMutex
	tasks  map[string]*Task
	retain int
	ttl    time.Duration
	now    func() time.Time
}

// NewRegistry constructs a registry with default retention.
func NewRegistry() *Registry {
	return &Registry{
		tasks:  make(map[string]*Task),
		retain: defaultRetain,
		ttl:    defaultTTL,
		now:    func() time.Time { return time.Now().UTC() },
	}
}

// Start creates a running task with a detachable cancel context.
func (r *Registry) Start(taskType, label string, total int) *Task {
	if total < 0 {
		total = 0
	}
	ctx, cancel := context.WithCancel(context.Background())
	now := r.now()
	task := &Task{
		id: newTaskID(), typ: taskType, label: label, status: StatusRunning,
		total: total, createdAt: now, startedAt: now, ctx: ctx, cancel: cancel,
	}
	r.mu.Lock()
	r.tasks[task.id] = task
	r.pruneLocked(now)
	r.mu.Unlock()
	return task
}

// Get returns a task by id.
func (r *Registry) Get(id string) (*Task, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	task, ok := r.tasks[id]
	return task, ok
}

// Cancel requests cooperative cancellation.
func (r *Registry) Cancel(id string) bool {
	r.mu.RLock()
	task, ok := r.tasks[id]
	r.mu.RUnlock()
	if !ok {
		return false
	}
	task.mu.Lock()
	if task.status == StatusDone || task.status == StatusError || task.status == StatusCancelled {
		task.mu.Unlock()
		return true
	}
	if task.cancel != nil {
		task.cancel()
	}
	task.mu.Unlock()
	return true
}

// ListActive returns non-terminal tasks, newest first.
func (r *Registry) ListActive() []Snapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Snapshot, 0, len(r.tasks))
	for _, task := range r.tasks {
		if task.IsTerminal() {
			continue
		}
		out = append(out, task.Snapshot())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// ListRecent returns recent tasks including terminal ones (for restore UI).
func (r *Registry) ListRecent(limit int) []Snapshot {
	if limit <= 0 {
		limit = 20
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Snapshot, 0, len(r.tasks))
	for _, task := range r.tasks {
		out = append(out, task.Snapshot())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func (r *Registry) pruneLocked(now time.Time) {
	// Drop oldest terminal tasks beyond retain, and any finished past TTL.
	type item struct {
		id   string
		task *Task
	}
	terminal := make([]item, 0)
	for id, task := range r.tasks {
		snap := task.Snapshot()
		if snap.Status != StatusDone && snap.Status != StatusError && snap.Status != StatusCancelled {
			continue
		}
		if snap.FinishedAt != nil && now.Sub(*snap.FinishedAt) > r.ttl {
			delete(r.tasks, id)
			continue
		}
		terminal = append(terminal, item{id: id, task: task})
	}
	if len(terminal) <= r.retain {
		return
	}
	sort.Slice(terminal, func(i, j int) bool {
		return terminal[i].task.Snapshot().CreatedAt.Before(terminal[j].task.Snapshot().CreatedAt)
	})
	for i := 0; i < len(terminal)-r.retain; i++ {
		delete(r.tasks, terminal[i].id)
	}
}

func newTaskID() string {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return hex.EncodeToString([]byte(time.Now().UTC().Format("20060102150405.000000000")))
	}
	return hex.EncodeToString(buf[:])
}
