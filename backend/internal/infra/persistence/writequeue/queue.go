// Package writequeue coalesces high-frequency account hot-path writes into a
// single flusher (SQLite-friendly). Auth/health failures still write immediately.
package writequeue

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// Sink is the durable store for coalesced account patches.
type Sink interface {
	UpdateHealth(ctx context.Context, id uint64, failureCount int, cooldownUntil *time.Time, lastError string, success bool) error
	RecordBuildCLISuccessWithCalls(ctx context.Context, accountID uint64, at time.Time, callDelta int) error
	BumpBuildCLICallCountBy(ctx context.Context, accountID uint64, delta int) error
	UpdateIdentityMetadata(ctx context.Context, accountID uint64, email, userID, teamID string) error
}

// Config controls the single-flusher account write queue.
type Config struct {
	Enabled       bool
	BatchSize     int
	FlushInterval time.Duration
	BufferSize    int
}

// DefaultConfig returns SQLite-friendly defaults (plan §4.4).
func DefaultConfig() Config {
	return Config{
		Enabled:       true,
		BatchSize:     200,
		FlushInterval: 200 * time.Millisecond,
		BufferSize:    4096,
	}
}

// Normalize fills zero fields with defaults; disables when Enabled is false.
func (c Config) Normalize() Config {
	d := DefaultConfig()
	if !c.Enabled {
		c.BatchSize = d.BatchSize
		c.FlushInterval = d.FlushInterval
		c.BufferSize = d.BufferSize
		return c
	}
	if c.BatchSize < 1 {
		c.BatchSize = d.BatchSize
	}
	if c.BatchSize > 2000 {
		c.BatchSize = 2000
	}
	if c.FlushInterval <= 0 {
		c.FlushInterval = d.FlushInterval
	}
	if c.FlushInterval < 10*time.Millisecond {
		c.FlushInterval = 10 * time.Millisecond
	}
	if c.FlushInterval > 5*time.Second {
		c.FlushInterval = 5 * time.Second
	}
	if c.BufferSize < 64 {
		c.BufferSize = d.BufferSize
	}
	if c.BufferSize > 1<<20 {
		c.BufferSize = 1 << 20
	}
	return c
}

// Queue merges same-account patches and applies them with one flusher goroutine.
type Queue struct {
	sink   Sink
	logger *slog.Logger
	cfg    atomic.Value // Config

	notify chan struct{}
	stop   chan struct{}
	done   chan struct{}

	startOnce sync.Once
	stopOnce  sync.Once
	stopped   atomic.Bool

	mu      sync.Mutex
	pending map[uint64]*accountPatch
	depth   atomic.Int64
	flushed atomic.Uint64
	direct  atomic.Uint64
	merged  atomic.Uint64
}

type accountPatch struct {
	health      *healthPatch
	cliSuccess  *cliSuccessPatch
	cliBump     int
	identity    *identityPatch
	immediate   bool // force sync path next flush waiters — unused with sync fail path
}

type healthPatch struct {
	failureCount  int
	cooldownUntil *time.Time
	lastError     string
	success       bool
}

type cliSuccessPatch struct {
	at        time.Time
	callDelta int
}

type identityPatch struct {
	email  string
	userID string
	teamID string
}

// New creates a queue. Start must be called when Enabled.
func New(sink Sink, cfg Config, logger *slog.Logger) *Queue {
	if logger == nil {
		logger = slog.Default()
	}
	q := &Queue{
		sink:    sink,
		logger:  logger,
		notify:  make(chan struct{}, 1),
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
		pending: make(map[uint64]*accountPatch),
	}
	q.cfg.Store(cfg.Normalize())
	return q
}

// UpdateConfig hot-reloads batch/flush settings (enabled is fixed after Start for simplicity).
func (q *Queue) UpdateConfig(cfg Config) {
	if q == nil {
		return
	}
	current := q.config()
	next := cfg.Normalize()
	// Keep Enabled sticky after construction so Close/Start semantics stay simple.
	next.Enabled = current.Enabled
	q.cfg.Store(next)
	q.signal()
}

func (q *Queue) config() Config {
	if q == nil {
		return Config{}
	}
	if v, ok := q.cfg.Load().(Config); ok {
		return v
	}
	return DefaultConfig()
}

// Enabled reports whether the queue is active.
func (q *Queue) Enabled() bool {
	return q != nil && q.config().Enabled && !q.stopped.Load()
}

// Stats exposes queue depth and counters for ops/logging.
func (q *Queue) Stats() (depth int64, flushed, direct, merged uint64) {
	if q == nil {
		return 0, 0, 0, 0
	}
	return q.depth.Load(), q.flushed.Load(), q.direct.Load(), q.merged.Load()
}

// Start launches the single flusher. Idempotent.
func (q *Queue) Start() {
	if q == nil || !q.config().Enabled {
		return
	}
	q.startOnce.Do(func() {
		go q.run()
	})
}

// Close stops the flusher and applies remaining patches. Safe to call once.
func (q *Queue) Close(ctx context.Context) error {
	if q == nil {
		return nil
	}
	if !q.config().Enabled {
		return nil
	}
	q.stopOnce.Do(func() {
		q.stopped.Store(true)
		close(q.stop)
	})
	select {
	case <-q.done:
	case <-ctx.Done():
		// Best-effort final flush under caller's context if worker already stopped racing.
		q.flushOnce(ctx)
		return ctx.Err()
	case <-time.After(10 * time.Second):
		q.flushOnce(context.Background())
		return errors.New("writequeue close timeout")
	}
	return nil
}

// UpdateHealth applies failure patches immediately; success patches are coalesced.
func (q *Queue) UpdateHealth(ctx context.Context, id uint64, failureCount int, cooldownUntil *time.Time, lastError string, success bool) error {
	if id == 0 || q == nil || q.sink == nil {
		return nil
	}
	if !q.Enabled() || !success {
		q.direct.Add(1)
		return q.sink.UpdateHealth(ctx, id, failureCount, cooldownUntil, lastError, success)
	}
	q.enqueueHealth(id, healthPatch{
		failureCount:  failureCount,
		cooldownUntil: cloneTimePtr(cooldownUntil),
		lastError:     lastError,
		success:       true,
	})
	return nil
}

// RecordBuildCLISuccessWithCalls coalesces call deltas and success timestamps.
func (q *Queue) RecordBuildCLISuccessWithCalls(ctx context.Context, accountID uint64, at time.Time, callDelta int) error {
	if accountID == 0 || q == nil || q.sink == nil {
		return nil
	}
	if !q.Enabled() {
		q.direct.Add(1)
		return q.sink.RecordBuildCLISuccessWithCalls(ctx, accountID, at, callDelta)
	}
	if callDelta < 1 {
		callDelta = 1
	}
	q.enqueueCLISuccess(accountID, at, callDelta)
	return nil
}

// BumpBuildCLICallCountBy coalesces load-spreading call bumps.
func (q *Queue) BumpBuildCLICallCountBy(ctx context.Context, accountID uint64, delta int) error {
	if accountID == 0 || delta < 1 || q == nil || q.sink == nil {
		return nil
	}
	if !q.Enabled() {
		q.direct.Add(1)
		return q.sink.BumpBuildCLICallCountBy(ctx, accountID, delta)
	}
	q.enqueueCLIBump(accountID, delta)
	return nil
}

// UpdateIdentityMetadata coalesces identity field updates (last non-empty wins).
func (q *Queue) UpdateIdentityMetadata(ctx context.Context, accountID uint64, email, userID, teamID string) error {
	if accountID == 0 || q == nil || q.sink == nil {
		return nil
	}
	if !q.Enabled() {
		q.direct.Add(1)
		return q.sink.UpdateIdentityMetadata(ctx, accountID, email, userID, teamID)
	}
	q.enqueueIdentity(accountID, identityPatch{email: email, userID: userID, teamID: teamID})
	return nil
}

// Flush applies all pending patches synchronously (tests / critical sections).
func (q *Queue) Flush(ctx context.Context) error {
	if q == nil || q.sink == nil {
		return nil
	}
	if !q.config().Enabled {
		return nil
	}
	q.flushOnce(ctx)
	return nil
}

func (q *Queue) enqueueHealth(id uint64, patch healthPatch) {
	q.mu.Lock()
	p := q.ensureLocked(id)
	if p.health != nil {
		q.merged.Add(1)
	}
	p.health = &patch
	q.mu.Unlock()
	q.signal()
}

func (q *Queue) enqueueCLISuccess(id uint64, at time.Time, callDelta int) {
	q.mu.Lock()
	p := q.ensureLocked(id)
	if p.cliSuccess != nil {
		q.merged.Add(1)
		p.cliSuccess.callDelta += callDelta
		if at.After(p.cliSuccess.at) {
			p.cliSuccess.at = at
		}
	} else {
		p.cliSuccess = &cliSuccessPatch{at: at, callDelta: callDelta}
	}
	// success record absorbs pending bare bumps
	if p.cliBump > 0 {
		p.cliSuccess.callDelta += p.cliBump
		p.cliBump = 0
	}
	q.mu.Unlock()
	q.signal()
}

func (q *Queue) enqueueCLIBump(id uint64, delta int) {
	q.mu.Lock()
	p := q.ensureLocked(id)
	if p.cliSuccess != nil {
		q.merged.Add(1)
		p.cliSuccess.callDelta += delta
	} else {
		if p.cliBump > 0 {
			q.merged.Add(1)
		}
		p.cliBump += delta
	}
	q.mu.Unlock()
	q.signal()
}

func (q *Queue) enqueueIdentity(id uint64, patch identityPatch) {
	q.mu.Lock()
	p := q.ensureLocked(id)
	if p.identity != nil {
		q.merged.Add(1)
		if patch.email != "" {
			p.identity.email = patch.email
		}
		if patch.userID != "" {
			p.identity.userID = patch.userID
		}
		if patch.teamID != "" {
			p.identity.teamID = patch.teamID
		}
	} else {
		p.identity = &patch
	}
	q.mu.Unlock()
	q.signal()
}

func (q *Queue) ensureLocked(id uint64) *accountPatch {
	p, ok := q.pending[id]
	if !ok {
		p = &accountPatch{}
		q.pending[id] = p
		q.depth.Add(1)
	}
	return p
}

func (q *Queue) signal() {
	select {
	case q.notify <- struct{}{}:
	default:
	}
}

func (q *Queue) run() {
	defer close(q.done)
	cfg := q.config()
	ticker := time.NewTicker(cfg.FlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-q.stop:
			q.flushOnce(context.Background())
			return
		case <-q.notify:
			if q.depth.Load() >= int64(q.config().BatchSize) {
				q.flushOnce(context.Background())
			}
		case <-ticker.C:
			if q.depth.Load() > 0 {
				q.flushOnce(context.Background())
			}
			// refresh interval if config changed
			next := q.config().FlushInterval
			if next > 0 {
				ticker.Reset(next)
			}
		}
	}
}

func (q *Queue) flushOnce(ctx context.Context) {
	batch := q.takeBatch(q.config().BatchSize)
	if len(batch) == 0 {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	// Bound individual flush so a stuck DB does not hang the flusher forever.
	flushCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	var healthErr, cliErr, idErr error
	for id, patch := range batch {
		if patch.health != nil {
			h := patch.health
			if err := q.sink.UpdateHealth(flushCtx, id, h.failureCount, h.cooldownUntil, h.lastError, h.success); err != nil {
				healthErr = errors.Join(healthErr, err)
			}
		}
		if patch.cliSuccess != nil {
			c := patch.cliSuccess
			if err := q.sink.RecordBuildCLISuccessWithCalls(flushCtx, id, c.at, c.callDelta); err != nil {
				cliErr = errors.Join(cliErr, err)
			}
		} else if patch.cliBump > 0 {
			if err := q.sink.BumpBuildCLICallCountBy(flushCtx, id, patch.cliBump); err != nil {
				cliErr = errors.Join(cliErr, err)
			}
		}
		if patch.identity != nil {
			i := patch.identity
			if err := q.sink.UpdateIdentityMetadata(flushCtx, id, i.email, i.userID, i.teamID); err != nil {
				idErr = errors.Join(idErr, err)
			}
		}
		q.flushed.Add(1)
	}
	if err := errors.Join(healthErr, cliErr, idErr); err != nil {
		q.logger.Warn("account_write_queue_flush_failed", "batch", len(batch), "error", err)
	}
}

func (q *Queue) takeBatch(limit int) map[uint64]*accountPatch {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.pending) == 0 {
		return nil
	}
	if limit < 1 {
		limit = len(q.pending)
	}
	out := make(map[uint64]*accountPatch, min(limit, len(q.pending)))
	for id, patch := range q.pending {
		out[id] = patch
		delete(q.pending, id)
		q.depth.Add(-1)
		if len(out) >= limit {
			break
		}
	}
	return out
}

func cloneTimePtr(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copied := value.UTC()
	return &copied
}
