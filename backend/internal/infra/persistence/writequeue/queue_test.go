package writequeue

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type memSink struct {
	mu       sync.Mutex
	health   map[uint64]healthPatch
	cli      map[uint64]cliSuccessPatch
	bumps    map[uint64]int
	identity map[uint64]identityPatch
	healthN  atomic.Int64
	cliN     atomic.Int64
	bumpN    atomic.Int64
	idN      atomic.Int64
}

func newMemSink() *memSink {
	return &memSink{
		health:   make(map[uint64]healthPatch),
		cli:      make(map[uint64]cliSuccessPatch),
		bumps:    make(map[uint64]int),
		identity: make(map[uint64]identityPatch),
	}
}

func (m *memSink) UpdateHealth(_ context.Context, id uint64, failureCount int, cooldownUntil *time.Time, lastError string, success bool) error {
	m.healthN.Add(1)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.health[id] = healthPatch{failureCount: failureCount, cooldownUntil: cloneTimePtr(cooldownUntil), lastError: lastError, success: success}
	return nil
}

func (m *memSink) RecordBuildCLISuccessWithCalls(_ context.Context, accountID uint64, at time.Time, callDelta int) error {
	m.cliN.Add(1)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cli[accountID] = cliSuccessPatch{at: at, callDelta: callDelta}
	return nil
}

func (m *memSink) BumpBuildCLICallCountBy(_ context.Context, accountID uint64, delta int) error {
	m.bumpN.Add(1)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bumps[accountID] += delta
	return nil
}

func (m *memSink) UpdateIdentityMetadata(_ context.Context, accountID uint64, email, userID, teamID string) error {
	m.idN.Add(1)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.identity[accountID] = identityPatch{email: email, userID: userID, teamID: teamID}
	return nil
}

func TestQueueCoalescesSuccessAndIdentity(t *testing.T) {
	sink := newMemSink()
	q := New(sink, Config{Enabled: true, BatchSize: 50, FlushInterval: time.Hour, BufferSize: 64}, nil)
	q.Start()
	t.Cleanup(func() {
		_ = q.Close(context.Background())
	})

	ctx := context.Background()
	now := time.Now().UTC()
	for i := 0; i < 10; i++ {
		if err := q.UpdateHealth(ctx, 7, 0, nil, "", true); err != nil {
			t.Fatal(err)
		}
		if err := q.RecordBuildCLISuccessWithCalls(ctx, 7, now.Add(time.Duration(i)*time.Second), 1); err != nil {
			t.Fatal(err)
		}
		if err := q.UpdateIdentityMetadata(ctx, 7, "a@x.ai", "u1", ""); err != nil {
			t.Fatal(err)
		}
	}
	if err := q.UpdateIdentityMetadata(ctx, 7, "", "u2", "t9"); err != nil {
		t.Fatal(err)
	}
	if err := q.Flush(ctx); err != nil {
		t.Fatal(err)
	}

	if sink.healthN.Load() != 1 {
		t.Fatalf("health writes=%d want 1", sink.healthN.Load())
	}
	if sink.cliN.Load() != 1 {
		t.Fatalf("cli writes=%d want 1", sink.cliN.Load())
	}
	if sink.idN.Load() != 1 {
		t.Fatalf("identity writes=%d want 1", sink.idN.Load())
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if sink.cli[7].callDelta != 10 {
		t.Fatalf("callDelta=%d want 10", sink.cli[7].callDelta)
	}
	if sink.identity[7].email != "a@x.ai" || sink.identity[7].userID != "u2" || sink.identity[7].teamID != "t9" {
		t.Fatalf("identity=%+v", sink.identity[7])
	}
	if !sink.health[7].success {
		t.Fatal("expected success health")
	}
}

func TestQueueFailureWritesImmediately(t *testing.T) {
	sink := newMemSink()
	q := New(sink, Config{Enabled: true, BatchSize: 50, FlushInterval: time.Hour, BufferSize: 64}, nil)
	q.Start()
	t.Cleanup(func() {
		_ = q.Close(context.Background())
	})

	until := time.Now().UTC().Add(time.Minute)
	if err := q.UpdateHealth(context.Background(), 3, 2, &until, "upstream status 429", false); err != nil {
		t.Fatal(err)
	}
	if sink.healthN.Load() != 1 {
		t.Fatalf("health writes=%d want immediate 1", sink.healthN.Load())
	}
	depth, _, direct, _ := q.Stats()
	if depth != 0 || direct != 1 {
		t.Fatalf("depth=%d direct=%d", depth, direct)
	}
}

func TestQueueDisabledPassthrough(t *testing.T) {
	sink := newMemSink()
	q := New(sink, Config{Enabled: false}, nil)
	if err := q.UpdateHealth(context.Background(), 1, 0, nil, "", true); err != nil {
		t.Fatal(err)
	}
	if sink.healthN.Load() != 1 {
		t.Fatalf("disabled queue should direct-write, got %d", sink.healthN.Load())
	}
}

func TestQueueCLIBumpMergesIntoSuccess(t *testing.T) {
	sink := newMemSink()
	q := New(sink, Config{Enabled: true, BatchSize: 10, FlushInterval: time.Hour, BufferSize: 32}, nil)
	q.Start()
	t.Cleanup(func() { _ = q.Close(context.Background()) })
	ctx := context.Background()
	_ = q.BumpBuildCLICallCountBy(ctx, 9, 3)
	_ = q.RecordBuildCLISuccessWithCalls(ctx, 9, time.Now().UTC(), 2)
	_ = q.Flush(ctx)
	if sink.bumpN.Load() != 0 {
		t.Fatalf("bare bump should merge into success write, bumpN=%d", sink.bumpN.Load())
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if sink.cli[9].callDelta != 5 {
		t.Fatalf("callDelta=%d want 5", sink.cli[9].callDelta)
	}
}
