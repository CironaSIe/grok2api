package admintask

import (
	"testing"
	"time"
)

func TestRegistryStartProgressFinishAndCancel(t *testing.T) {
	reg := NewRegistry()
	task := reg.Start("web_scripts", "test", 2)
	if task.ID() == "" {
		t.Fatal("empty id")
	}
	task.Record(true)
	task.Record(false)
	snap := task.Snapshot()
	if snap.Processed != 2 || snap.OK != 1 || snap.Fail != 1 || snap.Status != StatusRunning {
		t.Fatalf("snap=%+v", snap)
	}
	task.Finish(map[string]any{"succeeded": 1, "failed": 1})
	if !task.IsTerminal() || task.Snapshot().Status != StatusDone {
		t.Fatalf("expected done, got %+v", task.Snapshot())
	}
	active := reg.ListActive()
	if len(active) != 0 {
		t.Fatalf("active=%v", active)
	}
	got, ok := reg.Get(task.ID())
	if !ok || got.Snapshot().Result["succeeded"] != 1 {
		t.Fatalf("get result missing")
	}

	running := reg.Start("convert", "c", 10)
	if !reg.Cancel(running.ID()) {
		t.Fatal("cancel")
	}
	select {
	case <-running.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("context not cancelled")
	}
	running.MarkCancelled()
	if running.Snapshot().Status != StatusCancelled {
		t.Fatalf("status=%s", running.Snapshot().Status)
	}
}

func TestRegistryPruneRespectsRetain(t *testing.T) {
	reg := NewRegistry()
	reg.retain = 2
	reg.ttl = time.Hour
	for i := 0; i < 5; i++ {
		task := reg.Start("t", "l", 0)
		task.Finish(nil)
	}
	// trigger prune via another start
	_ = reg.Start("live", "live", 1)
	reg.mu.RLock()
	terminal := 0
	for _, task := range reg.tasks {
		if task.IsTerminal() {
			terminal++
		}
	}
	reg.mu.RUnlock()
	if terminal > reg.retain {
		t.Fatalf("terminal=%d retain=%d", terminal, reg.retain)
	}
}
