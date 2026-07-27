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

func TestTaskFailWithResult(t *testing.T) {
	reg := NewRegistry()
	task := reg.Start("convert", "c", 2)
	task.Record(false)
	task.Record(false)
	task.FailWithResult("boom", map[string]any{"failures": []map[string]any{{"accountId": 1, "message": "err"}}})
	snap := task.Snapshot()
	if snap.Status != StatusError {
		t.Fatalf("status=%s, want error", snap.Status)
	}
	if snap.Error != "boom" {
		t.Fatalf("error=%q, want boom", snap.Error)
	}
	if snap.Result == nil || snap.Result["failures"] == nil {
		t.Fatalf("result missing: %+v", snap.Result)
	}
	if !task.IsTerminal() {
		t.Fatal("expected terminal")
	}
}

func TestTaskFailWithResultDoesNotOverrideTerminal(t *testing.T) {
	reg := NewRegistry()
	done := reg.Start("done", "d", 0)
	done.Finish(map[string]any{"ok": 1})
	done.FailWithResult("late", map[string]any{"ok": 0})
	if done.Snapshot().Status != StatusDone || done.Snapshot().Error != "" {
		t.Fatalf("done overwritten: %+v", done.Snapshot())
	}

	cancelled := reg.Start("cancelled", "c", 0)
	cancelled.MarkCancelled()
	cancelled.FailWithResult("late", map[string]any{"ok": 0})
	if cancelled.Snapshot().Status != StatusCancelled || cancelled.Snapshot().Error != "" {
		t.Fatalf("cancelled overwritten: %+v", cancelled.Snapshot())
	}
}
