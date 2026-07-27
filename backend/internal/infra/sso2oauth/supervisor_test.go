package sso2oauth

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// mockDaemonScript generates a shell script that mimics the Python
// daemon's READY handshake: it prints "READY port=<port>" then keeps
// running until killed. It does NOT listen on the port — tests only
// verify the supervisor's process lifecycle, not HTTP traffic.
func mockDaemonScript(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("mock daemon script is shell-based")
	}
	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "mock_daemon.sh")
	script := `#!/bin/sh
echo "READY port=$MOCK_PORT"
# keep running until killed
while true; do sleep 0.5; done
`
	if err := os.WriteFile(scriptPath, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	return scriptPath
}

func TestSupervisor_StartAndStop(t *testing.T) {
	script := mockDaemonScript(t)
	s := NewSupervisor(SupervisorConfig{
		Enabled:        true,
		PythonPath:     "/bin/sh",
		ScriptPath:     script,
		Env:            map[string]string{"MOCK_PORT": "18080"},
		StartupTimeout: 5 * time.Second,
	}, nil)
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("start failed: %v", err)
	}
	if !s.IsRunning() {
		t.Fatal("supervisor should be running")
	}
	if s.Client() == nil {
		t.Fatal("client should be available after start")
	}
	if err := s.Stop(); err != nil {
		t.Fatalf("stop failed: %v", err)
	}
}

func TestSupervisor_StartTimeout(t *testing.T) {
	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "no_ready.sh")
	// 不输出 READY 行 → 超时
	if err := os.WriteFile(scriptPath, []byte("#!/bin/sh\nwhile true; do sleep 1; done\n"), 0755); err != nil {
		t.Fatal(err)
	}
	s := NewSupervisor(SupervisorConfig{
		Enabled:        true,
		PythonPath:     "/bin/sh",
		ScriptPath:     scriptPath,
		StartupTimeout: 2 * time.Second,
	}, nil)
	err := s.Start(context.Background())
	if err == nil {
		_ = s.Stop()
		t.Fatal("expected timeout error")
	}
}

func TestSupervisor_StopIdempotent(t *testing.T) {
	script := mockDaemonScript(t)
	s := NewSupervisor(SupervisorConfig{
		Enabled:        true,
		PythonPath:     "/bin/sh",
		ScriptPath:     script,
		Env:            map[string]string{"MOCK_PORT": "18081"},
		StartupTimeout: 5 * time.Second,
	}, nil)
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("start failed: %v", err)
	}
	if err := s.Stop(); err != nil {
		t.Fatalf("first stop failed: %v", err)
	}
	// Second Stop must not panic (close-on-panic guard).
	if err := s.Stop(); err != nil {
		t.Fatalf("second stop failed: %v", err)
	}
}
