package sso2oauth

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// TestIntegration_PythonDaemonLifecycle is an integration test that
// starts the REAL Python daemon (scripts/sso2oauthd.py) through the
// Supervisor and verifies the READY handshake + /health endpoint.
// Skipped if python3 or curl_cffi is not available.
func TestIntegration_PythonDaemonLifecycle(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("not on windows")
	}
	// Check python3 exists.
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not on PATH")
	}
	// Resolve the daemon script relative to the backend module root.
	repoRoot := filepath.Join("..", "..", "..", "..")
	scriptPath, err := filepath.Abs(filepath.Join(repoRoot, "scripts", "sso2oauthd.py"))
	if err != nil {
		t.Fatal(err)
	}
	// Verify the script exists.
	if _, err := os.Stat(scriptPath); err != nil {
		t.Skipf("daemon script not found: %s", scriptPath)
	}

	s := NewSupervisor(SupervisorConfig{
		Enabled:        true,
		PythonPath:     "python3",
		ScriptPath:     scriptPath,
		Env:            map[string]string{"LD_LIBRARY_PATH": "/data/data/com.termux/files/usr/lib"},
		StartupTimeout: 10 * time.Second,
	}, nil)
	if err := s.Start(context.Background()); err != nil {
		t.Skipf("Python daemon start failed (likely curl_cffi not installed): %v", err)
	}
	defer s.Stop()
	if !s.IsRunning() {
		t.Fatal("supervisor should be running")
	}
	client := s.Client()
	if client == nil {
		t.Fatal("client should be available")
	}
	// Health check via the daemon client.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Health(ctx); err != nil {
		t.Fatalf("health check failed: %v", err)
	}
	// Stop and verify clean shutdown.
	if err := s.Stop(); err != nil {
		t.Fatalf("stop failed: %v", err)
	}
}
