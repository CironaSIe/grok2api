package sso2oauth

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SupervisorConfig controls the Python daemon subprocess lifecycle.
type SupervisorConfig struct {
	Enabled        bool
	PythonPath     string
	ScriptPath     string
	Env            map[string]string
	StartupTimeout time.Duration
	HealthInterval time.Duration
	MaxRestarts    int
	RestartWindow  time.Duration
}

// Supervisor manages a Python sso2oauth daemon subprocess: it starts
// the daemon, waits for the READY handshake on stdout, builds a Client
// for the discovered port, runs a background health-check loop with
// crash-restart, and provides graceful shutdown via /shutdown.
type Supervisor struct {
	cfg           SupervisorConfig
	client        *Client
	cmd           *exec.Cmd
	port          int
	mu            sync.Mutex
	stop          chan struct{}
	stopOnce      sync.Once
	wg            sync.WaitGroup
	restartCount  int
	restartWindow time.Time
	logger        *slog.Logger
}

// NewSupervisor returns a Supervisor with sensible defaults for any
// unset duration fields. A nil logger falls back to slog.Default().
func NewSupervisor(cfg SupervisorConfig, logger *slog.Logger) *Supervisor {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.StartupTimeout <= 0 {
		cfg.StartupTimeout = 15 * time.Second
	}
	if cfg.HealthInterval <= 0 {
		cfg.HealthInterval = 30 * time.Second
	}
	if cfg.MaxRestarts <= 0 {
		cfg.MaxRestarts = 5
	}
	if cfg.RestartWindow <= 0 {
		cfg.RestartWindow = 10 * time.Minute
	}
	return &Supervisor{cfg: cfg, logger: logger, stop: make(chan struct{})}
}

// Start launches the daemon subprocess, waits for its READY handshake
// (or until ctx is cancelled / StartupTimeout fires), and starts the
// background health-check goroutine. Returns an error if the daemon
// did not become ready.
func (s *Supervisor) Start(ctx context.Context) error {
	if err := s.startProcess(ctx); err != nil {
		return err
	}
	s.wg.Add(1)
	go s.healthLoop()
	return nil
}

// startProcess spawns the daemon, reads stdout for the "READY port=N"
// line, and stores the resulting Client. The subprocess lifetime is
// NOT tied to ctx — the process runs until Stop/kill, so that a
// short-lived caller context cannot tear down a long-running daemon.
// ctx is only consulted for cancellation of the startup wait itself.
func (s *Supervisor) startProcess(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cmd := exec.Command(s.cfg.PythonPath, s.cfg.ScriptPath, "--port", "0")
	cmd.Env = os.Environ()
	for k, v := range s.cfg.Env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("创建 stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("启动 Python daemon: %w", err)
	}
	s.cmd = cmd
	// 等待 READY 信号
	readyCh := make(chan int, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "READY port=") {
				portStr := strings.TrimPrefix(line, "READY port=")
				if port, err := strconv.Atoi(portStr); err == nil {
					readyCh <- port
					// 继续读 stdout（避免 pipe 阻塞），丢弃后续输出
					go io.Copy(io.Discard, stdout)
					return
				}
			}
		}
		readyCh <- 0
	}()
	select {
	case port := <-readyCh:
		if port == 0 {
			_ = cmd.Process.Kill()
			go cmd.Wait()
			s.cmd = nil
			return errors.New("Python daemon 未输出有效 READY 信号")
		}
		s.port = port
		s.client = NewClient(fmt.Sprintf("http://127.0.0.1:%d", port), s.logger)
	case <-time.After(s.cfg.StartupTimeout):
		_ = cmd.Process.Kill()
		go cmd.Wait()
		s.cmd = nil
		return fmt.Errorf("等待 Python daemon READY 超时 (%s)", s.cfg.StartupTimeout)
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		go cmd.Wait()
		s.cmd = nil
		return fmt.Errorf("启动被取消: %w", ctx.Err())
	}
	return nil
}

// Stop signals the health loop to exit, sends /shutdown to the daemon,
// then waits up to 5s for the process to exit before force-killing.
// Safe to call multiple times (idempotent via stopOnce).
func (s *Supervisor) Stop() error {
	s.stopOnce.Do(func() { close(s.stop) })
	s.wg.Wait()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cmd == nil || s.cmd.Process == nil {
		return nil
	}
	// 优雅关闭：请求 daemon 的 /shutdown 端点
	if s.client != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.client.baseURL+"/shutdown", nil)
		if err == nil {
			if resp, err := s.client.httpClient.Do(req); err == nil {
				resp.Body.Close()
			}
		}
	}
	done := make(chan struct{})
	go func() { _ = s.cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = s.cmd.Process.Kill()
		_ = s.cmd.Wait()
	}
	return nil
}

// Client returns the HTTP client for talking to the running daemon,
// or nil if the daemon has not started / has been stopped.
func (s *Supervisor) Client() *Client {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.client
}

// IsRunning reports whether the daemon process is currently alive.
func (s *Supervisor) IsRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cmd != nil && s.cmd.Process != nil
}

// healthLoop periodically GETs /health. After 3 consecutive failures
// it triggers a restart, subject to MaxRestarts within RestartWindow.
func (s *Supervisor) healthLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(s.cfg.HealthInterval)
	defer ticker.Stop()
	failures := 0
	for {
		select {
		case <-s.stop:
			return
		case <-ticker.C:
			client := s.Client()
			if client == nil {
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			err := client.Health(ctx)
			cancel()
			if err != nil {
				failures++
				if failures >= 3 {
					s.logger.Warn("sso2oauth_daemon_health_failed", "failures", failures, "error", err)
					s.restart()
					failures = 0
				}
			} else {
				failures = 0
			}
		}
	}
}

// restart kills the current daemon and starts a new one, respecting
// MaxRestarts within a sliding RestartWindow. Caller (healthLoop) does
// NOT hold the lock when invoking this.
func (s *Supervisor) restart() {
	s.mu.Lock()
	now := time.Now()
	if now.Sub(s.restartWindow) > s.cfg.RestartWindow {
		s.restartCount = 0
		s.restartWindow = now
	}
	s.restartCount++
	if s.restartCount > s.cfg.MaxRestarts {
		s.logger.Error("sso2oauth_daemon_restart_limit_exceeded", "count", s.restartCount, "window", s.cfg.RestartWindow)
		s.mu.Unlock()
		return
	}
	if s.cmd != nil && s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
		_ = s.cmd.Wait()
	}
	s.mu.Unlock()
	time.Sleep(5 * time.Second)
	if err := s.startProcess(context.Background()); err != nil {
		s.logger.Error("sso2oauth_daemon_restart_failed", "error", err)
	}
}
