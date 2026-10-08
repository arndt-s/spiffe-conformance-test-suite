// Package harness manages the lifecycle of an SDK subprocess under test.
package harness

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	// DefaultReadinessTimeout is how long Start waits for READY.
	DefaultReadinessTimeout = 10 * time.Second
	// stopGrace is how long Stop waits after SIGTERM before SIGKILL.
	stopGrace = 5 * time.Second
	// stderrTailBytes is how much of the harness's stderr is kept for reports.
	stderrTailBytes = 4096
)

// Config holds the parameters for spawning the SDK harness.
type Config struct {
	// Cmd is the binary path to spawn.
	Cmd string
	// Args are the command-line arguments.
	Args []string
	// Endpoint is the value of SPIFFE_ENDPOINT_SOCKET, e.g. "unix:///tmp/x/api.sock".
	Endpoint string
	// ReadinessTimeout overrides DefaultReadinessTimeout.
	ReadinessTimeout time.Duration
	// ExtraEnv is additional environment variables beyond the inherited set.
	ExtraEnv []string

	// StdOut and StdErr optionally receive a copy of the subprocess's output.
	StdOut io.Writer
	StdErr io.Writer
}

// RunningProcess represents a spawned SDK harness process.
type RunningProcess struct {
	cmd       *exec.Cmd
	Readiness Readiness
	stderr    *tailBuffer
	done      chan struct{}
	stopOnce  sync.Once
}

// Start spawns the harness in its own process group and waits until it signals
// readiness. On failure the process is stopped and the error includes the tail
// of its stderr.
func Start(ctx context.Context, cfg Config) (*RunningProcess, error) {
	timeout := cfg.ReadinessTimeout
	if timeout == 0 {
		timeout = DefaultReadinessTimeout
	}

	cmd := exec.Command(cfg.Cmd, cfg.Args...)
	cmd.Env = buildEnv(cfg)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}
	tail := &tailBuffer{max: stderrTailBytes}
	if cfg.StdErr != nil {
		cmd.Stderr = io.MultiWriter(tail, cfg.StdErr)
	} else {
		cmd.Stderr = tail
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start process: %w", err)
	}

	rp := &RunningProcess{cmd: cmd, stderr: tail, done: make(chan struct{})}
	go func() {
		_ = cmd.Wait()
		close(rp.done)
	}()

	type result struct {
		r   Readiness
		err error
	}
	ch := make(chan result, 1)
	go func() {
		reader := io.Reader(stdoutPipe)
		if cfg.StdOut != nil {
			reader = io.TeeReader(stdoutPipe, cfg.StdOut)
		}
		var r Readiness
		err := parseStdout(reader, &r)
		ch <- result{r, err}
		// Keep draining so the harness never blocks on a full pipe.
		_, _ = io.Copy(io.Discard, reader)
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case res := <-ch:
		if res.err != nil {
			rp.Stop()
			return nil, rp.withStderr(fmt.Errorf("readiness: %w", res.err))
		}
		rp.Readiness = res.r
		return rp, nil
	case <-timer.C:
		rp.Stop()
		return nil, rp.withStderr(fmt.Errorf("no READY within %s", timeout))
	case <-ctx.Done():
		rp.Stop()
		return nil, ctx.Err()
	}
}

// Stop sends SIGTERM to the harness's process group, waits up to stopGrace,
// then sends SIGKILL. It is safe to call more than once.
func (rp *RunningProcess) Stop() {
	rp.stopOnce.Do(func() {
		pgid := -rp.cmd.Process.Pid
		_ = syscall.Kill(pgid, syscall.SIGTERM)
		select {
		case <-rp.done:
		case <-time.After(stopGrace):
		}
		// Kill whatever is left of the group, including orphaned children.
		_ = syscall.Kill(pgid, syscall.SIGKILL)
		<-rp.done
	})
}

// StderrTail returns the last few KiB the harness wrote to stderr.
func (rp *RunningProcess) StderrTail() string { return rp.stderr.String() }

func (rp *RunningProcess) withStderr(err error) error {
	tail := strings.TrimSpace(rp.StderrTail())
	if tail == "" {
		return err
	}
	return fmt.Errorf("%w\n--- harness stderr (tail) ---\n%s", err, tail)
}

// Version returns the harness contract version.
func (rp *RunningProcess) Version() int { return rp.Readiness.Version }

// X509Port returns the port on which the harness serves X.509 SVIDs.
func (rp *RunningProcess) X509Port() int { return rp.Readiness.X509Port }

// JWTPort returns the v0 JWT validation port.
func (rp *RunningProcess) JWTPort() int { return rp.Readiness.JWTPort }

// ControlPort returns the v1 control port.
func (rp *RunningProcess) ControlPort() int { return rp.Readiness.ControlPort }

func buildEnv(cfg Config) []string {
	env := make([]string, 0, len(os.Environ())+len(cfg.ExtraEnv)+1)
	for _, e := range os.Environ() {
		// The harness must discover the endpoint only from what the suite sets.
		if strings.HasPrefix(e, "SPIFFE_ENDPOINT_SOCKET=") {
			continue
		}
		env = append(env, e)
	}
	env = append(env, "SPIFFE_ENDPOINT_SOCKET="+cfg.Endpoint)
	return append(env, cfg.ExtraEnv...)
}

// tailBuffer keeps the last max bytes written to it.
type tailBuffer struct {
	mu  sync.Mutex
	max int
	buf []byte
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = append(t.buf, p...)
	if len(t.buf) > t.max {
		t.buf = t.buf[len(t.buf)-t.max:]
	}
	return len(p), nil
}

func (t *tailBuffer) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(t.buf)
}
