// Package harness manages the lifecycle of an SDK subprocess under test.
package harness

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"
)

const defaultReadinessTimeout = 5 * time.Minute

// Config holds the parameters for spawning the SDK harness.
type Config struct {
	// Cmd is the binary path to spawn.
	Cmd string
	// Args are the command-line arguments.
	Args []string
	// SocketPath is the UDS path set via SPIFFE_ENDPOINT_SOCKET.
	SocketPath string
	// ReadinessTimeout overrides the default 10 s readiness timeout.
	ReadinessTimeout time.Duration
	// ExtraEnv is additional environment variables beyond the inherited set.
	ExtraEnv []string

	// StdOut and StdErr are optional writers for the subprocess's stdout and stderr.
	StdOut io.Writer
	StdErr io.Writer
}

// RunningProcess represents a spawned SDK harness process.
type RunningProcess struct {
	cmd        *exec.Cmd
	Readiness  Readiness
	cancelFunc context.CancelFunc
}

// Start spawns the harness subprocess and waits until it signals readiness.
// ctx is the parent context; Start creates a child context with timeout for
// readiness detection only — the subprocess continues to run after Start returns.
func Start(ctx context.Context, cfg Config) (*RunningProcess, error) {
	timeout := cfg.ReadinessTimeout
	if timeout == 0 {
		timeout = defaultReadinessTimeout
	}

	readinessCtx, cancel := context.WithTimeout(ctx, timeout)

	procCtx, procCancel := context.WithCancel(ctx)

	cmd := exec.CommandContext(procCtx, cfg.Cmd, cfg.Args...)
	cmd.Env = buildEnv(cfg)

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		procCancel()
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}

	// Set stderr to the configured writer, or discard if nil.
	if cfg.StdErr != nil {
		cmd.Stderr = cfg.StdErr
	} else {
		cmd.Stderr = io.Discard
	}

	if err := cmd.Start(); err != nil {
		cancel()
		procCancel()
		return nil, fmt.Errorf("start process: %w", err)
	}

	rp := &RunningProcess{
		cmd:        cmd,
		cancelFunc: procCancel,
	}

	// Read readiness in a goroutine so we can respect the timeout.
	type result struct {
		r   Readiness
		err error
	}
	ch := make(chan result, 1)

	go func() {
		var r Readiness

		// Create a TeeReader if StdOut is configured, so we can parse readiness
		// while also writing to the configured writer
		reader := io.Reader(stdoutPipe)
		if cfg.StdOut != nil {
			reader = io.TeeReader(stdoutPipe, cfg.StdOut)
		}

		err := parseStdout(reader, &r)
		ch <- result{r, err}

		// Drain remaining stdout to prevent pipe buffer filling
		if cfg.StdOut != nil {
			_, _ = io.Copy(cfg.StdOut, stdoutPipe)
		} else {
			_, _ = io.Copy(io.Discard, stdoutPipe)
		}
	}()

	select {
	case <-readinessCtx.Done():
		cancel()
		_ = cmd.Process.Kill()
		procCancel()
		return nil, fmt.Errorf("readiness timeout after %s", timeout)
	case res := <-ch:
		cancel()
		if res.err != nil {
			procCancel()
			return nil, fmt.Errorf("readiness parse: %w", res.err)
		}
		rp.Readiness = res.r
		return rp, nil
	}
}

// Stop terminates the subprocess and waits for it to exit.
func (rp *RunningProcess) Stop() error {
	rp.cancelFunc()
	return rp.cmd.Wait()
}

// X509Port returns the port on which the harness serves X.509 SVIDs.
func (rp *RunningProcess) X509Port() int { return rp.Readiness.X509Port }

// JWTPort returns the port on which the harness serves JWT SVIDs.
func (rp *RunningProcess) JWTPort() int { return rp.Readiness.JWTPort }

// ControlPort returns the harness's control HTTP port, or 0 if the
// harness did not advertise one.
func (rp *RunningProcess) ControlPort() int { return rp.Readiness.ControlPort }

// buildEnv assembles the env slice for the subprocess. os/exec respects
// the last occurrence of any duplicate KEY=VAL entry, so callers can
// override SPIFFE_ENDPOINT_SOCKET (or anything else) by appending to
// ExtraEnv.
func buildEnv(cfg Config) []string {
	env := os.Environ()
	env = append(env, fmt.Sprintf("SPIFFE_ENDPOINT_SOCKET=unix://%s", cfg.SocketPath))
	env = append(env, cfg.ExtraEnv...)
	return env
}
