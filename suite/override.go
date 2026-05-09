package suite

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/arndt-s/spiffe-conformance-test-suite/internal/harness"
)

// HarnessOverride lets a test spawn an additional SDK-harness subprocess
// with a custom environment and a short readiness timeout. It is the
// hook for tests that intentionally provoke a startup failure — for
// example, E3/E4 verifying that the SDK refuses a malformed
// SPIFFE_ENDPOINT_SOCKET.
type HarnessOverride struct {
	// ExtraEnv are KEY=VALUE entries appended to the harness's
	// environment. os/exec honours last-wins, so entries here can
	// override the suite's default values (notably
	// SPIFFE_ENDPOINT_SOCKET).
	ExtraEnv []string

	// ReadinessTimeout caps how long the helper waits for the harness
	// to print READY. Defaults to 3 seconds — long enough for healthy
	// startup on slow CI, short enough to keep negative tests fast.
	ReadinessTimeout time.Duration
}

// SpawnHarnessWithOverride launches a fresh SDK-harness subprocess
// alongside the test environment's existing one, applying the given
// override. It returns nil iff the harness reached READY before the
// timeout — in which case the caller is responsible for calling the
// returned cleanup. When the harness fails to ready within the
// timeout, it returns harness.ErrReadinessTimeout (wrapped) and a
// nil cleanup; tests asserting startup failure should treat this as
// the success case via errors.Is.
//
// The spawned process listens on its own socket — the suite's mock
// Workload API is not visible to it. The intended use is to verify
// the harness's *own* startup behaviour under a hostile environment.
func (e *TestEnv) SpawnHarnessWithOverride(
	ctx context.Context,
	override HarnessOverride,
) (cleanup func(), err error) {
	if e.cmd == "" {
		return nil, errors.New("suite: no SDK harness command recorded")
	}
	timeout := override.ReadinessTimeout
	if timeout == 0 {
		timeout = 3 * time.Second
	}

	// A throwaway socket directory the harness will fail to use —
	// callers that want a non-default socket should override
	// SPIFFE_ENDPOINT_SOCKET via ExtraEnv.
	tmp, err := os.MkdirTemp("", "spiffe-suite-override-*")
	if err != nil {
		return nil, fmt.Errorf("temp dir: %w", err)
	}
	socket := filepath.Join(tmp, "override.sock")

	process, err := harness.Start(ctx, harness.Config{
		Cmd:              e.cmd,
		Args:             e.args,
		SocketPath:       socket,
		ReadinessTimeout: timeout,
		ExtraEnv:         override.ExtraEnv,
		StdOut:           io.Discard,
		StdErr:           io.Discard,
	})
	if err != nil {
		// Whether or not the failure was the intended timeout, the
		// temp dir + (already-killed) subprocess need no further
		// cleanup from the caller.
		os.RemoveAll(tmp)
		return nil, fmt.Errorf("override harness: %w", err)
	}

	cleanup = func() {
		_ = process.Stop()
		os.RemoveAll(tmp)
	}
	return cleanup, nil
}
