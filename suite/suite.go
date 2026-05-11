// Package suite provides the test case registry and runner for the SPIFFE
// Conformance Test Suite.
package suite

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/arndt-s/spiffe-conformance-test-suite/internal/result"
)

// TestFunc is the signature every test case must implement.
type TestFunc func(ctx context.Context, env *TestEnv) error

// TestCase is the unit of work registered into the suite.
type TestCase struct {
	Name        string
	Description string
	Run         TestFunc
}

var (
	mu       sync.RWMutex
	registry []TestCase
)

// Register adds a test case to the global registry. Typically called from
// an init() function in a test-case file.
func Register(tc TestCase) {
	mu.Lock()
	defer mu.Unlock()
	registry = append(registry, tc)
}

// All returns a snapshot of all registered test cases.
func All() []TestCase {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]TestCase, len(registry))
	copy(out, registry)
	return out
}

// Lookup returns the test case with the given name, or an error if not found.
func Lookup(name string) (TestCase, error) {
	mu.RLock()
	defer mu.RUnlock()
	for _, tc := range registry {
		if tc.Name == name {
			return tc, nil
		}
	}
	return TestCase{}, fmt.Errorf("test case %q not found", name)
}

// RunnerConfig holds the parameters needed to run test cases.
type RunnerConfig struct {
	// Cmd is the SDK harness binary path.
	Cmd string
	// Args are the arguments to pass to the harness.
	Args []string

	StOut io.Writer
	StErr io.Writer
}

// RunAll runs every registered test case and returns a Report.
func RunAll(ctx context.Context, cfg RunnerConfig) result.Report {
	var report result.Report
	for _, tc := range All() {
		report.Add(runOne(ctx, tc, cfg))
	}
	return report
}

// RunOne runs the single named test case.
func RunOne(ctx context.Context, name string, cfg RunnerConfig) (result.Result, error) {
	tc, err := Lookup(name)
	if err != nil {
		return result.Result{}, err
	}
	return runOne(ctx, tc, cfg), nil
}

func runOne(ctx context.Context, tc TestCase, cfg RunnerConfig) result.Result {
	env, cleanup, err := newTestEnv(ctx, cfg.Cmd, cfg.Args, cfg.StOut, cfg.StErr)
	if err != nil {
		return result.Result{
			Name:        tc.Name,
			Description: tc.Description,
			Status:      result.StatusError,
			Message:     fmt.Sprintf("setup: %v", err),
		}
	}
	defer cleanup()

	runErr := tc.Run(ctx, env)
	if runErr != nil {
		if msg, ok := IsSkip(runErr); ok {
			return result.Result{
				Name:        tc.Name,
				Description: tc.Description,
				Status:      result.StatusSkip,
				Message:     msg,
			}
		}
		return result.Result{
			Name:        tc.Name,
			Description: tc.Description,
			Status:      result.StatusFail,
			Message:     runErr.Error(),
		}
	}
	return result.Result{
		Name:        tc.Name,
		Description: tc.Description,
		Status:      result.StatusPass,
	}
}

// BridgeToGoTest bridges a single named test case into the standard Go test
// framework. It reads SUITE_CMD and SUITE_ARGS environment variables; if
// SUITE_CMD is unset, the test is skipped.
func BridgeToGoTest(t *testing.T, name string) {
	t.Helper()

	cmd := os.Getenv("SUITE_CMD")
	if cmd == "" {
		t.Skipf("SUITE_CMD not set; skipping %s", name)
		return
	}
	args := strings.Fields(os.Getenv("SUITE_ARGS"))

	cfg := RunnerConfig{Cmd: cmd, Args: args}
	res, err := RunOne(t.Context(), name, cfg)
	if err != nil {
		t.Fatalf("test case %q not registered: %v", name, err)
	}
	switch res.Status {
	case result.StatusPass:
		// nothing
	case result.StatusSkip:
		t.Skip(res.Message)
	default:
		t.Errorf("[%s] %s: %s", res.Status, res.Name, res.Message)
	}
}
