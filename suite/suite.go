// Package suite provides the test case registry and runner for the SPIFFE
// Conformance Test Suite.
package suite

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/arndt-s/spiffe-conformance-test-suite/internal/result"
	"github.com/arndt-s/spiffe-conformance-test-suite/internal/workloadapi"
)

// TestFunc is the signature every test case must implement. It returns nil if
// the SDK behaved correctly, an error describing the misbehaviour if it did not
// (reported as FAIL), or an ExecutionError if the test could not be carried out
// (reported as ERROR).
type TestFunc func(ctx context.Context, env *TestEnv) error

// ExecutionError marks a test outcome as "could not execute": the suite failed
// to set up or drive the test, so nothing was learned about the SDK.
type ExecutionError struct{ Err error }

func (e *ExecutionError) Error() string { return e.Err.Error() }
func (e *ExecutionError) Unwrap() error { return e.Err }

// SkipError marks a test as skipped, e.g. because the harness does not
// support an operation the test needs.
type SkipError struct{ Reason string }

func (e *SkipError) Error() string { return e.Reason }

// Skipf returns a SkipError with a formatted reason.
func Skipf(format string, args ...any) error {
	return &SkipError{Reason: fmt.Sprintf(format, args...)}
}

// ExecErrorf returns an ExecutionError with a formatted message.
func ExecErrorf(format string, args ...any) error {
	return &ExecutionError{Err: fmt.Errorf(format, args...)}
}

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
	res, env := runCase(ctx, tc, cfg)
	if env != nil {
		for _, c := range env.Server().Calls() {
			if c.Method == workloadapi.MethodValidateJWTSVID {
				res.Delegated = true
				break
			}
		}
	}
	return res
}

func runCase(ctx context.Context, tc TestCase, cfg RunnerConfig) (res result.Result, env *TestEnv) {
	env, cleanup, err := newTestEnv(ctx, cfg.Cmd, cfg.Args, cfg.StOut, cfg.StErr)
	if err != nil {
		return result.Result{
			Name:        tc.Name,
			Description: tc.Description,
			Status:      result.StatusError,
			Message:     fmt.Sprintf("setup: %v", err),
		}, nil
	}
	defer cleanup()

	defer func() {
		if p := recover(); p != nil {
			res = result.Result{
				Name:        tc.Name,
				Description: tc.Description,
				Status:      result.StatusError,
				Message:     fmt.Sprintf("test panicked: %v", p),
			}
			env = nil
		}
	}()

	runErr := tc.Run(ctx, env)
	var execErr *ExecutionError
	var skipErr *SkipError
	if errors.As(runErr, &skipErr) {
		return result.Result{
			Name:        tc.Name,
			Description: tc.Description,
			Status:      result.StatusSkip,
			Message:     skipErr.Reason,
		}, env
	}
	if errors.As(runErr, &execErr) {
		return result.Result{
			Name:        tc.Name,
			Description: tc.Description,
			Status:      result.StatusError,
			Message:     runErr.Error(),
		}, env
	}
	if runErr != nil {
		return result.Result{
			Name:        tc.Name,
			Description: tc.Description,
			Status:      result.StatusFail,
			Message:     runErr.Error(),
		}, env
	}
	return result.Result{
		Name:        tc.Name,
		Description: tc.Description,
		Status:      result.StatusPass,
	}, env
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
