// Package suite provides the test case registry and runner for the SPIFFE
// Conformance Test Suite.
package suite

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/arndt-s/spiffe-conformance-test-suite/internal/result"
	"github.com/arndt-s/spiffe-conformance-test-suite/internal/workloadapi"
)

// Re-exported so test packages need not import internal/result.
type (
	Level   = result.Level
	Feature = result.Feature
)

const (
	MUST   = result.LevelMust
	SHOULD = result.LevelShould
	OPT    = result.LevelOpt

	X509Server  = result.FeatureX509Server
	X509Client  = result.FeatureX509Client
	JWTValidate = result.FeatureJWTValidate
	JWTFetch    = result.FeatureJWTFetch
)

// TestFunc is the signature every test case must implement. It returns nil if
// the SDK behaved correctly, an error describing the misbehaviour if it did not
// (reported as FAIL), an ExecutionError if the test could not be carried out
// (reported as ERROR), or a SkipError (reported as SKIP).
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

// TestCase is the unit of work registered into the suite. Every field except
// Options is required.
type TestCase struct {
	// ID is the catalogue ID (docs/TEST_CATALOGUE.md), with a "/<variant>"
	// suffix for sub-results, e.g. "XV-8/server" or "JV-2/RS256".
	ID          string
	Description string
	Level       Level
	Feature     Feature
	// Ref is the specification reference, e.g. "XS §5.2".
	Ref     string
	Options EnvOptions
	Run     TestFunc
}

var (
	mu       sync.RWMutex
	registry []TestCase
)

// Register adds a test case to the global registry. It panics on a missing
// field or a duplicate ID, so mistakes surface when the binary starts.
func Register(tc TestCase) {
	if tc.ID == "" || tc.Description == "" || tc.Level == "" || tc.Feature == "" || tc.Ref == "" || tc.Run == nil {
		panic(fmt.Sprintf("suite.Register: incomplete test case %+v", tc))
	}
	mu.Lock()
	defer mu.Unlock()
	for _, existing := range registry {
		if existing.ID == tc.ID {
			panic(fmt.Sprintf("suite.Register: duplicate test ID %q", tc.ID))
		}
	}
	registry = append(registry, tc)
}

// All returns a snapshot of all registered test cases in registration order.
func All() []TestCase {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]TestCase, len(registry))
	copy(out, registry)
	return out
}

// Select returns the test cases matching any of the selectors, in
// registration order. A selector matches an ID exactly, the ID's sub-results
// ("XV-8" matches "XV-8/server"), or a whole group ("XV" matches "XV-8/server"
// but "XV-1" does not match "XV-10"). An empty selector list selects all.
// Selectors that match nothing are an error.
func Select(selectors []string) ([]TestCase, error) {
	all := All()
	if len(selectors) == 0 {
		return all, nil
	}
	used := map[string]bool{}
	var out []TestCase
	for _, tc := range all {
		for _, sel := range selectors {
			if matches(tc.ID, sel) {
				out = append(out, tc)
				used[sel] = true
				break
			}
		}
	}
	var unknown []string
	for _, sel := range selectors {
		if !used[sel] {
			unknown = append(unknown, sel)
		}
	}
	if len(unknown) > 0 {
		return nil, fmt.Errorf("no test case matches: %s", strings.Join(unknown, ","))
	}
	return out, nil
}

func matches(id, sel string) bool {
	return id == sel || strings.HasPrefix(id, sel+"/") || strings.HasPrefix(id, sel+"-")
}

// RunnerConfig holds the parameters needed to run test cases.
type RunnerConfig struct {
	// Cmd is the SDK harness binary path.
	Cmd string
	// Args are the arguments to pass to the harness.
	Args []string
	// Parallel is the number of test cases run concurrently (default 1).
	Parallel int
	// ReadyTimeout is how long to wait for the harness's READY (default
	// harness.DefaultReadinessTimeout).
	ReadyTimeout time.Duration

	StOut io.Writer
	StErr io.Writer
}

// Run executes cases and returns their results in the same order.
func Run(ctx context.Context, cases []TestCase, cfg RunnerConfig) []result.Result {
	results := make([]result.Result, len(cases))
	workers := cfg.Parallel
	if workers < 1 {
		workers = 1
	}
	next := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				results[i] = runOne(ctx, cases[i], cfg)
			}
		}()
	}
	for i := range cases {
		next <- i
	}
	close(next)
	wg.Wait()
	return results
}

func runOne(ctx context.Context, tc TestCase, cfg RunnerConfig) result.Result {
	res := result.Result{
		Name:        tc.ID,
		Description: tc.Description,
		Level:       tc.Level,
		Feature:     tc.Feature,
		Ref:         tc.Ref,
	}
	status, msg, env := execute(ctx, tc, cfg)
	res.Status, res.Message = status, msg
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

func execute(ctx context.Context, tc TestCase, cfg RunnerConfig) (status result.Status, msg string, env *TestEnv) {
	env, err := newTestEnv(ctx, cfg, tc.Options)
	if err != nil {
		return result.StatusError, fmt.Sprintf("setup: %v", err), nil
	}
	defer env.close()

	defer func() {
		if p := recover(); p != nil {
			status, msg = result.StatusError, fmt.Sprintf("test panicked: %v", p)
		}
	}()

	runErr := tc.Run(ctx, env)
	var execErr *ExecutionError
	var skipErr *SkipError
	switch {
	case runErr == nil:
		return result.StatusPass, "", env
	case errors.As(runErr, &skipErr):
		return result.StatusSkip, skipErr.Reason, env
	case errors.As(runErr, &execErr):
		return result.StatusError, runErr.Error(), env
	default:
		return result.StatusFail, runErr.Error(), env
	}
}
