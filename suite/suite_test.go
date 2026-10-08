package suite

import (
	"context"
	"errors"
	"testing"

	"github.com/arndt-s/spiffe-conformance-test-suite/internal/result"
)

// fakeHarness announces readiness and then idles; enough for runOne to build
// a TestEnv without a real SDK.
var fakeHarness = RunnerConfig{
	Cmd: "sh",
	Args: []string{"-c", "echo SPIFFE_HARNESS_VERSION=1; echo SPIFFE_X509_PORT=1; " +
		"echo SPIFFE_CONTROL_PORT=2; echo READY; exec sleep 30"},
}

func tc(id string, run TestFunc) TestCase {
	return TestCase{ID: id, Description: "d", Level: MUST, Feature: X509Server, Ref: "XS §5", Run: run}
}

func TestRunOneMapsOutcomesToStatuses(t *testing.T) {
	cases := []struct {
		name string
		run  TestFunc
		want result.Status
	}{
		{"pass", func(context.Context, *TestEnv) error { return nil }, result.StatusPass},
		{"sdk-misbehaved", func(context.Context, *TestEnv) error { return errors.New("SDK accepted bad cert") }, result.StatusFail},
		{"not-executed", func(context.Context, *TestEnv) error { return ExecErrorf("issue SVID: %w", errors.New("boom")) }, result.StatusError},
		{"wrapped-not-executed", func(context.Context, *TestEnv) error {
			return errors.Join(errors.New("context"), ExecErrorf("serve bundle"))
		}, result.StatusError},
		{"skip", func(context.Context, *TestEnv) error { return Skipf("unsupported") }, result.StatusSkip},
		{"panic", func(context.Context, *TestEnv) error { panic("bug in test") }, result.StatusError},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := runOne(context.Background(), tc(c.name, c.run), fakeHarness)
			if res.Status != c.want {
				t.Fatalf("status = %s (%s), want %s", res.Status, res.Message, c.want)
			}
			if res.Level != MUST || res.Feature != X509Server || res.Ref == "" {
				t.Fatalf("metadata not carried into result: %+v", res)
			}
		})
	}
}

func TestRunOneHarnessThatCannotStartIsError(t *testing.T) {
	res := runOne(context.Background(), tc("x", func(context.Context, *TestEnv) error { return nil }),
		RunnerConfig{Cmd: "/nonexistent/harness"})
	if res.Status != result.StatusError {
		t.Fatalf("status = %s, want ERROR", res.Status)
	}
}

func TestManualStartLeavesHarnessStopped(t *testing.T) {
	c := tc("manual", func(ctx context.Context, env *TestEnv) error {
		if env.process != nil {
			return errors.New("harness started despite ManualStart")
		}
		return env.StartHarness(ctx, 5e9)
	})
	c.Options = EnvOptions{ManualStart: true}
	if res := runOne(context.Background(), c, fakeHarness); res.Status != result.StatusPass {
		t.Fatalf("status = %s (%s)", res.Status, res.Message)
	}
}

func TestRunPreservesOrderInParallel(t *testing.T) {
	var cases []TestCase
	for _, id := range []string{"A-1", "A-2", "A-3", "A-4"} {
		cases = append(cases, tc(id, func(context.Context, *TestEnv) error { return nil }))
	}
	cfg := fakeHarness
	cfg.Parallel = 3
	results := Run(context.Background(), cases, cfg)
	for i, r := range results {
		if r.Name != cases[i].ID || r.Status != result.StatusPass {
			t.Fatalf("result %d = %+v", i, r)
		}
	}
}

func TestSelect(t *testing.T) {
	saved := registry
	defer func() { registry = saved }()
	registry = nil
	for _, id := range []string{"XV-1/server", "XV-1/client", "XV-10/server", "JV-2/RS256", "EP-5"} {
		Register(tc(id, func(context.Context, *TestEnv) error { return nil }))
	}
	ids := func(sel ...string) []string {
		cases, err := Select(sel)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, c := range cases {
			out = append(out, c.ID)
		}
		return out
	}
	if got := ids("XV-1"); len(got) != 2 {
		t.Errorf("XV-1 selected %v, want the two XV-1 variants only", got)
	}
	if got := ids("XV"); len(got) != 3 {
		t.Errorf("XV selected %v", got)
	}
	if got := ids("JV-2/RS256", "EP-5"); len(got) != 2 {
		t.Errorf("exact IDs selected %v", got)
	}
	if _, err := Select([]string{"NOPE"}); err == nil {
		t.Error("unknown selector accepted")
	}
}

func TestRegisterRejectsDuplicatesAndIncompleteCases(t *testing.T) {
	saved := registry
	defer func() { registry = saved }()
	registry = nil

	mustPanic := func(name string, f func()) {
		t.Helper()
		defer func() {
			if recover() == nil {
				t.Errorf("%s: no panic", name)
			}
		}()
		f()
	}
	Register(tc("A-1", func(context.Context, *TestEnv) error { return nil }))
	mustPanic("duplicate", func() { Register(tc("A-1", func(context.Context, *TestEnv) error { return nil })) })
	mustPanic("missing level", func() {
		c := tc("A-2", func(context.Context, *TestEnv) error { return nil })
		c.Level = ""
		Register(c)
	})
}
