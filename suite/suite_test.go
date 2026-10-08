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
	Cmd:  "sh",
	Args: []string{"-c", "echo SPIFFE_X509_PORT=1; echo SPIFFE_JWT_PORT=2; echo READY; exec sleep 30"},
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
		{"panic", func(context.Context, *TestEnv) error { panic("bug in test") }, result.StatusError},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := runOne(context.Background(), TestCase{Name: c.name, Run: c.run}, fakeHarness)
			if res.Status != c.want {
				t.Fatalf("status = %s (%s), want %s", res.Status, res.Message, c.want)
			}
		})
	}
}

func TestRunOneHarnessThatCannotStartIsError(t *testing.T) {
	res := runOne(context.Background(), TestCase{Name: "x", Run: func(context.Context, *TestEnv) error { return nil }},
		RunnerConfig{Cmd: "/nonexistent/harness"})
	if res.Status != result.StatusError {
		t.Fatalf("status = %s, want ERROR", res.Status)
	}
}
