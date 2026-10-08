package workload

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/arndt-s/spiffe-conformance-test-suite/internal/prober"
	"github.com/arndt-s/spiffe-conformance-test-suite/internal/workloadapi"
	"github.com/arndt-s/spiffe-conformance-test-suite/suite"
)

const (
	// readinessTimeout is the harness contract's default readiness timeout
	// (harness contract §2.3). Tests that expect *no* READY wait this long.
	readinessTimeout = 10 * time.Second

	// observeWindow is how long a test watches the X.509 port after serving a
	// bad response, before it pushes the barrier. It gives the mock server
	// ample time to deliver the bad response (it is sent as soon as the state
	// changes), so that the barrier cannot overtake it.
	observeWindow = time.Second

	// barrierTimeout bounds how long a test waits for a barrier SVID after a
	// bad response. It is longer than suite.UpdateTimeout because an SDK that
	// reacts to a bad response by closing the stream and reconnecting with
	// backoff only sees the barrier on the new stream.
	barrierTimeout = 15 * time.Second

	pollInterval = 100 * time.Millisecond
)

// isSuiteErr reports whether err is an ExecutionError or SkipError that must
// be propagated unchanged.
func isSuiteErr(err error) bool {
	var exec *suite.ExecutionError
	var skip *suite.SkipError
	return errors.As(err, &exec) || errors.As(err, &skip)
}

// presents reports whether res's leaf certificate is exactly der.
func presents(res *prober.X509ProbeResult, der []byte) bool {
	return res != nil && len(res.PeerCerts) > 0 && bytes.Equal(res.PeerCerts[0].Raw, der)
}

// servingCheck validates one probe outcome: the SDK must keep serving
// (the probe succeeds), must never present the forbidden leaf, and must
// present one of the allowed SPIFFE IDs.
func servingCheck(what string, forbidden []byte, allowed ...string) func(*prober.X509ProbeResult, error) error {
	return func(res *prober.X509ProbeResult, err error) error {
		if err != nil {
			if isSuiteErr(err) {
				return err
			}
			return fmt.Errorf("SDK stopped serving a valid SVID after %s (it either presented the bad material or dropped its SVID): %v", what, err)
		}
		if forbidden != nil && presents(res, forbidden) {
			return fmt.Errorf("SDK presented the SVID from %s", what)
		}
		for _, id := range allowed {
			if suite.HasID(res, id) {
				return nil
			}
		}
		return fmt.Errorf("after %s the SDK presented %v, want one of %v", what, res.SpiffeIDs, allowed)
	}
}

// waitWhile polls the X.509 port until it presents the barrier SVID target,
// which was served after `what`. Every probe before that must pass check. It
// returns a plain error (FAIL) on timeout.
func waitWhile(ctx context.Context, env *suite.TestEnv, what, target string, timeout time.Duration, check func(*prober.X509ProbeResult, error) error) error {
	deadline := time.Now().Add(timeout)
	for {
		res, err := env.ProbeX509()
		if err == nil && suite.HasID(res, target) {
			return nil
		}
		if cerr := check(res, err); cerr != nil {
			return cerr
		}
		if time.Now().After(deadline) {
			var last []string
			if res != nil {
				last = res.SpiffeIDs
			}
			return fmt.Errorf("SDK did not apply the valid update that followed %s: barrier SVID %s not presented within %s (it presented %v)", what, target, timeout, last)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(pollInterval):
		}
	}
}

// countCalls returns the number of recorded calls to method.
func countCalls(calls []workloadapi.Call, method string) int {
	n := 0
	for _, c := range calls {
		if c.Method == method {
			n++
		}
	}
	return n
}

// callSummary renders calls as "Method(Code) +offset" for failure messages.
func callSummary(calls []workloadapi.Call) string {
	if len(calls) == 0 {
		return "no calls"
	}
	var b bytes.Buffer
	t0 := calls[0].Time
	for i, c := range calls {
		if i > 0 {
			b.WriteString(", ")
		}
		if i == 20 {
			fmt.Fprintf(&b, "... (%d calls total)", len(calls))
			break
		}
		fmt.Fprintf(&b, "%s(%s)+%dms", c.Method, c.Code, c.Time.Sub(t0).Milliseconds())
	}
	return b.String()
}
