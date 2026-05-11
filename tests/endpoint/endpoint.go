// Package endpoint registers Workload Endpoint conformance test cases.
//
// These tests exercise the requirements from the SPIFFE Workload Endpoint
// specification that govern how an SDK must talk to the endpoint:
//   - the mandatory `workload.spiffe.io: true` gRPC metadata header
//   - retry semantics for InvalidArgument / Unavailable / PermissionDenied
//   - reconnect-after-stream-close behavior
package endpoint

import (
	"context"
	"fmt"
	"sort"
	"time"

	"google.golang.org/grpc/codes"

	"github.com/arndt-s/spiffe-conformance-test-suite/internal/workloadapi"
	"github.com/arndt-s/spiffe-conformance-test-suite/suite"
)

func init() {
	suite.Register(suite.TestCase{
		Name:        "E1",
		Description: "SDK includes the workload.spiffe.io:true metadata header on every Workload API request",
		Run:         runE1,
	})
	suite.Register(suite.TestCase{
		Name:        "E5",
		Description: "SDK does not tight-loop reconnect when the Workload API returns InvalidArgument",
		Run:         runE5,
	})
	suite.Register(suite.TestCase{
		Name:        "E6",
		Description: "SDK retries with backoff when the Workload API returns Unavailable",
		Run:         runE6,
	})
	suite.Register(suite.TestCase{
		Name:        "E7",
		Description: "SDK retries with backoff when the Workload API returns PermissionDenied",
		Run:         runE7,
	})
	suite.Register(suite.TestCase{
		Name:        "E8",
		Description: "SDK reconnects promptly after the Workload API closes a healthy stream",
		Run:         runE8,
	})
}

// runE1 verifies that every RPC the SDK issued against the mock server
// carried the `workload.spiffe.io: true` gRPC metadata header.
//
// The default test environment already drives an X.509 fetch (the SDK must
// fetch an SVID before it can signal READY). To also exercise the JWT path
// the test forces a JWT bundle update and a JWT validation probe so that the
// SDK invokes FetchJWTBundles and/or ValidateJWTSVID.
func runE1(ctx context.Context, env *suite.TestEnv) error {
	// Issue a JWT and serve it so the SDK has bundles to fetch.
	jwt, err := env.IssueJWT("spiffe://test.example.org/e1")
	if err != nil {
		return fmt.Errorf("issue JWT: %w", err)
	}
	if err := env.ServeJWT("test", jwt); err != nil {
		return fmt.Errorf("serve JWT: %w", err)
	}

	// Probing the SDK's JWT port forces the SDK to validate the token
	// against its JWKS bundle, which in turn requires an earlier
	// FetchJWTBundles call.
	if _, err := env.ProbeJWT(jwt.Token); err != nil {
		// Probe failure is non-fatal here; we only care whether the SDK
		// made the underlying RPCs with the correct header.
		_ = err
	}

	// Give the SDK a brief moment to flush any in-flight RPCs.
	time.Sleep(200 * time.Millisecond)

	calls := env.Calls()
	if len(calls) == 0 {
		return fmt.Errorf("no Workload API RPCs recorded; cannot verify metadata header")
	}

	missing := map[string]int{}
	for _, c := range calls {
		if !c.HeaderSeen {
			missing[c.Method]++
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("RPC(s) observed without workload.spiffe.io:true header: %v", missing)
	}
	return nil
}

// runE5 verifies that the SDK does not tight-loop when the server returns
// InvalidArgument. EP-12: "Client receiving InvalidArgument SHOULD NOT
// retry (client implementation error)".
//
// We allow some retries (many SDKs implement a generic backoff that does
// not special-case InvalidArgument) but reject pathological tight loops.
func runE5(ctx context.Context, env *suite.TestEnv) error {
	return assertReconnectBehavior(env, codes.InvalidArgument, reconnectExpect{
		maxCallsIn2s: 12, // tight loop would be hundreds; flag obvious abuse
		minGapMs:     0,  // EP-12 doesn't require backoff (it forbids retry)
	})
}

// runE6 verifies that the SDK retries with backoff on Unavailable.
// EP-13: "Client receiving Unavailable ... MAY retry with backoff".
func runE6(ctx context.Context, env *suite.TestEnv) error {
	return assertReconnectBehavior(env, codes.Unavailable, reconnectExpect{
		minCallsIn2s: 2,   // proves retry
		maxCallsIn2s: 50,  // proves not pathological
		minGapMs:     20,  // proves at least minimal backoff
	})
}

// runE7 verifies that the SDK retries with backoff on PermissionDenied.
// EP-14: "Client receiving PermissionDenied MAY retry with backoff".
func runE7(ctx context.Context, env *suite.TestEnv) error {
	return assertReconnectBehavior(env, codes.PermissionDenied, reconnectExpect{
		minCallsIn2s: 2,
		maxCallsIn2s: 50,
		minGapMs:     20,
	})
}

// runE8 verifies that after a healthy FetchX509SVID stream is closed by
// the server, the SDK reopens it promptly. WLAPI-03: "Client SHOULD
// immediately establish a new connection upon termination".
func runE8(ctx context.Context, env *suite.TestEnv) error {
	// Wait for at least one successful FetchX509SVID call to have happened.
	if err := waitForCalls(env, "FetchX509SVID", 1, 5*time.Second); err != nil {
		return fmt.Errorf("waiting for initial FetchX509SVID: %w", err)
	}

	env.ResetCalls()
	closeAt := time.Now()
	env.CloseStreamOnce("FetchX509SVID")

	// Expect a fresh FetchX509SVID call within a generous window.
	if err := waitForCalls(env, "FetchX509SVID", 1, 5*time.Second); err != nil {
		return fmt.Errorf("SDK did not reconnect after stream close within 5s")
	}

	first := firstCallAfter(env.Calls(), "FetchX509SVID", closeAt)
	if first.IsZero() {
		return fmt.Errorf("no FetchX509SVID call observed after stream close")
	}
	gap := first.Sub(closeAt)
	if gap > 5*time.Second {
		return fmt.Errorf("SDK reconnected too slowly: %s after stream close", gap)
	}
	return nil
}

// reconnectExpect describes the expected pattern of FetchX509SVID calls
// observed within a fixed measurement window after the server begins
// returning a configured error code.
type reconnectExpect struct {
	minCallsIn2s int
	maxCallsIn2s int
	minGapMs     int64
}

// assertReconnectBehavior:
//  1. waits until the SDK has opened an initial FetchX509SVID stream
//  2. resets the call log and configures the server to fail with `code`
//  3. closes the existing stream
//  4. measures FetchX509SVID call count and inter-call gaps over 2s
//  5. asserts the observed pattern against `want`
func assertReconnectBehavior(env *suite.TestEnv, code codes.Code, want reconnectExpect) error {
	if err := waitForCalls(env, "FetchX509SVID", 1, 5*time.Second); err != nil {
		return fmt.Errorf("waiting for initial FetchX509SVID: %w", err)
	}

	env.ResetCalls()
	env.SetFailMode("FetchX509SVID", code)
	env.CloseStreamOnce("FetchX509SVID")

	const window = 2 * time.Second
	time.Sleep(window)

	// Stop forcing failures so the SDK can recover for subsequent tests.
	env.SetFailMode("FetchX509SVID", codes.OK)

	calls := filterMethod(env.Calls(), "FetchX509SVID")

	if want.minCallsIn2s > 0 && len(calls) < want.minCallsIn2s {
		return fmt.Errorf("expected at least %d FetchX509SVID calls in %s, observed %d",
			want.minCallsIn2s, window, len(calls))
	}
	if want.maxCallsIn2s > 0 && len(calls) > want.maxCallsIn2s {
		return fmt.Errorf("observed %d FetchX509SVID calls in %s — looks like a tight retry loop (max allowed: %d)",
			len(calls), window, want.maxCallsIn2s)
	}

	if want.minGapMs > 0 && len(calls) >= 2 {
		// Check the smallest inter-call gap.
		sort.Slice(calls, func(i, j int) bool { return calls[i].At.Before(calls[j].At) })
		smallest := time.Duration(1<<62) * time.Nanosecond
		for i := 1; i < len(calls); i++ {
			d := calls[i].At.Sub(calls[i-1].At)
			if d < smallest {
				smallest = d
			}
		}
		if smallest.Milliseconds() < want.minGapMs {
			return fmt.Errorf("smallest gap between FetchX509SVID retries was %s (< %dms) — SDK appears to retry without backoff",
				smallest, want.minGapMs)
		}
	}
	return nil
}

func filterMethod(calls []workloadapi.MethodCall, method string) []workloadapi.MethodCall {
	out := make([]workloadapi.MethodCall, 0, len(calls))
	for _, c := range calls {
		if c.Method == method {
			out = append(out, c)
		}
	}
	return out
}

func waitForCalls(env *suite.TestEnv, method string, count int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if len(filterMethod(env.Calls(), method)) >= count {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout waiting for %d %s call(s)", count, method)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func firstCallAfter(calls []workloadapi.MethodCall, method string, after time.Time) time.Time {
	var first time.Time
	for _, c := range calls {
		if c.Method != method {
			continue
		}
		if c.At.Before(after) {
			continue
		}
		if first.IsZero() || c.At.Before(first) {
			first = c.At
		}
	}
	return first
}
