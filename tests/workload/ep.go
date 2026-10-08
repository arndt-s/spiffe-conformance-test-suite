package workload

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"google.golang.org/grpc/codes"

	"github.com/arndt-s/spiffe-conformance-test-suite/internal/workloadapi"
	"github.com/arndt-s/spiffe-conformance-test-suite/suite"
)

func init() {
	suite.Register(suite.TestCase{
		ID:          "EP-1",
		Description: "Discovers the endpoint from SPIFFE_ENDPOINT_SOCKET when not explicitly configured",
		Level:       suite.MUST,
		Feature:     suite.X509Server,
		Ref:         "WE §4",
		Options:     suite.EnvOptions{ManualStart: true},
		Run:         runEP1,
	})
	suite.Register(suite.TestCase{
		ID:          "EP-2",
		Description: "Sends metadata workload.spiffe.io: true on every RPC",
		Level:       suite.MUST,
		Feature:     suite.X509Server,
		Ref:         "WE §3",
		Options:     suite.EnvOptions{ManualStart: true},
		Run:         runEP2,
	})
	suite.Register(suite.TestCase{
		ID:          "EP-3",
		Description: "Supports a tcp://127.0.0.1:<port> endpoint",
		Level:       suite.SHOULD,
		Feature:     suite.X509Server,
		Ref:         "WE §3, §4",
		Options:     suite.EnvOptions{ManualStart: true, TCPEndpoint: true},
		Run:         runEP3,
	})
	suite.Register(suite.TestCase{
		ID:          "EP-4/unix-authority",
		Description: "Rejects an endpoint URI with an authority (unix://host/abs/path)",
		Level:       suite.OPT,
		Feature:     suite.X509Server,
		Ref:         "WE §4",
		Options:     suite.EnvOptions{ManualStart: true},
		Run: func(ctx context.Context, env *suite.TestEnv) error {
			// unix://localhost/<abs path>: the path names the working socket.
			bad := "unix://localhost" + env.Server().SocketPath()
			return runEP4(ctx, env, bad)
		},
	})
	suite.Register(suite.TestCase{
		ID:          "EP-4/tcp-path",
		Description: "Rejects an endpoint URI with a path on tcp://",
		Level:       suite.OPT,
		Feature:     suite.X509Server,
		Ref:         "WE §4",
		Options:     suite.EnvOptions{ManualStart: true, TCPEndpoint: true},
		Run: func(ctx context.Context, env *suite.TestEnv) error {
			return runEP4(ctx, env, env.Endpoint()+"/foo")
		},
	})
	suite.Register(suite.TestCase{
		ID:          "EP-5",
		Description: "Retries with backoff after Unavailable",
		Level:       suite.SHOULD,
		Feature:     suite.X509Server,
		Ref:         "WE §6, App. A",
		Options:     suite.EnvOptions{ManualStart: true},
		Run: func(ctx context.Context, env *suite.TestEnv) error {
			return runRetryBackoff(ctx, env, codes.Unavailable)
		},
	})
	suite.Register(suite.TestCase{
		ID:          "EP-6",
		Description: "Retries with backoff after PermissionDenied",
		Level:       suite.SHOULD,
		Feature:     suite.X509Server,
		Ref:         "WE §6, App. A",
		Options:     suite.EnvOptions{ManualStart: true},
		Run: func(ctx context.Context, env *suite.TestEnv) error {
			return runRetryBackoff(ctx, env, codes.PermissionDenied)
		},
	})
	suite.Register(suite.TestCase{
		ID:          "EP-7",
		Description: "Does not retry after InvalidArgument",
		Level:       suite.SHOULD,
		Feature:     suite.X509Server,
		Ref:         "WE §6, App. A",
		Options:     suite.EnvOptions{ManualStart: true},
		Run:         runEP7,
	})
	suite.Register(suite.TestCase{
		ID:          "EP-8",
		Description: "Retries when the endpoint is not reachable yet",
		Level:       suite.OPT,
		Feature:     suite.X509Server,
		Ref:         "WE §6",
		Options:     suite.EnvOptions{ManualStart: true, DeferServerStart: true},
		Run:         runEP8,
	})
}

// runEP1: the harness is given nothing but SPIFFE_ENDPOINT_SOCKET. Reaching
// READY and presenting the served SVID shows the
// SDK found the endpoint through it.
func runEP1(ctx context.Context, env *suite.TestEnv) error {
	if err := env.StartHarness(ctx, readinessTimeout); err != nil {
		return fmt.Errorf("harness given only SPIFFE_ENDPOINT_SOCKET=%s did not become ready: %w", env.Endpoint(), err)
	}
	if n := len(env.Server().Calls()); n == 0 {
		return fmt.Errorf("harness became ready without calling the Workload API at %s", env.Endpoint())
	}
	_, err := env.WaitForSVID(ctx, suite.DefaultSVIDID, suite.UpdateTimeout)
	return err
}

// runEP2 exercises the X.509, JWT bundle (validation) and JWT fetch paths and
// asserts every recorded RPC carried the security header. The mock answers
// header-less calls with InvalidArgument, so a missing header may surface as
// the harness not becoming ready or a JWT operation failing; the outcome of
// those operations is therefore not asserted, only the recorded calls.
func runEP2(ctx context.Context, env *suite.TestEnv) error {
	startErr := env.StartHarness(ctx, readinessTimeout)
	if startErr == nil {
		if _, err := env.WaitForSVID(ctx, suite.DefaultSVIDID, suite.UpdateTimeout); err != nil {
			return err
		}
		// JWT bundle path. SKIP/unsupported or a harness error are fine here.
		token, err := env.IssueJWT(suite.DefaultSVIDID)
		if err != nil {
			return suite.ExecErrorf("issue JWT-SVID: %w", err)
		}
		_, _ = env.ValidateJWT(token.Token, suite.Audience)
		// JWT fetch path.
		_, _ = env.FetchJWTFromSDK([]string{suite.Audience}, "")
	}

	calls := env.Server().Calls()
	var missing []string
	for _, c := range calls {
		if !c.HasHeader {
			missing = append(missing, c.Method)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%d of %d Workload API calls lacked the workload.spiffe.io: true header: %s",
			len(missing), len(calls), strings.Join(missing, ", "))
	}
	if startErr != nil {
		return suite.ExecErrorf("harness did not become ready although every call carried the header: %v", startErr)
	}
	methods := map[string]bool{}
	for _, c := range calls {
		methods[c.Method] = true
	}
	if !methods[workloadapi.MethodFetchX509SVID] && !methods[workloadapi.MethodFetchX509Bundles] {
		return fmt.Errorf("no X.509 Workload API call was recorded: %s", callSummary(calls))
	}
	return nil
}

// runEP3: the mock listens on TCP only.
func runEP3(ctx context.Context, env *suite.TestEnv) error {
	if err := env.StartHarness(ctx, readinessTimeout); err != nil {
		return fmt.Errorf("harness did not become ready with SPIFFE_ENDPOINT_SOCKET=%s: %w", env.Endpoint(), err)
	}
	_, err := env.WaitForSVID(ctx, suite.DefaultSVIDID, suite.UpdateTimeout)
	return err
}

// runEP4 starts the harness with an invalid endpoint URI whose address still
// names the working mock server: a lenient client connects and becomes
// ready. Then, as a positive control, it starts the harness with the valid
// endpoint in the same environment.
func runEP4(ctx context.Context, env *suite.TestEnv, bad string) error {
	err := env.StartHarnessWithEndpoint(ctx, bad, readinessTimeout)
	if err == nil {
		return fmt.Errorf("SDK accepted the invalid endpoint %q and became ready", bad)
	}
	if isSuiteErr(err) {
		return err
	}
	if calls := env.Server().Calls(); len(calls) > 0 {
		return fmt.Errorf("SDK did not become ready with the invalid endpoint %q, but it connected and called the Workload API: %s", bad, callSummary(calls))
	}

	// Positive control: the same server through the valid endpoint.
	if err := env.StartHarness(ctx, readinessTimeout); err != nil {
		return fmt.Errorf("positive control: harness did not become ready with the valid endpoint %s: %w", env.Endpoint(), err)
	}
	_, err = env.WaitForSVID(ctx, suite.DefaultSVIDID, suite.UpdateTimeout)
	return err
}

// retryReadiness bounds how long EP-5/EP-6 wait for READY. Three failed
// calls under a typical exponential backoff (1 s, 2 s, 4 s) take ~7 s.
const retryReadiness = 30 * time.Second

// minRetryInterval is the smallest mean interval between FetchX509SVID calls
// that does not count as a tight retry loop (catalogue: < 20 calls/s).
const minRetryInterval = 50 * time.Millisecond

// runRetryBackoff fails the first three FetchX509SVID calls with code and
// expects the SDK to retry, become ready, and not retry in a tight loop.
func runRetryBackoff(ctx context.Context, env *suite.TestEnv, code codes.Code) error {
	const failures = 3
	env.Server().InjectError(workloadapi.MethodFetchX509SVID, code, failures)
	if err := env.StartHarness(ctx, retryReadiness); err != nil {
		return fmt.Errorf("SDK did not become ready after %d FetchX509SVID calls failed with %s: %w; calls: %s",
			failures, code, err, callSummary(env.Server().Calls()))
	}
	if _, err := env.WaitForSVID(ctx, suite.DefaultSVIDID, suite.UpdateTimeout); err != nil {
		return err
	}

	// FetchX509SVID calls up to and including the first successful one.
	var times []time.Time
	failed := 0
	for _, c := range env.Server().Calls() {
		if c.Method != workloadapi.MethodFetchX509SVID {
			continue
		}
		times = append(times, c.Time)
		if c.Code == codes.OK {
			break
		}
		failed++
	}
	if failed < failures {
		return suite.ExecErrorf("expected %d failed FetchX509SVID calls before the first success, recorded %d", failures, failed)
	}
	span := times[len(times)-1].Sub(times[0])
	mean := span / time.Duration(len(times)-1)
	if mean < minRetryInterval {
		return fmt.Errorf("SDK retried in a tight loop: %d FetchX509SVID calls in %s (mean interval %s, want >= %s); calls: %s",
			len(times), span, mean, minRetryInterval, callSummary(env.Server().Calls()))
	}
	return nil
}

// ep7Window is how long every call fails with InvalidArgument (catalogue).
const ep7Window = 5 * time.Second

// runEP7 answers every call with InvalidArgument for 5 s and expects at most
// two calls per method. Positive control: once the errors are cleared, the
// same SDK becomes ready against the same server.
func runEP7(ctx context.Context, env *suite.TestEnv) error {
	srv := env.Server()
	for _, m := range []string{
		workloadapi.MethodFetchX509SVID, workloadapi.MethodFetchX509Bundles,
		workloadapi.MethodFetchJWTSVID, workloadapi.MethodFetchJWTBundles,
		workloadapi.MethodValidateJWTSVID,
	} {
		srv.InjectError(m, codes.InvalidArgument, -1)
	}

	err := env.StartHarness(ctx, ep7Window)
	if err == nil {
		return fmt.Errorf("harness reported READY although every Workload API call failed with InvalidArgument")
	}
	if isSuiteErr(err) {
		return err
	}
	calls := srv.Calls()
	if len(calls) == 0 {
		return suite.ExecErrorf("SDK made no Workload API call within %s, so retries could not be assessed: %v", ep7Window, err)
	}
	perMethod := map[string]int{}
	for _, c := range calls {
		perMethod[c.Method]++
	}
	var over []string
	for m, n := range perMethod {
		if n > 2 {
			over = append(over, fmt.Sprintf("%s: %d", m, n))
		}
	}
	if len(over) > 0 {
		sort.Strings(over)
		return fmt.Errorf("SDK retried after InvalidArgument (want <= 2 calls per method in %s): %s; calls: %s",
			ep7Window, strings.Join(over, ", "), callSummary(calls))
	}

	// Positive control.
	srv.ClearErrors()
	if err := env.StartHarness(ctx, readinessTimeout); err != nil {
		return fmt.Errorf("positive control: harness did not become ready once errors were cleared: %w", err)
	}
	_, err = env.WaitForSVID(ctx, suite.DefaultSVIDID, suite.UpdateTimeout)
	return err
}

// ep8Delay is how long after starting the harness the socket is created.
const ep8Delay = 2 * time.Second

// ep8Readiness bounds the wait for READY after the harness starts: the delay
// plus room for a reconnect backoff.
const ep8Readiness = 30 * time.Second

// runEP8 starts the harness before the mock server listens and creates the
// socket 2 s later; the SDK must retry and become ready.
func runEP8(ctx context.Context, env *suite.TestEnv) error {
	started := make(chan error, 1)
	go func() { started <- env.StartHarness(ctx, ep8Readiness) }()

	select {
	case err := <-started:
		// Ready before the server exists is impossible; this is an early exit.
		return fmt.Errorf("harness exited before the endpoint became reachable: %w", err)
	case <-time.After(ep8Delay):
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := env.Server().Start(); err != nil {
		<-started
		return suite.ExecErrorf("start mock server: %v", err)
	}
	if err := <-started; err != nil {
		if isSuiteErr(err) {
			return err
		}
		return fmt.Errorf("SDK did not become ready after the endpoint appeared %s late: %w", ep8Delay, err)
	}
	_, err := env.WaitForSVID(ctx, suite.DefaultSVIDID, suite.UpdateTimeout)
	return err
}
