package workload

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc/codes"

	workloadv1 "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"

	"github.com/arndt-s/spiffe-conformance-test-suite/internal/ca"
	"github.com/arndt-s/spiffe-conformance-test-suite/internal/workloadapi"
	"github.com/arndt-s/spiffe-conformance-test-suite/suite"
)

func init() {
	suite.Register(suite.TestCase{
		ID:          "WA-1",
		Description: "Re-establishes the stream after the server closes it",
		Level:       suite.SHOULD,
		Feature:     suite.X509Server,
		Ref:         "WA §4.2",
		Run:         runWA1,
	})

	for _, v := range wa2Variants {
		v := v
		suite.Register(suite.TestCase{
			ID:          "WA-2/" + v.name,
			Description: "Discards a response in which a mandatory field has its default value (" + v.field + ")",
			Level:       suite.SHOULD,
			Feature:     suite.X509Server,
			Ref:         "WA §4.5",
			Run: func(ctx context.Context, env *suite.TestEnv) error {
				return runWA2(ctx, env, v)
			},
		})
	}

	suite.Register(suite.TestCase{
		ID:          "WA-3",
		Description: "Uses the first SVID in the response as the default identity",
		Level:       suite.MUST,
		Feature:     suite.X509Server,
		Ref:         "WA §8",
		Run:         runWA3,
	})
	suite.Register(suite.TestCase{
		ID:          "WA-4",
		Description: "Stops using SVIDs after the stream returns PermissionDenied",
		Level:       suite.SHOULD,
		Feature:     suite.X509Server,
		Ref:         "WA §5.2.1",
		Run:         runWA4,
	})
}

// reconnectTimeout bounds how long WA-1 waits for the SDK to open a new
// FetchX509SVID stream after the server closed it (room for backoff).
const reconnectTimeout = 15 * time.Second

// runWA1 closes the stream with Unavailable, waits for the SDK to open a new
// one, and only then serves SVID B, so B can only arrive on the new stream.
func runWA1(ctx context.Context, env *suite.TestEnv) error {
	if _, err := env.WaitForSVID(ctx, suite.DefaultSVIDID, suite.UpdateTimeout); err != nil {
		return err
	}
	const idB = suite.TrustDomain + "/wa-1-b"
	b, err := env.IssueX509SVID(idB)
	if err != nil {
		return suite.ExecErrorf("issue SVID: %w", err)
	}

	srv := env.Server()
	before := countCalls(srv.Calls(), workloadapi.MethodFetchX509SVID)
	srv.CloseStreams(codes.Unavailable)

	deadline := time.Now().Add(reconnectTimeout)
	for countCalls(srv.Calls(), workloadapi.MethodFetchX509SVID) == before {
		if time.Now().After(deadline) {
			return fmt.Errorf("SDK did not open a new FetchX509SVID stream within %s after the server closed it with Unavailable", reconnectTimeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(pollInterval / 2):
		}
	}

	env.ServeX509(b)
	_, err = env.WaitForSVID(ctx, idB, suite.UpdateTimeout)
	if err != nil {
		return fmt.Errorf("after the stream was re-established: %w", err)
	}
	return nil
}

type wa2Variant struct {
	name  string
	field string
	// blank zeroes one mandatory field of a valid response.
	blank func(*workloadv1.X509SVIDResponse)
}

var wa2Variants = []wa2Variant{
	{"empty-svids", "svids", func(r *workloadv1.X509SVIDResponse) { r.Svids = nil }},
	{"empty-spiffe-id", "spiffe_id", func(r *workloadv1.X509SVIDResponse) { r.Svids[0].SpiffeId = "" }},
	{"empty-x509-svid", "x509_svid", func(r *workloadv1.X509SVIDResponse) { r.Svids[0].X509Svid = nil }},
	{"empty-key", "x509_svid_key", func(r *workloadv1.X509SVIDResponse) { r.Svids[0].X509SvidKey = nil }},
	{"empty-bundle", "bundle", func(r *workloadv1.X509SVIDResponse) { r.Svids[0].Bundle = nil }},
}

// runWA2 serves A, then a response for SVID C with one mandatory field
// blanked, then barrier SVID B. Throughout, the SDK must keep serving and
// present only A (or, once pushed, B); it must never present C.
func runWA2(ctx context.Context, env *suite.TestEnv, v wa2Variant) error {
	idA := suite.TrustDomain + "/wa-2-a"
	idB := suite.TrustDomain + "/wa-2-b"
	idC := suite.TrustDomain + "/wa-2-" + v.name

	a, err := env.IssueX509SVID(idA)
	if err != nil {
		return suite.ExecErrorf("issue SVID A: %w", err)
	}
	b, err := env.IssueX509SVID(idB)
	if err != nil {
		return suite.ExecErrorf("issue SVID B: %w", err)
	}
	c, err := env.IssueX509SVID(idC)
	if err != nil {
		return suite.ExecErrorf("issue SVID C: %w", err)
	}

	// Positive control: A is accepted and served.
	env.ServeX509(a)
	if _, err := env.WaitForSVID(ctx, idA, suite.UpdateTimeout); err != nil {
		return err
	}

	resp, err := workloadapi.BuildX509Response(&workloadapi.X509State{
		Materials:   []*ca.X509SVIDMaterial{c},
		TrustBundle: [][]byte{env.CA().CACertDER()},
		TrustDomain: env.CA().TrustDomain(),
	})
	if err != nil {
		return suite.ExecErrorf("build response: %w", err)
	}
	v.blank(resp)
	// FetchX509SVID streams the broken response. TrustBundle and TrustDomain
	// keep FetchX509Bundles serving the valid bundle, so an SDK that
	// authenticates peers through that RPC is not affected by the variant.
	env.SetX509State(&workloadapi.X509State{
		Raw:         resp,
		TrustBundle: [][]byte{env.CA().CACertDER()},
		TrustDomain: env.CA().TrustDomain(),
	})

	what := "a response with an empty " + v.field
	if err := env.ObserveX509(ctx, observeWindow, servingCheck(what, c.CertDER, idA)); err != nil {
		return err
	}
	env.ServeX509(b)
	return waitWhile(ctx, env, what, idB, barrierTimeout, servingCheck(what, c.CertDER, idA))
}

// runWA3 serves [A, B] and expects A, then [B, A] and expects B.
func runWA3(ctx context.Context, env *suite.TestEnv) error {
	idA := suite.TrustDomain + "/wa-3-a"
	idB := suite.TrustDomain + "/wa-3-b"
	a, err := env.IssueX509SVID(idA)
	if err != nil {
		return suite.ExecErrorf("issue SVID A: %w", err)
	}
	b, err := env.IssueX509SVID(idB)
	if err != nil {
		return suite.ExecErrorf("issue SVID B: %w", err)
	}

	env.ServeX509(a, b)
	if _, err := env.WaitForSVID(ctx, idA, suite.UpdateTimeout); err != nil {
		return fmt.Errorf("response [A, B]: %w", err)
	}
	env.ServeX509(b, a)
	if _, err := env.WaitForSVID(ctx, idB, suite.UpdateTimeout); err != nil {
		return fmt.Errorf("response [B, A]: %w", err)
	}
	return nil
}

// wa4Timeout is how long WA-4 waits for the SDK to stop presenting A.
const wa4Timeout = 5 * time.Second

// runWA4 ends the FetchX509SVID stream with PermissionDenied (and keeps
// answering new FetchX509SVID streams with PermissionDenied) and expects the
// X.509 port to stop presenting A. FetchX509Bundles keeps working, so a
// failing probe means the SDK dropped its SVID, not that it could no longer
// authenticate the suite's probe certificate.
func runWA4(ctx context.Context, env *suite.TestEnv) error {
	// Positive control: A is served.
	if _, err := env.WaitForSVID(ctx, suite.DefaultSVIDID, suite.UpdateTimeout); err != nil {
		return err
	}
	srv := env.Server()
	srv.InjectError(workloadapi.MethodFetchX509SVID, codes.PermissionDenied, -1)
	srv.CloseStreams(codes.PermissionDenied)

	deadline := time.Now().Add(wa4Timeout)
	for {
		res, err := env.ProbeX509()
		if err != nil {
			if isSuiteErr(err) {
				return err
			}
			return nil // no longer serving A
		}
		if !suite.HasID(res, suite.DefaultSVIDID) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("SDK still presented %s %s after the stream ended with PermissionDenied", suite.DefaultSVIDID, wa4Timeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(pollInterval):
		}
	}
}
