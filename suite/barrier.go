package suite

import (
	"context"
	"fmt"
	"time"

	"github.com/arndt-s/spiffe-conformance-test-suite/internal/ca"
	"github.com/arndt-s/spiffe-conformance-test-suite/internal/prober"
	"github.com/arndt-s/spiffe-conformance-test-suite/internal/workloadapi"
)

// Timeouts used by the helpers below. They bound how long the suite waits for
// an SDK to react to an update; they are not assertions about speed.
const (
	UpdateTimeout = 5 * time.Second
	pollInterval  = 100 * time.Millisecond
)

// WaitForSVID polls the SDK's X.509 port until it presents an SVID whose URI
// SANs include id. It returns a plain error (a FAIL) if that does not happen
// within timeout.
func (e *TestEnv) WaitForSVID(ctx context.Context, id string, timeout time.Duration) (*prober.X509ProbeResult, error) {
	deadline := time.Now().Add(timeout)
	var lastErr error
	var lastIDs []string
	for {
		res, err := e.ProbeX509()
		if err == nil {
			for _, got := range res.SpiffeIDs {
				if got == id {
					return res, nil
				}
			}
			lastIDs, lastErr = res.SpiffeIDs, nil
		} else {
			lastErr = err
		}
		if time.Now().After(deadline) {
			if lastErr != nil {
				return nil, fmt.Errorf("SDK did not present %s within %s; last probe error: %v", id, timeout, lastErr)
			}
			return nil, fmt.Errorf("SDK did not present %s within %s; it presented %v", id, timeout, lastIDs)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(pollInterval):
		}
	}
}

// X509Update describes a Workload API X.509 update pushed with
// PushX509AndWait.
type X509Update struct {
	// Issuer issues the barrier SVID. Defaults to the suite's CA.
	Issuer *ca.CA
	// TrustBundle is the workload's own trust bundle (DER CA certificates).
	// Defaults to the suite CA's root.
	TrustBundle [][]byte
	// FederatedBundles maps foreign trust domain SPIFFE IDs to DER CA certs.
	FederatedBundles map[string][][]byte
}

// PushX509AndWait serves u with a freshly issued barrier SVID as the default
// identity and waits until the SDK presents that SVID. Because responses are
// processed in order, once the barrier is presented the SDK has applied the
// bundles in the same response. It returns the barrier SVID, or a plain error
// (a FAIL) if the SDK never presented it.
func (e *TestEnv) PushX509AndWait(ctx context.Context, u X509Update) (*ca.X509SVIDMaterial, error) {
	issuer := u.Issuer
	if issuer == nil {
		issuer = e.ca
	} else {
		e.TrustRoot(issuer)
	}
	bundle := u.TrustBundle
	if bundle == nil {
		bundle = [][]byte{e.ca.CACertDER()}
	}
	id := fmt.Sprintf("%s/barrier-%d", issuer.TrustDomain(), barrierSeq.Add(1))
	marker, err := issuer.IssueX509SVID(id)
	if err != nil {
		return nil, ExecErrorf("issue barrier SVID: %w", err)
	}
	e.server.SetX509State(&workloadapi.X509State{
		Materials:        []*ca.X509SVIDMaterial{marker},
		TrustBundle:      bundle,
		TrustDomain:      e.ca.TrustDomain(),
		FederatedBundles: u.FederatedBundles,
	})
	if _, err := e.WaitForSVID(ctx, id, UpdateTimeout); err != nil {
		return nil, fmt.Errorf("SDK did not apply the X.509 update: %w", err)
	}
	return marker, nil
}

// ObserveX509 probes the SDK's X.509 port every 100 ms for duration d and
// passes each outcome to check. It returns the first error check returns.
// Use it to assert that something never happens during a window, e.g. that a
// bad SVID is never presented.
func (e *TestEnv) ObserveX509(ctx context.Context, d time.Duration, check func(*prober.X509ProbeResult, error) error) error {
	deadline := time.Now().Add(d)
	for {
		if err := check(e.ProbeX509()); err != nil {
			return err
		}
		if time.Now().After(deadline) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(pollInterval):
		}
	}
}

// WaitForJWTAccepted validates token until the SDK accepts it, for up to
// timeout. It returns a plain error (a FAIL) if it never does, or the
// ExecutionError/SkipError from ValidateJWT.
func (e *TestEnv) WaitForJWTAccepted(ctx context.Context, token, audience string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var last JWTVerdict
	for {
		v, err := e.ValidateJWT(token, audience)
		if err != nil {
			return err
		}
		if v.Accepted {
			return nil
		}
		last = v
		if time.Now().After(deadline) {
			return fmt.Errorf("SDK did not accept the token within %s: %s", timeout, last.Message)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(pollInterval):
		}
	}
}

// HasID reports whether res presents id among its URI SANs.
func HasID(res *prober.X509ProbeResult, id string) bool {
	if res == nil {
		return false
	}
	for _, got := range res.SpiffeIDs {
		if got == id {
			return true
		}
	}
	return false
}
