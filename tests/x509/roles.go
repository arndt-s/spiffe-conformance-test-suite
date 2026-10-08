package x509

import (
	"context"
	"fmt"

	"github.com/arndt-s/spiffe-conformance-test-suite/internal/ca"
	"github.com/arndt-s/spiffe-conformance-test-suite/suite"
)

// role is one way the suite can present a peer certificate to the SDK
// (catalogue §1.4).
type role struct {
	name    string
	feature suite.Feature
	// verdict reports whether the SDK accepted peer. The detail string is the
	// harness's explanation, if any. SkipError/ExecutionError are returned
	// unchanged.
	verdict func(env *suite.TestEnv, peer *ca.X509SVIDMaterial) (accepted bool, detail string, err error)
}

// roles are the two peer-validation roles: the SDK as TLS server (the suite's
// certificate is the client certificate) and the SDK as TLS client (the
// suite's certificate is the server certificate, /v1/x509/dial).
var roles = []role{
	{
		name:    "server",
		feature: suite.X509Server,
		verdict: func(env *suite.TestEnv, peer *ca.X509SVIDMaterial) (bool, string, error) {
			ok, err := env.ClientCertVerdict(peer)
			return ok, "", err
		},
	},
	{
		name:    "client",
		feature: suite.X509Client,
		verdict: func(env *suite.TestEnv, peer *ca.X509SVIDMaterial) (bool, string, error) {
			v, err := env.DialFromSDK(peer)
			return v.Accepted, v.Message, err
		},
	},
}

var serverRole = roles[0]

// expectAccepted returns a plain error (FAIL) if the SDK rejects peer.
func (r role) expectAccepted(env *suite.TestEnv, peer *ca.X509SVIDMaterial, what string) error {
	ok, detail, err := r.verdict(env, peer)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("SDK rejected %s%s", what, withDetail(detail))
	}
	return nil
}

// expectRejected returns a plain error (FAIL) if the SDK accepts peer.
func (r role) expectRejected(env *suite.TestEnv, peer *ca.X509SVIDMaterial, what string) error {
	ok, _, err := r.verdict(env, peer)
	if err != nil {
		return err
	}
	if ok {
		return fmt.Errorf("SDK accepted %s", what)
	}
	return nil
}

// positiveControl checks that the SDK accepts a plain valid leaf from the
// suite CA in this role, so a later rejection means something (catalogue §2.1).
func (r role) positiveControl(env *suite.TestEnv, id string) error {
	peer, err := env.IssueX509SVID(id)
	if err != nil {
		return suite.ExecErrorf("issue control SVID: %w", err)
	}
	if err := r.expectAccepted(env, peer, "the valid control peer"); err != nil {
		return fmt.Errorf("positive control failed: %w", err)
	}
	return nil
}

func withDetail(d string) string {
	if d == "" {
		return ""
	}
	return ": " + d
}

// runInRole adapts a role-parameterised test to a suite.TestFunc.
func runInRole(r role, f func(ctx context.Context, env *suite.TestEnv, r role) error) suite.TestFunc {
	return func(ctx context.Context, env *suite.TestEnv) error { return f(ctx, env, r) }
}
