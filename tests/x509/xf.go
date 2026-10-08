package x509

import (
	"context"
	"fmt"

	"github.com/arndt-s/spiffe-conformance-test-suite/internal/ca"
	"github.com/arndt-s/spiffe-conformance-test-suite/suite"
)

// federatedTD is the foreign trust domain used by the XF tests.
const federatedTD = "spiffe://fed.example.org"

func init() {
	cases := []struct {
		id, desc, ref string
		run           func(context.Context, *suite.TestEnv, role) error
	}{
		{"XF-1", "Accepts a peer from a federated trust domain using federated_bundles", "WA §4.6", runXF1},
		{"XF-2", "Rejects a peer claiming trust domain B whose chain only verifies against trust domain A's bundle (no bundle merging)", "WA §4.6, FD §4.2, §7.3", runXF2},
		{"XF-3", "Stops trusting a federated trust domain when a later response omits it", "WA §4.4", runXF3},
	}
	for _, c := range cases {
		for _, r := range roles {
			suite.Register(suite.TestCase{
				ID:          c.id + "/" + r.name,
				Description: c.desc,
				Level:       suite.MUST,
				Feature:     r.feature,
				Ref:         c.ref,
				Run:         runInRole(r, c.run),
			})
		}
	}
}

// federate creates a CA for federatedTD and pushes its bundle as a federated
// bundle, waiting until the SDK has applied it.
func federate(ctx context.Context, env *suite.TestEnv) (*ca.CA, error) {
	fed, err := ca.New(federatedTD)
	if err != nil {
		return nil, suite.ExecErrorf("create federated CA: %w", err)
	}
	if _, err := env.PushX509AndWait(ctx, suite.X509Update{
		FederatedBundles: map[string][][]byte{federatedTD: {fed.CACertDER()}},
	}); err != nil {
		return nil, err
	}
	return fed, nil
}

func runXF1(ctx context.Context, env *suite.TestEnv, r role) error {
	fed, err := federate(ctx, env)
	if err != nil {
		return err
	}
	peer, err := fed.IssueX509SVID(federatedTD + "/xf-1")
	if err != nil {
		return suite.ExecErrorf("issue federated peer: %w", err)
	}
	return r.expectAccepted(env, peer, "a peer from the federated trust domain "+federatedTD)
}

// runXF2 checks both directions: a federated-TD ID signed by the local CA, and
// a local-TD ID signed by the federated CA. Each chain verifies against a
// bundle the SDK holds, but not the bundle of the ID's own trust domain.
func runXF2(ctx context.Context, env *suite.TestEnv, r role) error {
	fed, err := federate(ctx, env)
	if err != nil {
		return err
	}
	fedPeer, err := fed.IssueX509SVID(federatedTD + "/xf-2-control")
	if err != nil {
		return suite.ExecErrorf("issue federated peer: %w", err)
	}
	if err := r.positiveControl(env, suite.TrustDomain+"/control"); err != nil {
		return err
	}
	if err := r.expectAccepted(env, fedPeer, "a peer from "+federatedTD+" signed by its own CA"); err != nil {
		return fmt.Errorf("positive control failed: %w", err)
	}

	fedIDLocalCA, err := env.IssueX509SVID(federatedTD + "/xf-2")
	if err != nil {
		return suite.ExecErrorf("issue peer: %w", err)
	}
	if err := r.expectRejected(env, fedIDLocalCA,
		"a peer "+federatedTD+"/xf-2 whose chain verifies only against the bundle of "+suite.TrustDomain); err != nil {
		return err
	}
	localIDFedCA, err := fed.IssueX509SVID(suite.TrustDomain + "/xf-2")
	if err != nil {
		return suite.ExecErrorf("issue peer: %w", err)
	}
	return r.expectRejected(env, localIDFedCA,
		"a peer "+suite.TrustDomain+"/xf-2 whose chain verifies only against the bundle of "+federatedTD)
}

func runXF3(ctx context.Context, env *suite.TestEnv, r role) error {
	fed, err := federate(ctx, env)
	if err != nil {
		return err
	}
	fedPeer, err := fed.IssueX509SVID(federatedTD + "/xf-3")
	if err != nil {
		return suite.ExecErrorf("issue federated peer: %w", err)
	}
	if err := r.expectAccepted(env, fedPeer, "a peer from "+federatedTD+" while its bundle is present"); err != nil {
		return fmt.Errorf("positive control failed: %w", err)
	}
	// Barrier: a response without federated_bundles.
	if _, err := env.PushX509AndWait(ctx, suite.X509Update{}); err != nil {
		return err
	}
	if err := r.positiveControl(env, suite.TrustDomain+"/control"); err != nil {
		return err
	}
	return r.expectRejected(env, fedPeer, "a peer from "+federatedTD+" after a response omitted its bundle")
}
