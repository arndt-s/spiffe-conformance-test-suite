package x509

import (
	"bytes"
	"context"
	"fmt"

	"github.com/arndt-s/spiffe-conformance-test-suite/internal/ca"
	"github.com/arndt-s/spiffe-conformance-test-suite/suite"
)

func init() {
	for _, tc := range []suite.TestCase{
		{
			ID:          "XS-1",
			Description: "Presents the X.509-SVID received from FetchX509SVID",
			Ref:         "WA §5.2.1",
			Run:         runXS1,
		},
		{
			ID:          "XS-2",
			Description: "Presents the full chain, leaf first, including intermediates",
			Ref:         "WA §5.1 (x509_svid)",
			Run:         runXS2,
		},
		{
			ID:          "XS-3",
			Description: "Uses a rotated SVID for new connections",
			Ref:         "WA §4.3",
			Run:         runXS3,
		},
		{
			ID:          "XS-4",
			Description: "Accepts a trust bundle with several concatenated CA certificates and trusts each",
			Ref:         "WA §5.1 (bundle)",
			Run:         runXS4,
		},
		{
			ID:          "XS-5",
			Description: "Stops trusting a CA once it is removed from the bundle",
			Ref:         "WA §4.3, §4.4",
			Run:         runXS5,
		},
	} {
		tc.Level = suite.MUST
		tc.Feature = suite.X509Server
		suite.Register(tc)
	}
}

func runXS1(ctx context.Context, env *suite.TestEnv) error {
	const id = suite.TrustDomain + "/xs-1"
	svid, err := env.IssueX509SVID(id)
	if err != nil {
		return suite.ExecErrorf("issue SVID: %w", err)
	}
	env.ServeX509(svid)
	_, err = env.WaitForSVID(ctx, id, suite.UpdateTimeout)
	return err
}

// runXS2 serves an SVID issued by an intermediate CA. The suite trusts only
// the root, so the probe verifies only if the SDK sends the intermediate; the
// test also checks the chain order explicitly.
func runXS2(ctx context.Context, env *suite.TestEnv) error {
	const id = suite.TrustDomain + "/xs-2"
	inter, err := env.CA().NewIntermediate()
	if err != nil {
		return suite.ExecErrorf("create intermediate CA: %w", err)
	}
	svid, err := inter.IssueX509SVID(id)
	if err != nil {
		return suite.ExecErrorf("issue SVID: %w", err)
	}
	if len(svid.Intermediates) != 1 {
		return suite.ExecErrorf("expected 1 intermediate in the issued chain, got %d", len(svid.Intermediates))
	}
	env.ServeX509(svid)
	res, err := env.WaitForSVID(ctx, id, suite.UpdateTimeout)
	if err != nil {
		return err
	}
	if len(res.PeerCerts) < 2 {
		return fmt.Errorf("SDK presented %d certificate(s); want leaf followed by the intermediate", len(res.PeerCerts))
	}
	if !bytes.Equal(res.PeerCerts[0].Raw, svid.CertDER) {
		return fmt.Errorf("first presented certificate is not the issued leaf")
	}
	if !bytes.Equal(res.PeerCerts[1].Raw, svid.Intermediates[0]) {
		return fmt.Errorf("second presented certificate is not the intermediate CA")
	}
	return nil
}

func runXS3(ctx context.Context, env *suite.TestEnv) error {
	for _, id := range []string{suite.TrustDomain + "/xs-3-a", suite.TrustDomain + "/xs-3-b"} {
		svid, err := env.IssueX509SVID(id)
		if err != nil {
			return suite.ExecErrorf("issue SVID: %w", err)
		}
		env.ServeX509(svid)
		if _, err := env.WaitForSVID(ctx, id, suite.UpdateTimeout); err != nil {
			return err
		}
	}
	return nil
}

// runXS4 serves a bundle CA1‖CA2 for the same trust domain and expects peers
// from both CAs to be accepted.
func runXS4(ctx context.Context, env *suite.TestEnv) error {
	ca2, err := ca.New(suite.TrustDomain)
	if err != nil {
		return suite.ExecErrorf("create second CA: %w", err)
	}
	if _, err := env.PushX509AndWait(ctx, suite.X509Update{
		TrustBundle: [][]byte{env.CA().CACertDER(), ca2.CACertDER()},
	}); err != nil {
		return err
	}
	peer1, err := env.IssueX509SVID(suite.TrustDomain + "/xs-4-ca1")
	if err != nil {
		return suite.ExecErrorf("issue peer SVID: %w", err)
	}
	peer2, err := ca2.IssueX509SVID(suite.TrustDomain + "/xs-4-ca2")
	if err != nil {
		return suite.ExecErrorf("issue peer SVID: %w", err)
	}
	if err := serverRole.expectAccepted(env, peer1, "a peer from the first CA in the bundle"); err != nil {
		return err
	}
	return serverRole.expectAccepted(env, peer2, "a peer from the second CA in the bundle")
}

// runXS5 first trusts CA1‖CA2, then replaces the bundle with CA1 only; peers
// from CA2 must then be rejected while peers from CA1 are still accepted. CA1
// is the suite CA, which also issued the suite's probe certificate, so the
// barrier after the removal still works against a conforming SDK.
func runXS5(ctx context.Context, env *suite.TestEnv) error {
	ca2, err := ca.New(suite.TrustDomain)
	if err != nil {
		return suite.ExecErrorf("create second CA: %w", err)
	}
	peer1, err := env.IssueX509SVID(suite.TrustDomain + "/xs-5-ca1")
	if err != nil {
		return suite.ExecErrorf("issue peer SVID: %w", err)
	}
	peer2, err := ca2.IssueX509SVID(suite.TrustDomain + "/xs-5-ca2")
	if err != nil {
		return suite.ExecErrorf("issue peer SVID: %w", err)
	}

	if _, err := env.PushX509AndWait(ctx, suite.X509Update{
		TrustBundle: [][]byte{env.CA().CACertDER(), ca2.CACertDER()},
	}); err != nil {
		return err
	}
	if err := serverRole.expectAccepted(env, peer2, "a peer from CA2 while CA2 is in the bundle"); err != nil {
		return fmt.Errorf("positive control failed: %w", err)
	}

	// Barrier: the same trust domain's bundle, now CA1 only.
	if _, err := env.PushX509AndWait(ctx, suite.X509Update{
		TrustBundle: [][]byte{env.CA().CACertDER()},
	}); err != nil {
		return err
	}
	if err := serverRole.expectAccepted(env, peer1, "a peer from CA1 after the bundle was replaced with CA1 only"); err != nil {
		return fmt.Errorf("positive control failed: %w", err)
	}
	return serverRole.expectRejected(env, peer2, "a peer from CA2 after CA2 was removed from the bundle")
}
