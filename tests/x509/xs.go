package x509

import (
	"context"

	"github.com/arndt-s/spiffe-conformance-test-suite/suite"
)

func init() {
	suite.Register(suite.TestCase{
		ID:          "XS-1",
		Description: "Presents the X.509-SVID received from FetchX509SVID",
		Level:       suite.MUST,
		Feature:     suite.X509Server,
		Ref:         "WA §5.2.1",
		Run:         runXS1,
	})
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
