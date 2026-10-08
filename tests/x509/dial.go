package x509

import (
	"context"
	"fmt"

	"github.com/arndt-s/spiffe-conformance-test-suite/suite"
)

func init() {
	suite.Register(suite.TestCase{
		Name:        "XV-1/client",
		Description: "SDK, as mTLS client, accepts a valid server SVID and presents its own SVID",
		Run:         runXV1Client,
	})
}

func runXV1Client(ctx context.Context, env *suite.TestEnv) error {
	const serverID = "spiffe://test.example.org/server"
	server, err := env.IssueX509SVID(serverID)
	if err != nil {
		return suite.ExecErrorf("issue server SVID: %w", err)
	}

	v, err := env.DialFromSDK(server)
	if err != nil {
		return err
	}
	if !v.Accepted {
		return fmt.Errorf("SDK rejected a valid server SVID: %s", v.Message)
	}
	if v.ServerID != serverID {
		return fmt.Errorf("SDK reported server ID %q, want %q", v.ServerID, serverID)
	}
	if v.ClientID != "spiffe://test.example.org/default" {
		return fmt.Errorf("SDK presented client SVID %q, want its default SVID spiffe://test.example.org/default", v.ClientID)
	}
	return nil
}
