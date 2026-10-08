package jwt

import (
	"context"
	"fmt"
	"slices"

	workloadv1 "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"

	"github.com/arndt-s/spiffe-conformance-test-suite/internal/ca"
	"github.com/arndt-s/spiffe-conformance-test-suite/internal/prober"
	"github.com/arndt-s/spiffe-conformance-test-suite/internal/workloadapi"
	"github.com/arndt-s/spiffe-conformance-test-suite/suite"
)

func init() {
	suite.Register(suite.TestCase{
		Name:        "JF-1",
		Description: "SDK calls FetchJWTSVID with the requested audience and returns the server's token",
		Run:         runJF1,
	})
}

func runJF1(ctx context.Context, env *suite.TestEnv) error {
	const audience = "jf-1-audience"
	tok, err := env.IssueJWT(workloadID, ca.WithJWTAudience(audience))
	if err != nil {
		return suite.ExecErrorf("issue JWT-SVID: %w", err)
	}
	if err := env.ServeJWT(tok); err != nil {
		return suite.ExecErrorf("serve JWT-SVID: %w", err)
	}

	res, err := env.FetchJWTFromSDK([]string{audience}, "")
	if err != nil {
		return err
	}
	if res.Status != prober.OutcomeOK {
		return fmt.Errorf("SDK failed to fetch a JWT-SVID: %s", res.Message)
	}
	if len(res.SVIDs) == 0 || res.SVIDs[0].Token != tok.Token || res.SVIDs[0].SPIFFEID != workloadID {
		return fmt.Errorf("SDK returned %+v, want the served token for %s", res.SVIDs, workloadID)
	}

	var fetches []workloadapi.Call
	for _, c := range env.Server().Calls() {
		if c.Method == workloadapi.MethodFetchJWTSVID {
			fetches = append(fetches, c)
		}
	}
	if len(fetches) == 0 {
		return fmt.Errorf("SDK returned a token without calling FetchJWTSVID")
	}
	req := fetches[len(fetches)-1].Request.(*workloadv1.JWTSVIDRequest)
	if !slices.Equal(req.Audience, []string{audience}) {
		return fmt.Errorf("SDK requested audience %v, want [%s]", req.Audience, audience)
	}
	return nil
}
