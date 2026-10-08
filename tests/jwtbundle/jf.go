package jwtbundle

import (
	"context"
	"fmt"
	"slices"

	"google.golang.org/grpc/codes"

	"github.com/arndt-s/spiffe-conformance-test-suite/internal/ca"
	"github.com/arndt-s/spiffe-conformance-test-suite/internal/prober"
	"github.com/arndt-s/spiffe-conformance-test-suite/internal/workloadapi"
	"github.com/arndt-s/spiffe-conformance-test-suite/suite"
	workloadv1 "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
)

func init() {
	suite.Register(suite.TestCase{
		ID:          "JF-1",
		Description: "Calls FetchJWTSVID with the requested audience and returns the server's token",
		Level:       suite.MUST,
		Feature:     suite.JWTFetch,
		Ref:         "WA §6.2.1",
		Run:         runJF1,
	})
	suite.Register(suite.TestCase{
		ID:          "JF-2",
		Description: "Passes several audiences through unchanged",
		Level:       suite.MUST,
		Feature:     suite.JWTFetch,
		Ref:         "WA §6.2.1",
		Run:         runJF2,
	})
	suite.Register(suite.TestCase{
		ID:          "JF-3",
		Description: "Passes spiffe_id through when one is requested",
		Level:       suite.OPT,
		Feature:     suite.JWTFetch,
		Ref:         "WA §6.2.1",
		Run:         runJF3,
	})
	suite.Register(suite.TestCase{
		ID:          "JF-4",
		Description: "Reports PermissionDenied as an error instead of returning a stale token",
		Level:       suite.OPT,
		Feature:     suite.JWTFetch,
		Ref:         "WA §6.2.1",
		Run:         runJF4,
	})
}

// serveJWTSVIDs serves the given JWT-SVIDs with the suite CA's bundle.
func serveJWTSVIDs(env *suite.TestEnv, svids ...*ca.JWTSVIDMaterial) error {
	b, err := jwks(env.CA().JWTKeys())
	if err != nil {
		return err
	}
	env.SetJWTState(&workloadapi.JWTState{
		Materials: svids,
		Bundles:   bundleSet{suite.TrustDomain: b},
	})
	return nil
}

func issue(env *suite.TestEnv, sub string, aud ...string) (*ca.JWTSVIDMaterial, error) {
	m, err := env.IssueJWT(sub, ca.WithJWTAudience(aud...), ca.WithJWTTTL(tokenTTL))
	if err != nil {
		return nil, suite.ExecErrorf("issue JWT-SVID: %w", err)
	}
	return m, nil
}

// fetchRequests returns the FetchJWTSVID requests recorded after the first
// `skip` calls.
func fetchRequests(env *suite.TestEnv, skip int) []*workloadv1.JWTSVIDRequest {
	var out []*workloadv1.JWTSVIDRequest
	for i, c := range env.Server().Calls() {
		if i < skip || c.Method != workloadapi.MethodFetchJWTSVID {
			continue
		}
		if r, ok := c.Request.(*workloadv1.JWTSVIDRequest); ok {
			out = append(out, r)
		}
	}
	return out
}

// fetch asks the SDK to fetch JWT-SVIDs and returns the response together
// with the FetchJWTSVID requests the SDK made while doing so.
func fetch(env *suite.TestEnv, audience []string, spiffeID string) (*prober.ControlResponse, []*workloadv1.JWTSVIDRequest, error) {
	before := len(env.Server().Calls())
	res, err := env.FetchJWTFromSDK(audience, spiffeID)
	if err != nil {
		return nil, nil, err
	}
	return res, fetchRequests(env, before), nil
}

func requireOK(res *prober.ControlResponse) error {
	if res.Status != prober.OutcomeOK {
		return fmt.Errorf("fetch did not succeed: status %q: %s", res.Status, res.Message)
	}
	return nil
}

func sameSet(a, b []string) bool {
	x, y := slices.Clone(a), slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(x, y)
}

// checkAudience asserts that the SDK made at least one FetchJWTSVID call and
// that every call carried exactly the requested audiences.
func checkAudience(reqs []*workloadv1.JWTSVIDRequest, want []string) error {
	if len(reqs) == 0 {
		return fmt.Errorf("SDK returned a token without calling FetchJWTSVID")
	}
	for _, r := range reqs {
		if !sameSet(r.Audience, want) {
			return fmt.Errorf("FetchJWTSVID request carried audience %q, want %q", r.Audience, want)
		}
	}
	return nil
}

func hasToken(res *prober.ControlResponse, tok string) bool {
	for _, s := range res.SVIDs {
		if s.Token == tok {
			return true
		}
	}
	return false
}

func runJFAudience(env *suite.TestEnv, sub string, aud []string) error {
	svid, err := issue(env, sub, aud...)
	if err != nil {
		return err
	}
	if err := serveJWTSVIDs(env, svid); err != nil {
		return err
	}
	res, reqs, err := fetch(env, aud, "")
	if err != nil {
		return err
	}
	if err := requireOK(res); err != nil {
		return err
	}
	if err := checkAudience(reqs, aud); err != nil {
		return err
	}
	if !hasToken(res, svid.Token) {
		return fmt.Errorf("SDK did not return the token served by FetchJWTSVID (got %d SVIDs)", len(res.SVIDs))
	}
	return nil
}

func runJF1(_ context.Context, env *suite.TestEnv) error {
	return runJFAudience(env, suite.DefaultSVIDID, []string{suite.Audience})
}

func runJF2(_ context.Context, env *suite.TestEnv) error {
	return runJFAudience(env, suite.DefaultSVIDID, []string{suite.Audience, "spiffe://test.example.org/jf-2-backend", "jf-2-other"})
}

func runJF3(_ context.Context, env *suite.TestEnv) error {
	other := suite.TrustDomain + "/jf-3-other"
	def, err := issue(env, suite.DefaultSVIDID, suite.Audience)
	if err != nil {
		return err
	}
	alt, err := issue(env, other, suite.Audience)
	if err != nil {
		return err
	}
	if err := serveJWTSVIDs(env, def, alt); err != nil {
		return err
	}
	res, reqs, err := fetch(env, []string{suite.Audience}, other)
	if err != nil {
		return err
	}
	if err := requireOK(res); err != nil {
		return err
	}
	if err := checkAudience(reqs, []string{suite.Audience}); err != nil {
		return err
	}
	for _, r := range reqs {
		if r.SpiffeId != other {
			return fmt.Errorf("FetchJWTSVID request carried spiffe_id %q, want %q", r.SpiffeId, other)
		}
	}
	if !hasToken(res, alt.Token) {
		return fmt.Errorf("SDK did not return the JWT-SVID for the requested SPIFFE ID %s", other)
	}
	if hasToken(res, def.Token) {
		return fmt.Errorf("SDK returned the JWT-SVID for %s although %s was requested", suite.DefaultSVIDID, other)
	}
	return nil
}

func runJF4(_ context.Context, env *suite.TestEnv) error {
	aud := []string{suite.Audience}
	svid, err := issue(env, suite.DefaultSVIDID, aud...)
	if err != nil {
		return err
	}
	if err := serveJWTSVIDs(env, svid); err != nil {
		return err
	}
	// Positive control: the fetch succeeds while the server answers.
	res, _, err := fetch(env, aud, "")
	if err != nil {
		return err
	}
	if err := requireOK(res); err != nil {
		return fmt.Errorf("positive control: %w", err)
	}
	if !hasToken(res, svid.Token) {
		return fmt.Errorf("positive control: SDK did not return the served token")
	}

	env.Server().InjectError(workloadapi.MethodFetchJWTSVID, codes.PermissionDenied, -1)
	res, reqs, err := fetch(env, aud, "")
	if err != nil {
		return err
	}
	switch res.Status {
	case prober.OutcomeError, prober.OutcomeRejected:
		return nil
	}
	stale := ""
	if hasToken(res, svid.Token) {
		stale = " (the previously fetched token)"
	}
	if len(reqs) == 0 {
		return fmt.Errorf("the Workload API now denies JWT-SVIDs, but the SDK returned %d cached token(s)%s without calling FetchJWTSVID (status %q)",
			len(res.SVIDs), stale, res.Status)
	}
	return fmt.Errorf("FetchJWTSVID answered PermissionDenied, but the harness reported status %q with %d token(s)%s",
		res.Status, len(res.SVIDs), stale)
}
