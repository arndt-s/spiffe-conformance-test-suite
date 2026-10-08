package jwtbundle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/arndt-s/spiffe-conformance-test-suite/internal/ca"
	"github.com/arndt-s/spiffe-conformance-test-suite/internal/workloadapi"
	"github.com/arndt-s/spiffe-conformance-test-suite/suite"
)

// ForeignTrustDomain is the second trust domain used by federation and
// bundle-removal tests.
const ForeignTrustDomain = "spiffe://other.example.org"

// tokenTTL matches the catalogue default (§6: 5-minute exp).
const tokenTTL = 5 * time.Minute

// bundleSet is one streamed JWT bundle update: JWKS documents keyed by trust
// domain SPIFFE ID.
type bundleSet map[string][]byte

// jwks builds a JWK Set from keys plus raw extra entries. A failure is a
// suite-side problem.
func jwks(keys []*ca.JWTKey, extra ...json.RawMessage) ([]byte, error) {
	b, err := ca.BuildJWKS(keys, extra...)
	if err != nil {
		return nil, suite.ExecErrorf("build JWKS: %w", err)
	}
	return b, nil
}

// pushBundles serves bundles as the complete JWT bundle state. It keeps a
// JWT-SVID for the default identity available so that SDK sources which also
// fetch JWT-SVIDs keep working.
func pushBundles(env *suite.TestEnv, bundles bundleSet) error {
	svid, err := env.IssueJWT(suite.DefaultSVIDID, ca.WithJWTAudience(suite.Audience), ca.WithJWTTTL(time.Hour))
	if err != nil {
		return suite.ExecErrorf("issue default JWT-SVID: %w", err)
	}
	env.SetJWTState(&workloadapi.JWTState{
		Materials: []*ca.JWTSVIDMaterial{svid},
		Bundles:   bundles,
	})
	return nil
}

// newKey adds a fresh ES256 key to the suite CA's key list and returns it.
// Tests publish bundles explicitly, so adding a key does not publish it.
func newKey(env *suite.TestEnv) (*ca.JWTKey, error) {
	k, err := env.CA().AddJWTKey("ES256")
	if err != nil {
		return nil, suite.ExecErrorf("generate JWT key: %w", err)
	}
	return k, nil
}

// token issues a valid JWT-SVID for sub with audience suite.Audience, signed
// by key k of issuer.
func token(issuer *ca.CA, sub string, k *ca.JWTKey) (string, error) {
	m, err := issuer.IssueJWT(sub,
		ca.WithJWTKey(k),
		ca.WithJWTAudience(suite.Audience),
		ca.WithJWTTTL(tokenTTL),
	)
	if err != nil {
		return "", suite.ExecErrorf("issue JWT-SVID for %s: %w", sub, err)
	}
	return m.Token, nil
}

// waitAccepted is the positive control / barrier: it waits until the SDK
// accepts tok. what describes the token in the failure message.
func waitAccepted(ctx context.Context, env *suite.TestEnv, tok, what string) error {
	if err := env.WaitForJWTAccepted(ctx, tok, suite.Audience, suite.UpdateTimeout); err != nil {
		if isSuiteErr(err) {
			return err
		}
		return fmt.Errorf("%s: %w", what, err)
	}
	return nil
}

// expectRejected validates tok once and fails if the SDK accepts it.
func expectRejected(env *suite.TestEnv, tok, what string) error {
	v, err := env.ValidateJWT(tok, suite.Audience)
	if err != nil {
		return err
	}
	if v.Accepted {
		return fmt.Errorf("SDK accepted %s (reported SPIFFE ID %q)", what, v.SPIFFEID)
	}
	return nil
}

// isSuiteErr reports whether err is a SkipError or ExecutionError that must be
// propagated unchanged.
func isSuiteErr(err error) bool {
	var skip *suite.SkipError
	var exec *suite.ExecutionError
	return errors.As(err, &skip) || errors.As(err, &exec)
}

// newForeignCA creates the CA of ForeignTrustDomain.
func newForeignCA() (*ca.CA, error) {
	c, err := ca.New(ForeignTrustDomain)
	if err != nil {
		return nil, suite.ExecErrorf("create foreign CA: %w", err)
	}
	return c, nil
}
