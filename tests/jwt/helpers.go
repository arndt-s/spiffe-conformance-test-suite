package jwt

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/arndt-s/spiffe-conformance-test-suite/internal/ca"
	"github.com/arndt-s/spiffe-conformance-test-suite/internal/workloadapi"
	"github.com/arndt-s/spiffe-conformance-test-suite/suite"
	gojwt "github.com/golang-jwt/jwt/v5"
)

// register adds a jwt-validate test case.
func register(id, ref, desc string, run suite.TestFunc) {
	suite.Register(suite.TestCase{
		ID:          id,
		Description: desc,
		Level:       suite.MUST,
		Feature:     suite.JWTValidate,
		Ref:         ref,
		Run:         run,
	})
}

// defaultKey is the suite CA's ES256 key, published in the default bundle.
func defaultKey(env *suite.TestEnv) *ca.JWTKey { return env.CA().JWTKeys()[0] }

// signToken signs claims with key via ca.SignRawJWT; failures are suite-side.
func signToken(key *ca.JWTKey, header, claims map[string]any) (string, error) {
	tok, err := ca.SignRawJWT(key, header, claims)
	if err != nil {
		return "", suite.ExecErrorf("sign token: %w", err)
	}
	return tok, nil
}

// validToken returns a catalogue-default token (ES256 with the bundle key,
// aud ["conformance"], 5-minute exp) for sub.
func validToken(env *suite.TestEnv, sub string) (string, error) {
	return signToken(defaultKey(env), nil, ca.ValidJWTClaims(sub, suite.Audience))
}

// signInput signs an arbitrary JWS signing input with key's algorithm and
// returns the compact token "<input>.<b64url(signature)>".
func signInput(key *ca.JWTKey, input string) (string, error) {
	method := gojwt.GetSigningMethod(key.Alg)
	if method == nil {
		return "", suite.ExecErrorf("unsupported algorithm %q", key.Alg)
	}
	sig, err := method.Sign(input, key.Signer)
	if err != nil {
		return "", suite.ExecErrorf("sign: %w", err)
	}
	return input + "." + b64(sig), nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func b64JSON(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", suite.ExecErrorf("marshal: %w", err)
	}
	return b64(b), nil
}

// expectAccepted validates token until the SDK accepts it (up to
// suite.UpdateTimeout, so that a just-served bundle can arrive) and checks that
// the SDK reports wantID. what names the token in failure messages.
func expectAccepted(ctx context.Context, env *suite.TestEnv, token, wantID, what string) error {
	deadline := time.Now().Add(suite.UpdateTimeout)
	for {
		v, err := env.ValidateJWT(token, suite.Audience)
		if err != nil {
			return err
		}
		if v.Accepted {
			if v.SPIFFEID != wantID {
				return fmt.Errorf("%s: SDK accepted the token but reported SPIFFE ID %q, want %q", what, v.SPIFFEID, wantID)
			}
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s: SDK rejected a valid token (waited %s): %s", what, suite.UpdateTimeout, v.Message)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// positiveControl checks that the SDK accepts a valid token for controlID
// signed by key (nil: the default key). Every negative test calls it first so
// that a harness that rejects everything fails instead of passing.
func positiveControl(ctx context.Context, env *suite.TestEnv, key *ca.JWTKey, controlID string) error {
	if key == nil {
		key = defaultKey(env)
	}
	tok, err := signToken(key, nil, ca.ValidJWTClaims(controlID, suite.Audience))
	if err != nil {
		return err
	}
	return expectAccepted(ctx, env, tok, controlID, "positive control")
}

// expectRejected asserts that the SDK rejects token. what describes the
// defect for the failure message.
func expectRejected(env *suite.TestEnv, token, what string) error {
	v, err := env.ValidateJWT(token, suite.Audience)
	if err != nil {
		return err
	}
	if v.Accepted {
		return fmt.Errorf("SDK accepted %s (reported SPIFFE ID %q)", what, v.SPIFFEID)
	}
	return nil
}

// negative runs the default positive control (default key, a valid ID in the
// suite trust domain), then asserts that token is rejected.
func negative(ctx context.Context, env *suite.TestEnv, testID, token, what string) error {
	if err := positiveControl(ctx, env, nil, controlID(testID)); err != nil {
		return err
	}
	return expectRejected(env, token, what)
}

// controlID is the SPIFFE ID used by a test's positive control token.
func controlID(testID string) string {
	return suite.TrustDomain + "/control/" + strings.ToLower(strings.NewReplacer("/", "-").Replace(testID))
}

// subID is a valid SPIFFE ID in the suite trust domain for a test's token.
func subID(testID string) string {
	return suite.TrustDomain + "/" + strings.ToLower(strings.NewReplacer("/", "-").Replace(testID))
}

// serveBundles first runs the default positive control for testID, so that
// the SDK has loaded the initial bundle (some harnesses create their bundle
// source lazily), then serves the JWT bundles of the given CAs (keyed by
// trust domain) along with a default JWT-SVID for FetchJWTSVID. Callers must
// prove the new bundles were applied with a token only they can verify.
func serveBundles(ctx context.Context, env *suite.TestEnv, testID string, cas ...*ca.CA) error {
	if err := positiveControl(ctx, env, nil, controlID(testID)); err != nil {
		return err
	}
	def, err := env.IssueJWT(suite.DefaultSVIDID)
	if err != nil {
		return suite.ExecErrorf("issue default JWT-SVID: %w", err)
	}
	bundles := map[string][]byte{}
	for _, c := range cas {
		jwks, err := c.JWKSBytes()
		if err != nil {
			return suite.ExecErrorf("build JWKS for %s: %w", c.TrustDomain(), err)
		}
		bundles[c.TrustDomain()] = jwks
	}
	env.SetJWTState(&workloadapi.JWTState{
		Materials: []*ca.JWTSVIDMaterial{def},
		Bundles:   bundles,
	})
	return nil
}

// isPlain reports whether err is an SDK finding (FAIL) rather than a skip or
// an execution error.
func isPlain(err error) bool {
	var skip *suite.SkipError
	var exec *suite.ExecutionError
	return !errors.As(err, &skip) && !errors.As(err, &exec)
}

// newCA creates a CA for another trust domain.
func newCA(td string) (*ca.CA, error) {
	c, err := ca.New(td)
	if err != nil {
		return nil, suite.ExecErrorf("create CA for %s: %w", td, err)
	}
	return c, nil
}

// addKey adds a JWT key with alg to the suite CA's bundle.
func addKey(env *suite.TestEnv, alg string) (*ca.JWTKey, error) {
	k, err := env.CA().AddJWTKey(alg)
	if err != nil {
		return nil, suite.ExecErrorf("add %s key: %w", alg, err)
	}
	return k, nil
}
