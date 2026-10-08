package jwt

import (
	"context"
	"crypto/rand"
	"fmt"
	"strings"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"

	"github.com/arndt-s/spiffe-conformance-test-suite/internal/ca"
	"github.com/arndt-s/spiffe-conformance-test-suite/internal/workloadapi"
	"github.com/arndt-s/spiffe-conformance-test-suite/suite"
)

func init() {
	suite.Register(suite.TestCase{
		Name:        "J1",
		Description: "SDK uses the JWT Bundle from the Workload API for validation",
		Run:         runJ1,
	})
	suite.Register(suite.TestCase{
		Name:        "J2",
		Description: "SDK rejects a JWT signed by a key not in the JWKS bundle",
		Run:         runJ2,
	})
	suite.Register(suite.TestCase{
		Name:        "J3",
		Description: "SDK rejects a JWT with an unexpected audience claim",
		Run:         runJ3,
	})
	suite.Register(suite.TestCase{
		Name:        "J4",
		Description: "SDK rejects a malformed JWT",
		Run:         runJ4,
	})
	suite.Register(suite.TestCase{
		Name:        "J5",
		Description: "SDK rejects a JWT with an invalid signature",
		Run:         runJ5,
	})
	suite.Register(suite.TestCase{
		Name:        "J6",
		Description: "SDK rejects a JWT with an expired 'exp' claim",
		Run:         runJ6,
	})
	suite.Register(suite.TestCase{
		Name:        "J7",
		Description: "SDK rejects a JWT with a non-SPIFFE ID 'sub' claim",
		Run:         runJ7,
	})
	suite.Register(suite.TestCase{
		Name:        "J8",
		Description: "SDK rejects a JWT with a 'sub' claim which does not match the trust domain",
		Run:         runJ8,
	})
	suite.Register(suite.TestCase{
		Name:        "J9",
		Description: "SDK rejects JWTs signed with 'none' algorithm or a symmetric key when the bundle advertises an asymmetric key",
		Run:         runJ9,
	})
	suite.Register(suite.TestCase{
		Name:        "J10",
		Description: "SDK rejects a JWT missing the required 'exp' claim",
		Run:         runJ10,
	})
	suite.Register(suite.TestCase{
		Name:        "J11",
		Description: "SDK rejects a JWT missing the required 'aud' claim",
		Run:         runJ11,
	})
	suite.Register(suite.TestCase{
		Name:        "J12",
		Description: "SDK rejects a JWT with an invalid 'typ' header",
		Run:         runJ12,
	})
	suite.Register(suite.TestCase{
		Name:        "J13",
		Description: "SDK picks up a new JWKS bundle when it rotates and rejects tokens signed by the old key",
		Run:         runJ13,
	})
}

const workloadID = "spiffe://test.example.org/workload"

// expectAccepted validates token and fails unless the SDK accepted it as
// wantID.
func expectAccepted(env *suite.TestEnv, token, wantID string) error {
	v, err := env.ValidateJWT(token, ValidAudience)
	if err != nil {
		return err
	}
	if !v.Accepted {
		return fmt.Errorf("SDK rejected a valid JWT-SVID: %s", v.Message)
	}
	if v.SPIFFEID != wantID {
		return fmt.Errorf("SDK returned SPIFFE ID %q, want %q", v.SPIFFEID, wantID)
	}
	return nil
}

// expectRejected validates token and fails if the SDK accepted it.
func expectRejected(env *suite.TestEnv, token, what string) error {
	v, err := env.ValidateJWT(token, ValidAudience)
	if err != nil {
		return err
	}
	if v.Accepted {
		return fmt.Errorf("SDK accepted %s (returned SPIFFE ID %q)", what, v.SPIFFEID)
	}
	return nil
}

// serveBundleWithControl serves the test CA's JWT bundle and checks that the
// SDK accepts a valid token, so that a later rejection means something.
func serveBundleWithControl(env *suite.TestEnv) error {
	if err := env.ServeJWTBundle(); err != nil {
		return suite.ExecErrorf("serve JWT bundle: %w", err)
	}
	valid, err := env.IssueJWT(workloadID, ca.WithJWTAudience(ValidAudience))
	if err != nil {
		return suite.ExecErrorf("issue control JWT: %w", err)
	}
	if err := expectAccepted(env, valid.Token, workloadID); err != nil {
		return fmt.Errorf("positive control: %w", err)
	}
	return nil
}

// rejectIssued serves the bundle, runs the positive control, issues a token
// with opts from the test CA and expects the SDK to reject it.
func rejectIssued(env *suite.TestEnv, spiffeID, what string, opts ...ca.JWTSVIDOption) error {
	if err := serveBundleWithControl(env); err != nil {
		return err
	}
	tok, err := env.IssueJWT(spiffeID, append([]ca.JWTSVIDOption{ca.WithJWTAudience(ValidAudience)}, opts...)...)
	if err != nil {
		return suite.ExecErrorf("issue JWT: %w", err)
	}
	return expectRejected(env, tok.Token, what)
}

func runJ1(ctx context.Context, env *suite.TestEnv) error {
	if err := env.ServeJWTBundle(); err != nil {
		return suite.ExecErrorf("serve JWT bundle: %w", err)
	}
	tok, err := env.IssueJWT(workloadID, ca.WithJWTAudience(ValidAudience))
	if err != nil {
		return suite.ExecErrorf("issue JWT SVID: %w", err)
	}
	return expectAccepted(env, tok.Token, workloadID)
}

func runJ2(ctx context.Context, env *suite.TestEnv) error {
	if err := serveBundleWithControl(env); err != nil {
		return err
	}
	// A second CA for the same trust domain has its own key with its own kid,
	// which is not in the bundle being served.
	foreignCA, err := ca.New("spiffe://test.example.org")
	if err != nil {
		return suite.ExecErrorf("create foreign CA: %w", err)
	}
	tok, err := foreignCA.IssueJWT(workloadID, ca.WithJWTAudience(ValidAudience))
	if err != nil {
		return suite.ExecErrorf("issue foreign JWT: %w", err)
	}
	return expectRejected(env, tok.Token, "a JWT signed by a key not in the bundle")
}

func runJ3(ctx context.Context, env *suite.TestEnv) error {
	return rejectIssued(env, workloadID, "a JWT for a different audience", ca.WithJWTAudience("wrong-audience"))
}

func runJ4(ctx context.Context, env *suite.TestEnv) error {
	if err := serveBundleWithControl(env); err != nil {
		return err
	}
	return expectRejected(env, "not_a.valid.jwt", "a malformed JWT")
}

func runJ5(ctx context.Context, env *suite.TestEnv) error {
	if err := serveBundleWithControl(env); err != nil {
		return err
	}
	tok, err := env.IssueJWT(workloadID, ca.WithJWTAudience(ValidAudience))
	if err != nil {
		return suite.ExecErrorf("issue JWT SVID: %w", err)
	}
	return expectRejected(env, flipSignatureChar(tok.Token), "a JWT with a tampered signature")
}

// flipSignatureChar changes one base64url character in the middle of the
// signature, so the token stays well-formed but the signature is wrong.
func flipSignatureChar(token string) string {
	i := strings.LastIndex(token, ".") + (len(token)-strings.LastIndex(token, "."))/2
	b := []byte(token)
	if b[i] == 'A' {
		b[i] = 'B'
	} else {
		b[i] = 'A'
	}
	return string(b)
}

func runJ6(ctx context.Context, env *suite.TestEnv) error {
	return rejectIssued(env, workloadID, "an expired JWT", ca.WithJWTTTL(-1*time.Hour))
}

func runJ7(ctx context.Context, env *suite.TestEnv) error {
	return rejectIssued(env, workloadID, "a JWT whose sub is not a SPIFFE ID", ca.WithJWTClaim("sub", "not-a-spiffe-id"))
}

func runJ8(ctx context.Context, env *suite.TestEnv) error {
	return rejectIssued(env, "spiffe://other.example.org/workload", "a JWT from a trust domain without a bundle")
}

func runJ9(ctx context.Context, env *suite.TestEnv) error {
	if err := serveBundleWithControl(env); err != nil {
		return err
	}

	now := time.Now()
	claims := jwtlib.MapClaims{
		"sub": workloadID,
		"aud": jwtlib.ClaimStrings{ValidAudience},
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	}

	none, err := jwtlib.NewWithClaims(jwtlib.SigningMethodNone, claims).SignedString(jwtlib.UnsafeAllowNoneSignatureType)
	if err != nil {
		return suite.ExecErrorf("sign none token: %w", err)
	}
	if err := expectRejected(env, none, "an alg=none JWT"); err != nil {
		return err
	}

	hmacKey := make([]byte, 32)
	if _, err := rand.Read(hmacKey); err != nil {
		return suite.ExecErrorf("generate HMAC key: %w", err)
	}
	hs, err := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, claims).SignedString(hmacKey)
	if err != nil {
		return suite.ExecErrorf("sign HS256 token: %w", err)
	}
	return expectRejected(env, hs, "an alg=HS256 JWT")
}

func runJ10(ctx context.Context, env *suite.TestEnv) error {
	return rejectIssued(env, workloadID, "a JWT without exp", ca.WithJWTDeleteClaim("exp"))
}

func runJ11(ctx context.Context, env *suite.TestEnv) error {
	return rejectIssued(env, workloadID, "a JWT without aud", ca.WithJWTDeleteClaim("aud"))
}

func runJ12(ctx context.Context, env *suite.TestEnv) error {
	return rejectIssued(env, workloadID, "a JWT with typ=INVALID", ca.WithJWTHeader("typ", "INVALID"))
}

func runJ13(ctx context.Context, env *suite.TestEnv) error {
	// Step 1: a token signed with the original key validates.
	jwt1, err := env.IssueJWT(workloadID, ca.WithJWTAudience(ValidAudience))
	if err != nil {
		return suite.ExecErrorf("issue JWT1: %w", err)
	}
	if err := env.ServeJWTBundle(); err != nil {
		return suite.ExecErrorf("serve initial JWKS: %w", err)
	}
	if err := expectAccepted(env, jwt1.Token, workloadID); err != nil {
		return fmt.Errorf("before rotation: %w", err)
	}

	// Step 2: rotate the bundle to a new key only.
	ca2, err := ca.New("spiffe://test.example.org")
	if err != nil {
		return suite.ExecErrorf("create ca2: %w", err)
	}
	jwks2, err := ca2.JWKSBytes()
	if err != nil {
		return suite.ExecErrorf("get ca2 JWKS: %w", err)
	}
	env.SetJWTState(&workloadapi.JWTState{
		Bundles: map[string][]byte{ca2.TrustDomain(): jwks2},
	})

	// Step 3: wait until the SDK accepts a token signed with the new key.
	jwt2, err := ca2.IssueJWT(workloadID, ca.WithJWTAudience(ValidAudience))
	if err != nil {
		return suite.ExecErrorf("issue JWT2: %w", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		v, err := env.ValidateJWT(jwt2.Token, ValidAudience)
		if err != nil {
			return err
		}
		if v.Accepted {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("SDK did not pick up the rotated JWT bundle within 5s")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}

	// Step 4: the old key is gone, so JWT1 must now be rejected.
	return expectRejected(env, jwt1.Token, "a JWT signed by a key removed from the bundle")
}
