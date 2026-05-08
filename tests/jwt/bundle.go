package jwt

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/url"
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

func runJ1(ctx context.Context, env *suite.TestEnv) error {
	// Issue a JWT SVID for the audience the SDK expects.
	// The demo uses "test" as the default audience (see demo/main.go).
	spiffeID := "spiffe://test.example.org/workload"

	jwtMaterial, err := env.IssueJWT(spiffeID, ca.WithJWTAudience(ValidAudience))
	if err != nil {
		return fmt.Errorf("issue JWT SVID: %w", err)
	}

	// Serve the JWKS bundle so the SDK can validate the token.
	if err := env.ServeJWTBundle(); err != nil {
		return fmt.Errorf("serve JWT bundle: %w", err)
	}

	// Probe the SDK's JWT port with the issued token
	result, err := env.ProbeJWT(jwtMaterial.Token)
	if err != nil {
		return fmt.Errorf("probe JWT endpoint: %w", err)
	}

	// Verify the SDK validated the token successfully
	if result.Status != "valid" {
		return fmt.Errorf("expected status 'valid', got %q", result.Status)
	}

	// Verify the SDK returned the correct SPIFFE ID
	if result.SPIFFEID != spiffeID {
		return fmt.Errorf("expected SPIFFE ID %q, got %q", spiffeID, result.SPIFFEID)
	}

	return nil
}

func runJ2(ctx context.Context, env *suite.TestEnv) error {
	// Create a second CA with an independent JWT signing key.
	foreignCA, err := ca.New("spiffe://test.example.org")
	if err != nil {
		return fmt.Errorf("create foreign CA: %w", err)
	}

	// Issue a JWT signed by the foreign key.
	foreignMaterial, err := foreignCA.IssueJWT(
		"spiffe://test.example.org/workload",
		ca.WithJWTAudience(ValidAudience),
	)
	if err != nil {
		return fmt.Errorf("issue foreign JWT: %w", err)
	}

	// Serve the foreign token, but ServeJWT populates JWKS from env.ca (the
	// first CA), so the public key in the bundle will not match the token's
	// signature.
	if err := env.ServeJWT("test", foreignMaterial); err != nil {
		return fmt.Errorf("serve JWT state: %w", err)
	}

	result, err := env.ProbeJWT(foreignMaterial.Token)
	if err != nil {
		return fmt.Errorf("probe: %w", err)
	}

	if result.HTTPStatus == 200 {
		return fmt.Errorf("expected non HTTP 200 from SDK, got %d", result.HTTPStatus)
	}
	if result.Status == "valid" {
		return fmt.Errorf("expected SDK to reject foreign-key JWT, but got status %q", result.Status)
	}
	return nil
}

func runJ3(ctx context.Context, env *suite.TestEnv) error {
	// Issue a JWT with an audience claim that the SDK does not expect.
	spiffeID := "spiffe://test.example.org/workload"
	wrongAudience := "wrong-audience"

	jwtMaterial, err := env.IssueJWT(spiffeID, ca.WithJWTAudience(wrongAudience))
	if err != nil {
		return fmt.Errorf("issue JWT SVID: %w", err)
	}

	// Serve the JWKS bundle so the SDK can validate the signature.
	if err := env.ServeJWTBundle(); err != nil {
		return fmt.Errorf("serve JWT bundle: %w", err)
	}

	result, err := env.ProbeJWT(jwtMaterial.Token)
	if err != nil {
		return fmt.Errorf("probe JWT endpoint: %w", err)
	}

	// The SDK should reject the JWT due to audience mismatch.
	if result.HTTPStatus == 200 {
		return fmt.Errorf("expected non HTTP 200 from SDK, got %d", result.HTTPStatus)
	}
	if result.Status == "valid" {
		return fmt.Errorf("expected SDK to reject JWT with wrong audience, but got status %q", result.Status)
	}

	return nil
}

func runJ4(ctx context.Context, env *suite.TestEnv) error {
	// Serve the JWKS bundle first.
	if err := env.ServeJWTBundle(); err != nil {
		return fmt.Errorf("serve JWT bundle: %w", err)
	}

	// Send a malformed JWT (not enough parts).
	malformedToken := "not_a.valid.jwt"

	result, err := env.ProbeJWT(malformedToken)
	if err != nil {
		return fmt.Errorf("probe JWT endpoint: %w", err)
	}

	// The SDK should reject the malformed JWT.
	if result.HTTPStatus == 200 {
		return fmt.Errorf("expected non HTTP 200 from SDK, got %d", result.HTTPStatus)
	}
	if result.Status == "valid" {
		return fmt.Errorf("expected SDK to reject malformed JWT, but got status %q", result.Status)
	}

	return nil
}

func runJ5(ctx context.Context, env *suite.TestEnv) error {
	// Issue a valid JWT.
	spiffeID := "spiffe://test.example.org/workload"

	jwtMaterial, err := env.IssueJWT(spiffeID, ca.WithJWTAudience(ValidAudience))
	if err != nil {
		return fmt.Errorf("issue JWT SVID: %w", err)
	}

	// Serve the JWKS bundle.
	if err := env.ServeJWTBundle(); err != nil {
		return fmt.Errorf("serve JWT bundle: %w", err)
	}

	// Corrupt the signature by appending garbage to the token.
	corruptToken := jwtMaterial.Token + "corrupted"

	result, err := env.ProbeJWT(corruptToken)
	if err != nil {
		return fmt.Errorf("probe JWT endpoint: %w", err)
	}

	// The SDK should reject the JWT due to invalid signature.
	if result.HTTPStatus == 200 {
		return fmt.Errorf("expected non HTTP 200 from SDK, got %d", result.HTTPStatus)
	}
	if result.Status == "valid" {
		return fmt.Errorf("expected SDK to reject JWT with invalid signature, but got status %q", result.Status)
	}

	return nil
}

func runJ6(ctx context.Context, env *suite.TestEnv) error {
	// Issue a JWT with a very short TTL and then wait for it to expire.
	// Use a negative TTL to issue an already-expired token.
	spiffeID := "spiffe://test.example.org/workload"

	jwtMaterial, err := env.IssueJWT(
		spiffeID,
		ca.WithJWTAudience(ValidAudience),
		ca.WithJWTTTL(-1*time.Hour), // Already expired
	)
	if err != nil {
		return fmt.Errorf("issue JWT SVID: %w", err)
	}

	// Serve the JWKS bundle.
	if err := env.ServeJWTBundle(); err != nil {
		return fmt.Errorf("serve JWT bundle: %w", err)
	}

	result, err := env.ProbeJWT(jwtMaterial.Token)
	if err != nil {
		return fmt.Errorf("probe JWT endpoint: %w", err)
	}

	// The SDK should reject the expired JWT.
	if result.HTTPStatus == 200 {
		return fmt.Errorf("expected non HTTP 200 from SDK, got %d", result.HTTPStatus)
	}
	if result.Status == "valid" {
		return fmt.Errorf("expected SDK to reject expired JWT, but got status %q", result.Status)
	}

	return nil
}

func runJ7(ctx context.Context, env *suite.TestEnv) error {
	// Issue a JWT with a non-SPIFFE ID in the 'sub' claim.
	// We use WithJWTClaim to override the subject with a non-SPIFFE ID.
	nonSpiffeID := "not-a-spiffe-id"

	// First issue a normal JWT to get the structure, but we need to use
	// a raw JWT construction via WithJWTClaim to override 'sub'.
	jwtMaterial, err := env.IssueJWT(
		"spiffe://test.example.org/workload",
		ca.WithJWTAudience(ValidAudience),
		ca.WithJWTClaim("sub", nonSpiffeID), // Override 'sub' with non-SPIFFE value
	)
	if err != nil {
		return fmt.Errorf("issue JWT SVID: %w", err)
	}

	// Serve the JWKS bundle.
	if err := env.ServeJWTBundle(); err != nil {
		return fmt.Errorf("serve JWT bundle: %w", err)
	}

	result, err := env.ProbeJWT(jwtMaterial.Token)
	if err != nil {
		return fmt.Errorf("probe JWT endpoint: %w", err)
	}

	// The SDK should reject the JWT due to non-SPIFFE 'sub' claim.
	if result.HTTPStatus == 200 {
		return fmt.Errorf("expected non HTTP 200 from SDK, got %d", result.HTTPStatus)
	}
	if result.Status == "valid" {
		return fmt.Errorf("expected SDK to reject JWT with non-SPIFFE 'sub', but got status %q", result.Status)
	}

	return nil
}

func runJ8(ctx context.Context, env *suite.TestEnv) error {
	// Issue a JWT with a SPIFFE ID from a different trust domain.
	wrongTrustDomainID := "spiffe://other.example.org/workload"

	jwtMaterial, err := env.IssueJWT(
		wrongTrustDomainID,
		ca.WithJWTAudience(ValidAudience),
	)
	if err != nil {
		return fmt.Errorf("issue JWT SVID: %w", err)
	}

	// Serve the JWKS bundle for the correct trust domain.
	if err := env.ServeJWTBundle(); err != nil {
		return fmt.Errorf("serve JWT bundle: %w", err)
	}

	result, err := env.ProbeJWT(jwtMaterial.Token)
	if err != nil {
		return fmt.Errorf("probe JWT endpoint: %w", err)
	}

	// The SDK should reject the JWT due to trust domain mismatch.
	if result.HTTPStatus == 200 {
		return fmt.Errorf("expected non HTTP 200 from SDK, got %d", result.HTTPStatus)
	}
	if result.Status == "valid" {
		return fmt.Errorf("expected SDK to reject JWT with wrong trust domain, but got status %q", result.Status)
	}

	return nil
}

func runJ9(ctx context.Context, env *suite.TestEnv) error {
	if err := env.ServeJWTBundle(); err != nil {
		return fmt.Errorf("serve JWT bundle: %w", err)
	}

	spiffeID := "spiffe://test.example.org/workload"
	now := time.Now()
	baseClaims := jwtlib.MapClaims{
		"sub": spiffeID,
		"aud": jwtlib.ClaimStrings{ValidAudience},
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	}

	// Sub-test 1: alg=none
	noneToken := jwtlib.NewWithClaims(jwtlib.SigningMethodNone, baseClaims)
	noneStr, err := noneToken.SignedString(jwtlib.UnsafeAllowNoneSignatureType)
	if err != nil {
		return fmt.Errorf("sign none token: %w", err)
	}
	r1, err := env.ProbeJWT(noneStr)
	if err != nil {
		return fmt.Errorf("probe alg=none: %w", err)
	}
	if r1.Status == "valid" {
		return fmt.Errorf("J9: SDK accepted alg=none token")
	}

	// Sub-test 2: alg=HS256 with a random symmetric key
	hmacKey := make([]byte, 32)
	if _, err := rand.Read(hmacKey); err != nil {
		return fmt.Errorf("generate HMAC key: %w", err)
	}
	hmacToken := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, baseClaims)
	hmacStr, err := hmacToken.SignedString(hmacKey)
	if err != nil {
		return fmt.Errorf("sign HS256 token: %w", err)
	}
	r2, err := env.ProbeJWT(hmacStr)
	if err != nil {
		return fmt.Errorf("probe alg=HS256: %w", err)
	}
	if r2.Status == "valid" {
		return fmt.Errorf("J9: SDK accepted alg=HS256 token signed with unknown symmetric key")
	}

	return nil
}

func runJ10(ctx context.Context, env *suite.TestEnv) error {
	spiffeID := "spiffe://test.example.org/workload"

	jwtMaterial, err := env.IssueJWT(spiffeID,
		ca.WithJWTAudience(ValidAudience),
		ca.WithJWTDeleteClaim("exp"),
	)
	if err != nil {
		return fmt.Errorf("issue JWT without exp: %w", err)
	}

	if err := env.ServeJWTBundle(); err != nil {
		return fmt.Errorf("serve JWT bundle: %w", err)
	}

	result, err := env.ProbeJWT(jwtMaterial.Token)
	if err != nil {
		return fmt.Errorf("probe JWT endpoint: %w", err)
	}

	if result.Status == "valid" {
		return fmt.Errorf("J10: SDK accepted JWT without 'exp' claim")
	}
	return nil
}

func runJ11(ctx context.Context, env *suite.TestEnv) error {
	spiffeID := "spiffe://test.example.org/workload"

	jwtMaterial, err := env.IssueJWT(spiffeID,
		ca.WithJWTAudience(ValidAudience),
		ca.WithJWTDeleteClaim("aud"),
	)
	if err != nil {
		return fmt.Errorf("issue JWT without aud: %w", err)
	}

	if err := env.ServeJWTBundle(); err != nil {
		return fmt.Errorf("serve JWT bundle: %w", err)
	}

	result, err := env.ProbeJWT(jwtMaterial.Token)
	if err != nil {
		return fmt.Errorf("probe JWT endpoint: %w", err)
	}

	if result.Status == "valid" {
		return fmt.Errorf("J11: SDK accepted JWT without 'aud' claim")
	}
	return nil
}

func runJ12(ctx context.Context, env *suite.TestEnv) error {
	spiffeID := "spiffe://test.example.org/workload"

	jwtMaterial, err := env.IssueJWT(spiffeID,
		ca.WithJWTAudience(ValidAudience),
		ca.WithJWTHeader("typ", "INVALID"),
	)
	if err != nil {
		return fmt.Errorf("issue JWT with invalid typ: %w", err)
	}

	if err := env.ServeJWTBundle(); err != nil {
		return fmt.Errorf("serve JWT bundle: %w", err)
	}

	result, err := env.ProbeJWT(jwtMaterial.Token)
	if err != nil {
		return fmt.Errorf("probe JWT endpoint: %w", err)
	}

	if result.Status == "valid" {
		return fmt.Errorf("J12: SDK accepted JWT with invalid 'typ' header")
	}
	return nil
}

func runJ13(ctx context.Context, env *suite.TestEnv) error {
	spiffeID := "spiffe://test.example.org/workload"

	// Step 1: issue JWT1 with the original CA (key1) and verify it validates.
	jwt1, err := env.IssueJWT(spiffeID, ca.WithJWTAudience(ValidAudience))
	if err != nil {
		return fmt.Errorf("issue JWT1: %w", err)
	}
	if err := env.ServeJWTBundle(); err != nil {
		return fmt.Errorf("serve initial JWKS: %w", err)
	}

	r1, err := env.ProbeJWT(jwt1.Token)
	if err != nil {
		return fmt.Errorf("initial probe: %w", err)
	}
	if r1.Status != "valid" {
		return fmt.Errorf("J13: JWT1 should be valid before rotation, got status %q", r1.Status)
	}

	// Step 2: rotate to a new CA (key2).
	ca2, err := ca.New("spiffe://test.example.org")
	if err != nil {
		return fmt.Errorf("create ca2: %w", err)
	}
	jwks2, err := ca2.JWKSBytes()
	if err != nil {
		return fmt.Errorf("get ca2 JWKS: %w", err)
	}
	u, _ := url.Parse("spiffe://test.example.org")
	env.SetJWTState(&workloadapi.JWTState{
		JWKSBundle: map[string][]byte{u.Host: jwks2},
	})

	// Step 3: issue JWT2 with ca2 and poll until SDK accepts it (bundle rotated).
	jwt2, err := ca2.IssueJWT(spiffeID, ca.WithJWTAudience(ValidAudience))
	if err != nil {
		return fmt.Errorf("issue JWT2: %w", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		r2, err := env.ProbeJWT(jwt2.Token)
		if err == nil && r2.Status == "valid" {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("J13: SDK did not pick up rotated JWKS within 5s")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}

	// Step 4: JWT1 (signed by the old key) must now be rejected.
	r3, err := env.ProbeJWT(jwt1.Token)
	if err != nil {
		return fmt.Errorf("probe JWT1 after rotation: %w", err)
	}
	if r3.Status == "valid" {
		return fmt.Errorf("J13: SDK accepted JWT1 (old key) after JWKS rotation")
	}

	return nil
}
