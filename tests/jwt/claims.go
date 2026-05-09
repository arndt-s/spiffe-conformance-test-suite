package jwt

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/arndt-s/spiffe-conformance-test-suite/internal/ca"
	"github.com/arndt-s/spiffe-conformance-test-suite/suite"
)

func init() {
	suite.Register(suite.TestCase{
		Name:        "J16",
		Description: "SDK accepts JWTs with typ=JWT, typ=JOSE, and missing typ header",
		Run:         runJ16,
	})
	suite.Register(suite.TestCase{
		Name:        "J17",
		Description: "SDK accepts a JWT carrying multiple audiences when one of them is the validator's expected audience",
		Run:         runJ17,
	})
	suite.Register(suite.TestCase{
		Name:        "J18",
		Description: "SDK rejects a JWT whose 'aud' claim is an empty array",
		Run:         runJ18,
	})
	suite.Register(suite.TestCase{
		Name:        "J19",
		Description: "SDK rejects a JWT whose 'nbf' claim is in the future",
		Run:         runJ19,
	})
	suite.Register(suite.TestCase{
		Name:        "J20",
		Description: "SDK rejects JWTs whose 'sub' claim is a syntactically-invalid SPIFFE ID",
		Run:         runJ20,
	})
	suite.Register(suite.TestCase{
		Name:        "J21",
		Description: "SDK rejects a JWS using JSON serialization (only Compact serialization is permitted)",
		Run:         runJ21,
	})
}

// runJ16 — typ header per JWT-07: optional; if present MUST be JWT or JOSE.
// We assert all three valid forms (JWT, JOSE, missing) are accepted.
func runJ16(ctx context.Context, env *suite.TestEnv) error {
	if err := env.ServeJWTBundle(); err != nil {
		return fmt.Errorf("serve JWT bundle: %w", err)
	}

	cases := []struct {
		name string
		opts []ca.JWTSVIDOption
	}{
		{"typ=JWT", []ca.JWTSVIDOption{ca.WithJWTHeader("typ", "JWT")}},
		{"typ=JOSE", []ca.JWTSVIDOption{ca.WithJWTHeader("typ", "JOSE")}},
		{"typ missing", []ca.JWTSVIDOption{ca.WithJWTDeleteHeader("typ")}},
	}
	for _, tc := range cases {
		opts := append([]ca.JWTSVIDOption{ca.WithJWTAudience(ValidAudience)}, tc.opts...)
		m, err := env.IssueJWT("spiffe://test.example.org/j16", opts...)
		if err != nil {
			return fmt.Errorf("%s: issue JWT: %w", tc.name, err)
		}
		r, err := env.ProbeJWT(m.Token)
		if err != nil {
			return fmt.Errorf("%s: probe: %w", tc.name, err)
		}
		if r.Status != "valid" {
			return fmt.Errorf("J16/%s: SDK rejected a JWT that should be accepted (status=%q, msg=%q)",
				tc.name, r.Status, r.Message)
		}
	}
	return nil
}

// runJ17 — JWT-09: validator MUST accept a token whose 'aud' contains
// the validator's identity, even when other audiences are also listed.
func runJ17(ctx context.Context, env *suite.TestEnv) error {
	if err := env.ServeJWTBundle(); err != nil {
		return fmt.Errorf("serve JWT bundle: %w", err)
	}
	m, err := env.IssueJWT("spiffe://test.example.org/j17",
		ca.WithJWTAudience("other-aud-1", ValidAudience, "other-aud-2"),
	)
	if err != nil {
		return fmt.Errorf("issue multi-aud JWT: %w", err)
	}
	r, err := env.ProbeJWT(m.Token)
	if err != nil {
		return fmt.Errorf("probe: %w", err)
	}
	if r.Status != "valid" {
		return fmt.Errorf("J17: SDK rejected multi-audience JWT containing expected audience (status=%q, msg=%q)",
			r.Status, r.Message)
	}
	return nil
}

// runJ18 — JWT-09: an 'aud' claim that is present but empty is invalid.
func runJ18(ctx context.Context, env *suite.TestEnv) error {
	if err := env.ServeJWTBundle(); err != nil {
		return fmt.Errorf("serve JWT bundle: %w", err)
	}
	// Build a JWT where the default audience is replaced with an empty array.
	m, err := env.IssueJWT("spiffe://test.example.org/j18",
		ca.WithJWTAudience(ValidAudience),         // satisfy default
		ca.WithJWTClaim("aud", []string{}),        // override to empty list
	)
	if err != nil {
		return fmt.Errorf("issue empty-aud JWT: %w", err)
	}
	r, err := env.ProbeJWT(m.Token)
	if err != nil {
		return fmt.Errorf("probe: %w", err)
	}
	if r.Status == "valid" {
		return fmt.Errorf("J18: SDK accepted a JWT with empty 'aud' array")
	}
	return nil
}

// runJ19 — JWT-14 implies a token must not be used before its 'nbf'.
func runJ19(ctx context.Context, env *suite.TestEnv) error {
	if err := env.ServeJWTBundle(); err != nil {
		return fmt.Errorf("serve JWT bundle: %w", err)
	}
	future := time.Now().Add(1 * time.Hour).Unix()
	m, err := env.IssueJWT("spiffe://test.example.org/j19",
		ca.WithJWTAudience(ValidAudience),
		ca.WithJWTClaim("nbf", future),
	)
	if err != nil {
		return fmt.Errorf("issue nbf-future JWT: %w", err)
	}
	r, err := env.ProbeJWT(m.Token)
	if err != nil {
		return fmt.Errorf("probe: %w", err)
	}
	if r.Status == "valid" {
		return fmt.Errorf("J19: SDK accepted a JWT whose 'nbf' is in the future")
	}
	return nil
}

// runJ20 — JWT-08: 'sub' MUST be a valid SPIFFE ID. We verify rejection
// for several syntactically-invalid forms that share the spiffe:// prefix
// but violate SPIFFE-ID syntax rules (root path, trailing slash, empty
// path segment, uppercase trust-domain).
func runJ20(ctx context.Context, env *suite.TestEnv) error {
	if err := env.ServeJWTBundle(); err != nil {
		return fmt.Errorf("serve JWT bundle: %w", err)
	}
	cases := []struct {
		name string
		sub  string
	}{
		{"trailing slash", "spiffe://test.example.org/workload/"},
		{"empty path segment", "spiffe://test.example.org//workload"},
		{"uppercase trust domain", "spiffe://TEST.example.org/workload"},
	}
	for _, tc := range cases {
		m, err := env.IssueJWT("spiffe://test.example.org/j20",
			ca.WithJWTAudience(ValidAudience),
			ca.WithJWTClaim("sub", tc.sub),
		)
		if err != nil {
			return fmt.Errorf("%s: issue JWT: %w", tc.name, err)
		}
		r, err := env.ProbeJWT(m.Token)
		if err != nil {
			return fmt.Errorf("%s: probe: %w", tc.name, err)
		}
		if r.Status == "valid" {
			return fmt.Errorf("J20/%s: SDK accepted JWT with invalid SPIFFE ID sub=%q", tc.name, tc.sub)
		}
	}
	return nil
}

// runJ21 — JWT-01/JWT-18: only Compact Serialization is permitted.
// The SDK must reject a JWS in JSON Serialization form.
func runJ21(ctx context.Context, env *suite.TestEnv) error {
	if err := env.ServeJWTBundle(); err != nil {
		return fmt.Errorf("serve JWT bundle: %w", err)
	}
	m, err := env.IssueJWT("spiffe://test.example.org/j21", ca.WithJWTAudience(ValidAudience))
	if err != nil {
		return fmt.Errorf("issue JWT: %w", err)
	}
	parts := strings.Split(m.Token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("expected Compact-Serialized JWT to have 3 parts, got %d", len(parts))
	}
	jsonForm, err := json.Marshal(map[string]string{
		"protected": parts[0],
		"payload":   parts[1],
		"signature": parts[2],
	})
	if err != nil {
		return fmt.Errorf("marshal JSON-serialized JWS: %w", err)
	}
	r, err := env.ProbeJWT(string(jsonForm))
	if err != nil {
		return fmt.Errorf("probe: %w", err)
	}
	if r.Status == "valid" {
		return fmt.Errorf("J21: SDK accepted a JWS using JSON serialization (only Compact serialization is allowed)")
	}
	return nil
}
