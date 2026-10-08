package ca

import (
	"crypto/x509"
	"encoding/json"
	"testing"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
)

const td = "spiffe://test.example.org"

func TestJWKSKeysCarryUseAndKid(t *testing.T) {
	c, err := New(td)
	if err != nil {
		t.Fatal(err)
	}
	other, err := New(td)
	if err != nil {
		t.Fatal(err)
	}
	if c.JWTKeys()[0].ID == other.JWTKeys()[0].ID {
		t.Fatalf("two CAs share key ID %q", c.JWTKeys()[0].ID)
	}

	raw, err := c.JWKSBytes()
	if err != nil {
		t.Fatal(err)
	}
	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(raw, &set); err != nil {
		t.Fatal(err)
	}
	if len(set.Keys) != 1 {
		t.Fatalf("got %d keys, want 1", len(set.Keys))
	}
	if got := set.Keys[0]["use"]; got != JWTUse {
		t.Errorf("use = %v, want %q", got, JWTUse)
	}
	if got := set.Keys[0]["kid"]; got != c.JWTKeys()[0].ID {
		t.Errorf("kid = %v, want %q", got, c.JWTKeys()[0].ID)
	}
}

func TestIssueJWTWithEveryAllowedAlgorithm(t *testing.T) {
	c, err := New(td)
	if err != nil {
		t.Fatal(err)
	}
	algs := []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"}
	keys := map[string]*JWTKey{}
	for _, alg := range algs {
		k, err := c.AddJWTKey(alg)
		if err != nil {
			t.Fatalf("AddJWTKey(%s): %v", alg, err)
		}
		keys[alg] = k
	}

	jwks, err := c.JWKSBytes()
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := jwtbundle.Parse(spiffeid.RequireTrustDomainFromString(td), jwks)
	if err != nil {
		t.Fatalf("go-spiffe cannot parse JWKS: %v", err)
	}

	for _, alg := range algs {
		t.Run(alg, func(t *testing.T) {
			m, err := c.IssueJWT(td+"/workload", WithJWTKey(keys[alg]), WithJWTAudience("conformance"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := jwtsvid.ParseAndValidate(m.Token, bundle, []string{"conformance"}); err != nil {
				t.Fatalf("go-spiffe rejected %s token: %v", alg, err)
			}
		})
	}
}

func TestEdDSAKeyIsPublished(t *testing.T) {
	c, err := New(td)
	if err != nil {
		t.Fatal(err)
	}
	k, err := c.AddJWTKey("EdDSA")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.IssueJWT(td+"/workload", WithJWTKey(k)); err != nil {
		t.Fatal(err)
	}
	jwks, err := c.JWKSBytes()
	if err != nil {
		t.Fatal(err)
	}
	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(jwks, &set); err != nil {
		t.Fatal(err)
	}
	if len(set.Keys) != 2 || set.Keys[1]["kty"] != "OKP" {
		t.Fatalf("expected an OKP key second in the bundle, got %v", set.Keys)
	}
}

func TestIntermediateChainVerifiesAgainstRoot(t *testing.T) {
	root, err := New(td)
	if err != nil {
		t.Fatal(err)
	}
	inter, err := root.NewIntermediate()
	if err != nil {
		t.Fatal(err)
	}
	m, err := inter.IssueX509SVID(td + "/workload")
	if err != nil {
		t.Fatal(err)
	}
	if got := len(m.CertChainDER()); got != 2 {
		t.Fatalf("chain length = %d, want 2 (leaf + intermediate)", got)
	}
	if string(m.CACertDER) != string(root.CACertDER()) {
		t.Fatal("material's CA cert is not the root")
	}

	intermediates := x509.NewCertPool()
	for _, der := range m.Intermediates {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		intermediates.AddCert(cert)
	}
	if _, err := m.Cert.Verify(x509.VerifyOptions{
		Roots:         root.CACertPool(),
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		t.Fatalf("leaf does not verify through intermediate: %v", err)
	}
}

func TestCACertCarriesTrustDomainURI(t *testing.T) {
	c, err := New(td)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(c.CACertDER())
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.URIs) != 1 || cert.URIs[0].String() != td {
		t.Fatalf("CA URIs = %v, want [%s]", cert.URIs, td)
	}
}
