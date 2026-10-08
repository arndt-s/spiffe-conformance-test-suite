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

func TestLeafCarriesBasicConstraintsWithCAFalse(t *testing.T) {
	c, err := New(td)
	if err != nil {
		t.Fatal(err)
	}
	m, err := c.IssueX509SVID(td + "/workload")
	if err != nil {
		t.Fatal(err)
	}
	if !m.Cert.BasicConstraintsValid || m.Cert.IsCA {
		t.Fatalf("BasicConstraintsValid=%v IsCA=%v, want true/false", m.Cert.BasicConstraintsValid, m.Cert.IsCA)
	}
	if m.Cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Fatal("leaf lacks digitalSignature")
	}
}

func TestSignRawJWTValidatesWithGoSpiffeAndSupportsOverrides(t *testing.T) {
	c, err := New(td)
	if err != nil {
		t.Fatal(err)
	}
	key := c.JWTKeys()[0]
	jwks, err := c.JWKSBytes()
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := jwtbundle.Parse(spiffeid.RequireTrustDomainFromString(td), jwks)
	if err != nil {
		t.Fatal(err)
	}

	tok, err := SignRawJWT(key, nil, ValidJWTClaims(td+"/w", "conformance"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := jwtsvid.ParseAndValidate(tok, bundle, []string{"conformance"}); err != nil {
		t.Fatalf("valid raw token rejected: %v", err)
	}

	mismatch, err := SignRawJWT(key, map[string]any{"alg": "RS256"}, ValidJWTClaims(td+"/w", "conformance"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := jwtsvid.ParseAndValidate(mismatch, bundle, []string{"conformance"}); err == nil {
		t.Fatal("alg-mismatch token accepted")
	}
}

func TestBuildJWKSWithExtraAndEmpty(t *testing.T) {
	empty, err := BuildJWKS(nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(empty) != `{"keys":[]}` {
		t.Fatalf("empty JWKS = %s", empty)
	}
	withExtra, err := BuildJWKS(nil, json.RawMessage(`{"kty":"XYZ","kid":"x","use":"jwt-svid"}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(withExtra) != `{"keys":[{"kty":"XYZ","kid":"x","use":"jwt-svid"}]}` {
		t.Fatalf("JWKS = %s", withExtra)
	}
}

func TestX509OptionsEmptySubjectAndNoURI(t *testing.T) {
	c, err := New(td)
	if err != nil {
		t.Fatal(err)
	}
	m, err := c.IssueX509SVID(td+"/w", WithX509EmptySubject())
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Cert.Subject.Names) != 0 || len(m.Cert.URIs) != 1 {
		t.Fatalf("subject=%v uris=%v", m.Cert.Subject, m.Cert.URIs)
	}
	noURI, err := c.IssueX509SVID(td+"/w", WithX509URIOverride())
	if err != nil {
		t.Fatal(err)
	}
	if len(noURI.Cert.URIs) != 0 {
		t.Fatalf("URIs = %v, want none", noURI.Cert.URIs)
	}
}
