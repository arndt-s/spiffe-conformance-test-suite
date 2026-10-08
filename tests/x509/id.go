package x509

import (
	"context"
	stdx509 "crypto/x509"
	"fmt"

	"github.com/arndt-s/spiffe-conformance-test-suite/internal/ca"
	"github.com/arndt-s/spiffe-conformance-test-suite/suite"
)

// idX509Cases are the SPIFFE ID parsing cases (catalogue §7, ID-1) that are
// also run as X.509 URI SANs, in the server role.
var idX509Cases = []struct{ variant, uri string }{
	{"x509-query", suite.TrustDomain + "/a?x=1"},
	{"x509-percent-encoded", suite.TrustDomain + "/%41"},
	{"x509-trailing-slash", suite.TrustDomain + "/a/"},
	{"x509-port", "spiffe://test.example.org:8080/a"},
}

func init() {
	for _, c := range idX509Cases {
		uri := c.uri
		suite.Register(suite.TestCase{
			ID:          "ID-1/" + c.variant,
			Description: "Rejects invalid SPIFFE IDs",
			Level:       suite.MUST,
			Feature:     suite.X509Server,
			Ref:         "ID §2",
			Run: func(_ context.Context, env *suite.TestEnv) error {
				return runIDX509(env, uri)
			},
		})
	}
}

func runIDX509(env *suite.TestEnv, uri string) error {
	peer, err := env.IssueX509SVID(uri, ca.WithX509URIOverride(mustURL(uri)))
	if err != nil {
		return suite.ExecErrorf("issue peer certificate: %w", err)
	}
	if err := checkURISAN(peer.CertDER, uri); err != nil {
		return suite.ExecErrorf("fixture: %w", err)
	}
	if err := serverRole.positiveControl(env, suite.TrustDomain+"/control"); err != nil {
		return err
	}
	return serverRole.expectRejected(env, peer, "a peer with the invalid SPIFFE ID "+uri)
}

// checkURISAN makes sure the encoded certificate carries exactly uri as its
// only URI SAN, so the SDK sees the intended string and not a normalised one.
func checkURISAN(der []byte, uri string) error {
	cert, err := stdx509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("parse issued certificate: %w", err)
	}
	if len(cert.URIs) != 1 || cert.URIs[0].String() != uri {
		var got []string
		for _, u := range cert.URIs {
			got = append(got, u.String())
		}
		return fmt.Errorf("issued certificate carries URI SANs %q, want [%q]", got, uri)
	}
	return nil
}
