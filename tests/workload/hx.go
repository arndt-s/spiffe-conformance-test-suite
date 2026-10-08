package workload

import (
	"context"
	"crypto/x509"
	"net/url"
	"strings"
	"time"

	"github.com/arndt-s/spiffe-conformance-test-suite/internal/ca"
	"github.com/arndt-s/spiffe-conformance-test-suite/suite"
)

// hxCase describes one hardening test: bad builds the invalid SVID material
// the mock serves as the default identity.
type hxCase struct {
	id   string
	desc string
	bad  func(env *suite.TestEnv, id string) (*ca.X509SVIDMaterial, error)
}

var hxCases = []hxCase{
	{"HX-1", "with an invalid signature", func(env *suite.TestEnv, id string) (*ca.X509SVIDMaterial, error) {
		m, err := env.IssueX509SVID(id)
		if err != nil {
			return nil, err
		}
		bad := *m
		// The DER ends inside the signature value: flip its last bit.
		bad.CertDER = append([]byte(nil), m.CertDER...)
		bad.CertDER[len(bad.CertDER)-1] ^= 0x01
		return &bad, nil
	}},
	{"HX-2", "that does not chain to the bundle in the same response", func(env *suite.TestEnv, id string) (*ca.X509SVIDMaterial, error) {
		foreign, err := ca.New(suite.TrustDomain)
		if err != nil {
			return nil, err
		}
		// Let the suite's prober verify the foreign chain, so that a
		// presented foreign SVID is reported as such rather than as a
		// probe failure. The SDK still only gets the suite CA's bundle.
		env.TrustRoot(foreign)
		return foreign.IssueX509SVID(id)
	}},
	{"HX-3", "that is expired", func(env *suite.TestEnv, id string) (*ca.X509SVIDMaterial, error) {
		return env.IssueX509SVID(id, ca.WithX509NotBefore(time.Now().Add(-2*time.Hour)), ca.WithX509TTL(time.Hour))
	}},
	{"HX-4", "whose leaf has cA=true", func(env *suite.TestEnv, id string) (*ca.X509SVIDMaterial, error) {
		return env.IssueX509SVID(id, ca.WithX509IsCA())
	}},
	{"HX-5", "whose leaf has keyCertSign", func(env *suite.TestEnv, id string) (*ca.X509SVIDMaterial, error) {
		return env.IssueX509SVID(id, ca.WithX509KeyUsage(x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign))
	}},
	{"HX-6", "with more than one URI SAN", func(env *suite.TestEnv, id string) (*ca.X509SVIDMaterial, error) {
		second, _ := url.Parse(suite.TrustDomain + "/hx-6-second")
		return env.IssueX509SVID(id, ca.WithX509ExtraURIs(second))
	}},
	{"HX-7", "with a non-spiffe:// URI SAN", func(env *suite.TestEnv, id string) (*ca.X509SVIDMaterial, error) {
		u, _ := url.Parse("https://test.example.org/hx-7")
		return env.IssueX509SVID(id, ca.WithX509URIOverride(u))
	}},
	{"HX-8", "whose private key does not match the certificate", func(env *suite.TestEnv, id string) (*ca.X509SVIDMaterial, error) {
		m, err := env.IssueX509SVID(id)
		if err != nil {
			return nil, err
		}
		other, err := env.IssueX509SVID(id + "-other-key")
		if err != nil {
			return nil, err
		}
		bad := *m
		bad.Key = other.Key
		return &bad, nil
	}},
	{"HX-9", "whose spiffe_id field differs from the certificate's URI SAN", func(env *suite.TestEnv, id string) (*ca.X509SVIDMaterial, error) {
		m, err := env.IssueX509SVID(id)
		if err != nil {
			return nil, err
		}
		bad := *m
		bad.SPIFFEID = id + "-claimed"
		return &bad, nil
	}},
}

func init() {
	for _, c := range hxCases {
		c := c
		suite.Register(suite.TestCase{
			ID:          c.id,
			Description: "Ignores a Workload API X.509-SVID " + c.desc,
			Level:       suite.OPT,
			Feature:     suite.X509Server,
			Ref:         "catalogue §8 (hardening)",
			Run: func(ctx context.Context, env *suite.TestEnv) error {
				return runHX(ctx, env, c)
			},
		})
	}
}

// runHX serves valid SVID A, then the bad SVID, then valid barrier SVID B.
// The SDK must keep serving A until B arrives and never present the bad SVID.
func runHX(ctx context.Context, env *suite.TestEnv, c hxCase) error {
	idA := suite.TrustDomain + "/hx-a"
	idB := suite.TrustDomain + "/hx-b"
	idBad := suite.TrustDomain + "/" + strings.ToLower(c.id) + "-bad"

	a, err := env.IssueX509SVID(idA)
	if err != nil {
		return suite.ExecErrorf("issue SVID A: %w", err)
	}
	b, err := env.IssueX509SVID(idB)
	if err != nil {
		return suite.ExecErrorf("issue barrier SVID B: %w", err)
	}
	bad, err := c.bad(env, idBad)
	if err != nil {
		return suite.ExecErrorf("issue bad SVID: %w", err)
	}

	// Positive control: a valid SVID is accepted and served.
	env.ServeX509(a)
	if _, err := env.WaitForSVID(ctx, idA, suite.UpdateTimeout); err != nil {
		return err
	}

	env.ServeX509(bad)
	what := "an X.509-SVID " + c.desc
	if err := env.ObserveX509(ctx, observeWindow, servingCheck(what, bad.CertDER, idA)); err != nil {
		return err
	}
	env.ServeX509(b)
	return waitWhile(ctx, env, what, idB, barrierTimeout, servingCheck(what, bad.CertDER, idA))
}
