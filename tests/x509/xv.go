package x509

import (
	"context"
	stdx509 "crypto/x509"
	"net/url"
	"time"

	"github.com/arndt-s/spiffe-conformance-test-suite/internal/ca"
	"github.com/arndt-s/spiffe-conformance-test-suite/suite"
)

// xvCase is one peer-validation case (catalogue §5.2), run in every role.
type xvCase struct {
	id     string
	desc   string
	ref    string
	accept bool
	// what describes the peer in failure messages.
	what string
	// peer builds the peer certificate the SDK is asked to validate.
	peer func(env *suite.TestEnv) (*ca.X509SVIDMaterial, error)
}

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

// fromSuiteCA issues id from the suite CA with opts.
func fromSuiteCA(id string, opts ...ca.X509SVIDOption) func(*suite.TestEnv) (*ca.X509SVIDMaterial, error) {
	return func(env *suite.TestEnv) (*ca.X509SVIDMaterial, error) {
		return env.IssueX509SVID(id, opts...)
	}
}

var xvCases = []xvCase{
	{
		id: "XV-1", desc: "Accepts a valid peer SVID (positive control)", ref: "XS §5.1", accept: true,
		what: "a plain leaf from the trust domain CA",
		peer: fromSuiteCA(suite.TrustDomain + "/xv-1"),
	},
	{
		id: "XV-2", desc: "Accepts a peer SVID chained through an intermediate", ref: "XS §5.1", accept: true,
		what: "a leaf issued by an intermediate CA (leaf + intermediate presented)",
		peer: func(env *suite.TestEnv) (*ca.X509SVIDMaterial, error) {
			inter, err := env.CA().NewIntermediate()
			if err != nil {
				return nil, err
			}
			return inter.IssueX509SVID(suite.TrustDomain + "/xv-2")
		},
	},
	{
		id: "XV-3", desc: "Accepts a peer SVID that also carries DNS SANs", ref: "XS §2", accept: true,
		what: "a leaf with an additional DNS SAN",
		peer: fromSuiteCA(suite.TrustDomain+"/xv-3", ca.WithX509DNSNames("xv-3.test.example.org")),
	},
	{
		id: "XV-4", desc: "Accepts a peer SVID with an empty Subject and a critical URI SAN", ref: "XS §3.1", accept: true,
		what: "a leaf with an empty Subject and a critical SAN extension",
		peer: fromSuiteCA(suite.TrustDomain+"/xv-4", ca.WithX509EmptySubject()),
	},
	{
		id: "XV-5", desc: "Rejects a peer chaining to an untrusted CA", ref: "XS §5.1",
		what: "a leaf from a different CA for the same trust domain name",
		peer: func(*suite.TestEnv) (*ca.X509SVIDMaterial, error) {
			other, err := ca.New(suite.TrustDomain)
			if err != nil {
				return nil, err
			}
			return other.IssueX509SVID(suite.TrustDomain + "/xv-5")
		},
	},
	{
		id: "XV-6", desc: "Rejects an expired peer certificate", ref: "XS §5.1 (RFC 5280)",
		what: "a leaf that expired an hour ago",
		peer: func(env *suite.TestEnv) (*ca.X509SVIDMaterial, error) {
			return env.IssueX509SVID(suite.TrustDomain+"/xv-6",
				ca.WithX509NotBefore(time.Now().Add(-2*time.Hour)), ca.WithX509TTL(time.Hour))
		},
	},
	{
		id: "XV-7", desc: "Rejects a not-yet-valid peer certificate", ref: "XS §5.1 (RFC 5280)",
		what: "a leaf that becomes valid in an hour",
		peer: func(env *suite.TestEnv) (*ca.X509SVIDMaterial, error) {
			return env.IssueX509SVID(suite.TrustDomain+"/xv-7",
				ca.WithX509NotBefore(time.Now().Add(time.Hour)), ca.WithX509TTL(time.Hour))
		},
	},
	{
		id: "XV-8", desc: "Rejects a peer leaf with cA=true", ref: "XS §5.2",
		what: "a leaf with basic constraints cA=true",
		peer: fromSuiteCA(suite.TrustDomain+"/xv-8", ca.WithX509IsCA()),
	},
	{
		id: "XV-9", desc: "Rejects a peer leaf with keyCertSign", ref: "XS §5.2",
		what: "a leaf with key usage keyCertSign",
		peer: fromSuiteCA(suite.TrustDomain+"/xv-9",
			ca.WithX509KeyUsage(stdx509.KeyUsageDigitalSignature|stdx509.KeyUsageCertSign)),
	},
	{
		id: "XV-10", desc: "Rejects a peer leaf with cRLSign", ref: "XS §5.2",
		what: "a leaf with key usage cRLSign",
		peer: fromSuiteCA(suite.TrustDomain+"/xv-10",
			ca.WithX509KeyUsage(stdx509.KeyUsageDigitalSignature|stdx509.KeyUsageCRLSign)),
	},
	{
		id: "XV-11", desc: "Rejects a peer with more than one URI SAN", ref: "XS §2, §5.2",
		what: "a leaf with two spiffe:// URI SANs",
		peer: fromSuiteCA(suite.TrustDomain+"/xv-11",
			ca.WithX509ExtraURIs(mustURL(suite.TrustDomain+"/xv-11-second"))),
	},
	{
		id: "XV-12", desc: "Rejects a peer without a URI SAN", ref: "XS §2",
		what: "a leaf without any URI SAN",
		peer: fromSuiteCA(suite.TrustDomain+"/xv-12", ca.WithX509URIOverride()),
	},
	{
		id: "XV-13", desc: "Rejects a peer URI SAN that is not spiffe://", ref: "XS §5.2",
		what: "a leaf whose only URI SAN is https://test.example.org/xv-13",
		peer: fromSuiteCA(suite.TrustDomain+"/xv-13",
			ca.WithX509URIOverride(mustURL("https://test.example.org/xv-13"))),
	},
	{
		id: "XV-14", desc: "Rejects a peer SPIFFE ID without a path (spiffe://td)", ref: "XS §3.1, §5.2",
		what: "a leaf whose URI SAN is the bare trust domain " + suite.TrustDomain,
		peer: fromSuiteCA(suite.TrustDomain),
	},
	{
		id:   "XV-15",
		desc: "Rejects a peer whose trust domain has no bundle, even if its chain verifies against another trust domain's CA",
		ref:  "WA §4.6, FD §7.3",
		what: "a leaf spiffe://other.example.org/xv-15 signed by the local trust domain's CA",
		peer: fromSuiteCA("spiffe://other.example.org/xv-15"),
	},
}

func init() {
	for _, c := range xvCases {
		for _, r := range roles {
			suite.Register(suite.TestCase{
				ID:          c.id + "/" + r.name,
				Description: c.desc,
				Level:       suite.MUST,
				Feature:     r.feature,
				Ref:         c.ref,
				Run:         runInRole(r, c.run),
			})
		}
	}
}

func (c xvCase) run(_ context.Context, env *suite.TestEnv, r role) error {
	peer, err := c.peer(env)
	if err != nil {
		return suite.ExecErrorf("issue peer certificate: %w", err)
	}
	if c.accept {
		return r.expectAccepted(env, peer, c.what)
	}
	if err := r.positiveControl(env, suite.TrustDomain+"/control"); err != nil {
		return err
	}
	return r.expectRejected(env, peer, c.what)
}
