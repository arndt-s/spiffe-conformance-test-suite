// Package x509 registers the X.509 SVID test cases.
package x509

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/url"
	"time"

	"github.com/arndt-s/spiffe-conformance-test-suite/internal/ca"
	"github.com/arndt-s/spiffe-conformance-test-suite/internal/workloadapi"
	"github.com/arndt-s/spiffe-conformance-test-suite/suite"
)

func init() {
	suite.Register(suite.TestCase{
		Name:        "X6",
		Description: "SDK rejects, via Workload API, an X.509 SVID where the leaf certificate has IsCA set",
		Run:         runX6,
	})
	suite.Register(suite.TestCase{
		Name:        "X7",
		Description: "SDK rejects, via Workload API, an X.509 SVID where the leaf has keyCertSign key usage",
		Run:         runX7,
	})
	suite.Register(suite.TestCase{
		Name:        "X8",
		Description: "SDK rejects, via Workload API, an X.509 SVID with more than one URI SAN",
		Run:         runX8,
	})
	suite.Register(suite.TestCase{
		Name:        "X9",
		Description: "SDK rejects, via Workload API, an X.509 SVID whose URI SAN is not a spiffe:// URI",
		Run:         runX9,
	})
}

func runX6(ctx context.Context, env *suite.TestEnv) error {
	valid, err := env.IssueX509SVID("spiffe://test.example.org/x6-valid")
	if err != nil {
		return fmt.Errorf("issue valid SVID: %w", err)
	}
	env.ServeX509(valid)

	if _, err := probeUntilSPIFFEID(ctx, env, "spiffe://test.example.org/x6-valid", 5*time.Second); err != nil {
		return fmt.Errorf("waiting for x6-valid: %w", err)
	}

	caSVID, err := env.IssueX509SVID("spiffe://test.example.org/x6-ca", ca.WithX509IsCA())
	if err != nil {
		return fmt.Errorf("issue CA SVID: %w", err)
	}
	env.PushX509Update(caSVID)

	time.Sleep(300 * time.Millisecond)

	result, err := env.ProbeX509()
	if err != nil {
		return fmt.Errorf("probe after CA cert push: %w", err)
	}
	return suite.AssertX509SPIFFEID(result, "spiffe://test.example.org/x6-valid")
}

func runX7(ctx context.Context, env *suite.TestEnv) error {
	valid, err := env.IssueX509SVID("spiffe://test.example.org/x7-valid")
	if err != nil {
		return fmt.Errorf("issue valid SVID: %w", err)
	}
	env.ServeX509(valid)

	if _, err := probeUntilSPIFFEID(ctx, env, "spiffe://test.example.org/x7-valid", 5*time.Second); err != nil {
		return fmt.Errorf("waiting for x7-valid: %w", err)
	}

	certSignSVID, err := env.IssueX509SVID("spiffe://test.example.org/x7-certsign",
		ca.WithX509KeyUsage(x509.KeyUsageCertSign|x509.KeyUsageDigitalSignature),
	)
	if err != nil {
		return fmt.Errorf("issue keyCertSign SVID: %w", err)
	}
	env.PushX509Update(certSignSVID)

	time.Sleep(300 * time.Millisecond)

	result, err := env.ProbeX509()
	if err != nil {
		return fmt.Errorf("probe after keyCertSign push: %w", err)
	}
	return suite.AssertX509SPIFFEID(result, "spiffe://test.example.org/x7-valid")
}

func runX8(ctx context.Context, env *suite.TestEnv) error {
	valid, err := env.IssueX509SVID("spiffe://test.example.org/x8-valid")
	if err != nil {
		return fmt.Errorf("issue valid SVID: %w", err)
	}
	env.ServeX509(valid)

	if _, err := probeUntilSPIFFEID(ctx, env, "spiffe://test.example.org/x8-valid", 5*time.Second); err != nil {
		return fmt.Errorf("waiting for x8-valid: %w", err)
	}

	extraURI, _ := url.Parse("spiffe://test.example.org/x8-extra")
	twoURISVID, err := env.IssueX509SVID("spiffe://test.example.org/x8-two-uris",
		ca.WithX509ExtraURIs(extraURI),
	)
	if err != nil {
		return fmt.Errorf("issue two-URI SVID: %w", err)
	}
	env.PushX509Update(twoURISVID)

	time.Sleep(300 * time.Millisecond)

	result, err := env.ProbeX509()
	if err != nil {
		return fmt.Errorf("probe after two-URI push: %w", err)
	}
	return suite.AssertX509SPIFFEID(result, "spiffe://test.example.org/x8-valid")
}

func runX9(ctx context.Context, env *suite.TestEnv) error {
	valid, err := env.IssueX509SVID("spiffe://test.example.org/x9-valid")
	if err != nil {
		return fmt.Errorf("issue valid SVID: %w", err)
	}
	env.ServeX509(valid)

	if _, err := probeUntilSPIFFEID(ctx, env, "spiffe://test.example.org/x9-valid", 5*time.Second); err != nil {
		return fmt.Errorf("waiting for x9-valid: %w", err)
	}

	httpsURI, _ := url.Parse("https://not-a-spiffe-uri.example.org/workload")
	nonSpiffeSVID, err := env.IssueX509SVID("spiffe://test.example.org/x9-https",
		ca.WithX509URIOverride(httpsURI),
	)
	if err != nil {
		return fmt.Errorf("issue non-spiffe URI SVID: %w", err)
	}
	// Push using raw state so the fake SPIFFE ID in the material does not confuse
	// the server; we want the cert's URI SAN (https://) to be the reject trigger.
	env.SetX509State(&workloadapi.X509State{
		Materials:   []*ca.X509SVIDMaterial{nonSpiffeSVID},
		TrustBundle: [][]byte{env.CA().CACertDER()},
	})

	time.Sleep(300 * time.Millisecond)

	result, err := env.ProbeX509()
	if err != nil {
		return fmt.Errorf("probe after non-spiffe URI push: %w", err)
	}
	return suite.AssertX509SPIFFEID(result, "spiffe://test.example.org/x9-valid")
}
