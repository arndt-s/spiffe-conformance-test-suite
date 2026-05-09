// Package x509 registers the X.509 SVID test cases.
package x509

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/url"
	"time"

	"github.com/arndt-s/spiffe-conformance-test-suite/internal/ca"
	"github.com/arndt-s/spiffe-conformance-test-suite/internal/harnessctl"
	"github.com/arndt-s/spiffe-conformance-test-suite/suite"
)

func init() {
	suite.Register(suite.TestCase{
		Name:        "X10",
		Description: "SDK rejects a peer presenting an X.509 client certificate with IsCA set",
		Run:         runX10,
	})
	suite.Register(suite.TestCase{
		Name:        "X11",
		Description: "SDK rejects a peer presenting an X.509 client certificate with keyCertSign key usage",
		Run:         runX11,
	})
	suite.Register(suite.TestCase{
		Name:        "X12",
		Description: "SDK rejects a peer presenting an X.509 client certificate with more than one URI SAN",
		Run:         runX12,
	})
	suite.Register(suite.TestCase{
		Name:        "X13",
		Description: "SDK rejects a peer presenting an X.509 client certificate with a non-spiffe:// URI SAN",
		Run:         runX13,
	})
}

func runX10(ctx context.Context, env *suite.TestEnv) error {
	if err := env.RequireCapability(harnessctl.CapMTLSVerify); err != nil {
		return err
	}
	// Wait for the SDK to be serving a valid SVID first.
	if _, err := probeUntilSPIFFEID(ctx, env, "spiffe://test.example.org/default", 5*time.Second); err != nil {
		return fmt.Errorf("waiting for SDK ready: %w", err)
	}

	badCert, err := env.IssueX509SVID("spiffe://test.example.org/x10-probe", ca.WithX509IsCA())
	if err != nil {
		return fmt.Errorf("issue IsCA cert: %w", err)
	}
	_, err = env.ProbeX509WithCert(badCert)
	if err == nil {
		return fmt.Errorf("X10: SDK accepted mTLS client cert with IsCA=true")
	}
	return nil // connection was rejected — correct behaviour
}

func runX11(ctx context.Context, env *suite.TestEnv) error {
	if _, err := probeUntilSPIFFEID(ctx, env, "spiffe://test.example.org/default", 5*time.Second); err != nil {
		return fmt.Errorf("waiting for SDK ready: %w", err)
	}

	badCert, err := env.IssueX509SVID("spiffe://test.example.org/x11-probe",
		ca.WithX509KeyUsage(x509.KeyUsageCertSign|x509.KeyUsageDigitalSignature),
	)
	if err != nil {
		return fmt.Errorf("issue keyCertSign cert: %w", err)
	}
	_, err = env.ProbeX509WithCert(badCert)
	if err == nil {
		return fmt.Errorf("X11: SDK accepted mTLS client cert with keyCertSign key usage")
	}
	return nil
}

func runX12(ctx context.Context, env *suite.TestEnv) error {
	if _, err := probeUntilSPIFFEID(ctx, env, "spiffe://test.example.org/default", 5*time.Second); err != nil {
		return fmt.Errorf("waiting for SDK ready: %w", err)
	}

	extraURI, _ := url.Parse("spiffe://test.example.org/x12-extra")
	badCert, err := env.IssueX509SVID("spiffe://test.example.org/x12-probe",
		ca.WithX509ExtraURIs(extraURI),
	)
	if err != nil {
		return fmt.Errorf("issue two-URI cert: %w", err)
	}
	_, err = env.ProbeX509WithCert(badCert)
	if err == nil {
		return fmt.Errorf("X12: SDK accepted mTLS client cert with more than one URI SAN")
	}
	return nil
}

func runX13(ctx context.Context, env *suite.TestEnv) error {
	if _, err := probeUntilSPIFFEID(ctx, env, "spiffe://test.example.org/default", 5*time.Second); err != nil {
		return fmt.Errorf("waiting for SDK ready: %w", err)
	}

	httpsURI, _ := url.Parse("https://not-a-spiffe-uri.example.org/workload")
	badCert, err := env.IssueX509SVID("spiffe://test.example.org/x13-probe",
		ca.WithX509URIOverride(httpsURI),
	)
	if err != nil {
		return fmt.Errorf("issue non-spiffe URI cert: %w", err)
	}
	_, err = env.ProbeX509WithCert(badCert)
	if err == nil {
		return fmt.Errorf("X13: SDK accepted mTLS client cert with non-spiffe:// URI SAN")
	}
	return nil
}
