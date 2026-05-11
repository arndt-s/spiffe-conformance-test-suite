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
		Name:        "X14",
		Description: "SDK rejects a peer presenting an X.509 client certificate whose SPIFFE ID has no path component",
		Run:         runX14,
	})
	suite.Register(suite.TestCase{
		Name:        "X15",
		Description: "SDK rejects a peer presenting an X.509 client certificate without a Key Usage extension",
		Run:         runX15,
	})
	suite.Register(suite.TestCase{
		Name:        "X16",
		Description: "SDK rejects a peer presenting an X.509 client certificate without the digitalSignature key usage",
		Run:         runX16,
	})
	suite.Register(suite.TestCase{
		Name:        "X17",
		Description: "SDK rejects a peer presenting an X.509 client certificate with cRLSign in key usage",
		Run:         runX17,
	})
	suite.Register(suite.TestCase{
		Name:        "X18",
		Description: "SDK rejects a peer presenting an X.509 client certificate whose Extended Key Usage omits both serverAuth and clientAuth",
		Run:         runX18,
	})
	suite.Register(suite.TestCase{
		Name:        "X19",
		Description: "SDK rejects a peer presenting an X.509 client certificate with no URI SAN",
		Run:         runX19,
	})
}

// runX14 — leaf SPIFFE ID without a path component (root path) is invalid
// per X509-04 / X509-22.
func runX14(ctx context.Context, env *suite.TestEnv) error {
	if err := env.RequireCapability(harnessctl.CapMTLSVerify); err != nil {
		return err
	}
	if _, err := probeUntilSPIFFEID(ctx, env, "spiffe://test.example.org/default", 5*time.Second); err != nil {
		return fmt.Errorf("waiting for SDK ready: %w", err)
	}
	rootOnly, _ := url.Parse("spiffe://test.example.org")
	badCert, err := env.IssueX509SVID("spiffe://test.example.org/x14-probe",
		ca.WithX509URIOverride(rootOnly),
	)
	if err != nil {
		return fmt.Errorf("issue root-path cert: %w", err)
	}
	if _, err := env.ProbeX509WithCert(badCert); err == nil {
		return fmt.Errorf("X14: SDK accepted client cert whose SPIFFE ID has no path component")
	}
	return nil
}

// runX15 — Key Usage extension absent is a violation of X509-12.
func runX15(ctx context.Context, env *suite.TestEnv) error {
	if err := env.RequireCapability(harnessctl.CapMTLSVerify); err != nil {
		return err
	}
	if _, err := probeUntilSPIFFEID(ctx, env, "spiffe://test.example.org/default", 5*time.Second); err != nil {
		return fmt.Errorf("waiting for SDK ready: %w", err)
	}
	badCert, err := env.IssueX509SVID("spiffe://test.example.org/x15-probe",
		ca.WithX509KeyUsage(0), // KeyUsage == 0 → x509 omits the extension entirely
	)
	if err != nil {
		return fmt.Errorf("issue cert without KU: %w", err)
	}
	if _, err := env.ProbeX509WithCert(badCert); err == nil {
		return fmt.Errorf("X15: SDK accepted client cert without a Key Usage extension")
	}
	return nil
}

// runX16 — leaf must have digitalSignature (X509-14). A cert with only
// keyAgreement is missing the required flag.
func runX16(ctx context.Context, env *suite.TestEnv) error {
	if err := env.RequireCapability(harnessctl.CapMTLSVerify); err != nil {
		return err
	}
	if _, err := probeUntilSPIFFEID(ctx, env, "spiffe://test.example.org/default", 5*time.Second); err != nil {
		return fmt.Errorf("waiting for SDK ready: %w", err)
	}
	badCert, err := env.IssueX509SVID("spiffe://test.example.org/x16-probe",
		ca.WithX509KeyUsage(x509.KeyUsageKeyAgreement),
	)
	if err != nil {
		return fmt.Errorf("issue cert without digitalSignature: %w", err)
	}
	if _, err := env.ProbeX509WithCert(badCert); err == nil {
		return fmt.Errorf("X16: SDK accepted client cert without digitalSignature key usage")
	}
	return nil
}

// runX17 — leaf MUST NOT set cRLSign (X509-15). Tested separately from
// keyCertSign (X11) because some SDKs may check the two flags independently.
func runX17(ctx context.Context, env *suite.TestEnv) error {
	if err := env.RequireCapability(harnessctl.CapMTLSVerify); err != nil {
		return err
	}
	if _, err := probeUntilSPIFFEID(ctx, env, "spiffe://test.example.org/default", 5*time.Second); err != nil {
		return fmt.Errorf("waiting for SDK ready: %w", err)
	}
	badCert, err := env.IssueX509SVID("spiffe://test.example.org/x17-probe",
		ca.WithX509KeyUsage(x509.KeyUsageDigitalSignature|x509.KeyUsageCRLSign),
	)
	if err != nil {
		return fmt.Errorf("issue cRLSign cert: %w", err)
	}
	if _, err := env.ProbeX509WithCert(badCert); err == nil {
		return fmt.Errorf("X17: SDK accepted client cert with cRLSign key usage")
	}
	return nil
}

// runX18 — when the EKU extension is present it must include serverAuth
// and clientAuth (X509-17). A cert that has EKU but neither value should
// be rejected.
func runX18(ctx context.Context, env *suite.TestEnv) error {
	if err := env.RequireCapability(harnessctl.CapMTLSVerify); err != nil {
		return err
	}
	if _, err := probeUntilSPIFFEID(ctx, env, "spiffe://test.example.org/default", 5*time.Second); err != nil {
		return fmt.Errorf("waiting for SDK ready: %w", err)
	}
	badCert, err := env.IssueX509SVID("spiffe://test.example.org/x18-probe",
		ca.WithX509ExtKeyUsage(x509.ExtKeyUsageCodeSigning),
	)
	if err != nil {
		return fmt.Errorf("issue codeSigning-only EKU cert: %w", err)
	}
	if _, err := env.ProbeX509WithCert(badCert); err == nil {
		return fmt.Errorf("X18: SDK accepted client cert whose EKU omits serverAuth and clientAuth")
	}
	return nil
}

// runX19 — a cert with no URI SAN cannot be a valid SVID (X509-01).
func runX19(ctx context.Context, env *suite.TestEnv) error {
	if err := env.RequireCapability(harnessctl.CapMTLSVerify); err != nil {
		return err
	}
	if _, err := probeUntilSPIFFEID(ctx, env, "spiffe://test.example.org/default", 5*time.Second); err != nil {
		return fmt.Errorf("waiting for SDK ready: %w", err)
	}
	badCert, err := env.IssueX509SVID("spiffe://test.example.org/x19-probe",
		ca.WithX509OmitURIs(),
	)
	if err != nil {
		return fmt.Errorf("issue cert without URI SANs: %w", err)
	}
	if _, err := env.ProbeX509WithCert(badCert); err == nil {
		return fmt.Errorf("X19: SDK accepted client cert with no URI SAN")
	}
	return nil
}
