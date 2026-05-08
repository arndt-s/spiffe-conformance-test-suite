// Package x509 registers the X.509 SVID test cases.
package x509

import (
	"context"
	"fmt"
	"time"

	"github.com/arndt-s/spiffe-conformance-test-suite/internal/ca"
	"github.com/arndt-s/spiffe-conformance-test-suite/internal/prober"
	"github.com/arndt-s/spiffe-conformance-test-suite/internal/workloadapi"
	"github.com/arndt-s/spiffe-conformance-test-suite/suite"
)

func init() {
	suite.Register(suite.TestCase{
		Name:        "X1",
		Description: "SDK correctly fetches an X.509 SVID from the Workload API and presents it over TLS",
		Run:         runX1,
	})
	suite.Register(suite.TestCase{
		Name:        "X2",
		Description: "SDK correctly rotates an X.509 SVID when the Workload API updates it",
		Run:         runX2,
	})
	suite.Register(suite.TestCase{
		Name:        "X3",
		Description: "SDK rejects an X.509 SVID with an invalid signature",
		Run:         runX3,
	})
	suite.Register(suite.TestCase{
		Name:        "X4",
		Description: "SDK rejects an X.509 SVID signed by an untrusted CA",
		Run:         runX4,
	})
	suite.Register(suite.TestCase{
		Name:        "X5",
		Description: "SDK rejects an expired X.509 SVID",
		Run:         runX5,
	})
}

func runX1(ctx context.Context, env *suite.TestEnv) error {
	svid, err := env.IssueX509SVID("spiffe://test.example.org/x1")
	if err != nil {
		return fmt.Errorf("issue SVID: %w", err)
	}
	env.ServeX509(svid)

	result, err := probeUntilSPIFFEID(ctx, env, "spiffe://test.example.org/x1", 5*time.Second)
	if err != nil {
		return err
	}
	if err := suite.AssertX509SPIFFEID(result, "spiffe://test.example.org/x1"); err != nil {
		return err
	}
	return suite.AssertX509CertValid(result)
}

func runX2(ctx context.Context, env *suite.TestEnv) error {
	first, err := env.IssueX509SVID("spiffe://test.example.org/x2-first")
	if err != nil {
		return fmt.Errorf("issue first SVID: %w", err)
	}
	env.ServeX509(first)

	if _, err := probeUntilSPIFFEID(ctx, env, "spiffe://test.example.org/x2-first", 5*time.Second); err != nil {
		return fmt.Errorf("waiting for x2-first: %w", err)
	}

	second, err := env.IssueX509SVID("spiffe://test.example.org/x2-second")
	if err != nil {
		return fmt.Errorf("issue second SVID: %w", err)
	}
	env.PushX509Update(second)

	if _, err := probeUntilSPIFFEID(ctx, env, "spiffe://test.example.org/x2-second", 5*time.Second); err != nil {
		return fmt.Errorf("waiting for x2-second (rotation): %w", err)
	}
	return nil
}

func runX3(ctx context.Context, env *suite.TestEnv) error {
	valid, err := env.IssueX509SVID("spiffe://test.example.org/x3-valid")
	if err != nil {
		return fmt.Errorf("issue valid SVID: %w", err)
	}
	env.ServeX509(valid)

	if _, err := probeUntilSPIFFEID(ctx, env, "spiffe://test.example.org/x3-valid", 5*time.Second); err != nil {
		return fmt.Errorf("waiting for x3-valid: %w", err)
	}

	corrupted, err := env.IssueX509SVID("spiffe://test.example.org/x3-corrupted")
	if err != nil {
		return fmt.Errorf("issue corrupted SVID: %w", err)
	}
	// XOR the last 10 bytes of the DER to corrupt the signature block.
	for i := len(corrupted.CertDER) - 10; i < len(corrupted.CertDER); i++ {
		corrupted.CertDER[i] ^= 0xFF
	}
	env.PushX509Update(corrupted)

	time.Sleep(300 * time.Millisecond)

	result, err := env.ProbeX509()
	if err != nil {
		return fmt.Errorf("probe after corrupt push: %w", err)
	}
	return suite.AssertX509SPIFFEID(result, "spiffe://test.example.org/x3-valid")
}

func runX4(ctx context.Context, env *suite.TestEnv) error {
	valid, err := env.IssueX509SVID("spiffe://test.example.org/x4-valid")
	if err != nil {
		return fmt.Errorf("issue valid SVID: %w", err)
	}
	env.ServeX509(valid)

	if _, err := probeUntilSPIFFEID(ctx, env, "spiffe://test.example.org/x4-valid", 5*time.Second); err != nil {
		return fmt.Errorf("waiting for x4-valid: %w", err)
	}

	foreignCA, err := ca.New("spiffe://foreign.example.org")
	if err != nil {
		return fmt.Errorf("create foreign CA: %w", err)
	}
	foreignSVID, err := foreignCA.IssueX509SVID("spiffe://foreign.example.org/x4-foreign")
	if err != nil {
		return fmt.Errorf("issue foreign SVID: %w", err)
	}

	// Send a cert chain signed by the foreign CA but advertise our CA as the
	// trust bundle. A conformant SDK must verify the chain and reject this update.
	env.SetX509State(&workloadapi.X509State{
		Materials:   []*ca.X509SVIDMaterial{foreignSVID},
		TrustBundle: [][]byte{env.CA().CACertDER()},
	})

	time.Sleep(300 * time.Millisecond)

	result, err := env.ProbeX509()
	if err != nil {
		return fmt.Errorf("probe after foreign CA push: %w", err)
	}
	return suite.AssertX509SPIFFEID(result, "spiffe://test.example.org/x4-valid")
}

func runX5(ctx context.Context, env *suite.TestEnv) error {
	valid, err := env.IssueX509SVID("spiffe://test.example.org/x5-valid")
	if err != nil {
		return fmt.Errorf("issue valid SVID: %w", err)
	}
	env.ServeX509(valid)

	if _, err := probeUntilSPIFFEID(ctx, env, "spiffe://test.example.org/x5-valid", 5*time.Second); err != nil {
		return fmt.Errorf("waiting for x5-valid: %w", err)
	}

	now := time.Now()
	expired, err := env.IssueX509SVID("spiffe://test.example.org/x5-expired",
		ca.WithX509NotBefore(now.Add(-2*time.Hour)),
		ca.WithX509TTL(time.Hour), // NotAfter = now-2h+1h = now-1h
	)
	if err != nil {
		return fmt.Errorf("issue expired SVID: %w", err)
	}
	env.PushX509Update(expired)

	time.Sleep(300 * time.Millisecond)

	result, err := env.ProbeX509()
	if err != nil {
		return fmt.Errorf("probe after expired cert push: %w", err)
	}
	return suite.AssertX509SPIFFEID(result, "spiffe://test.example.org/x5-valid")
}

// probeUntilSPIFFEID polls env.ProbeX509() at 100 ms intervals until the
// expected SPIFFE ID appears in the peer certificate's URI SANs, or until
// the timeout expires.
func probeUntilSPIFFEID(ctx context.Context, env *suite.TestEnv, want string, timeout time.Duration) (*prober.X509ProbeResult, error) {
	deadline := time.Now().Add(timeout)
	var lastErr error
	var lastIDs []string
	for {
		result, err := env.ProbeX509()
		if err == nil {
			for _, id := range result.SpiffeIDs {
				if id == want {
					return result, nil
				}
			}
			lastIDs = result.SpiffeIDs
			lastErr = nil
		} else {
			lastErr = err
		}
		if time.Now().After(deadline) {
			if lastErr != nil {
				return nil, fmt.Errorf("timeout waiting for SPIFFE ID %q: last probe error: %w", want, lastErr)
			}
			return nil, fmt.Errorf("timeout waiting for SPIFFE ID %q; last seen: %v", want, lastIDs)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}
