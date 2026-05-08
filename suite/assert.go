package suite

import (
	"fmt"
	"time"

	"github.com/arndt-s/spiffe-conformance-test-suite/internal/prober"
)

// AssertX509SPIFFEID verifies that the X.509 probe result contains the
// expected SPIFFE ID in the leaf certificate.
func AssertX509SPIFFEID(result *prober.X509ProbeResult, want string) error {
	for _, got := range result.SpiffeIDs {
		if got == want {
			return nil
		}
	}
	return fmt.Errorf("expected SPIFFE ID %q not found in peer cert; got %v",
		want, result.SpiffeIDs)
}

// AssertX509CertValid verifies the leaf certificate has a non-zero validity
// window and is currently valid.
func AssertX509CertValid(result *prober.X509ProbeResult) error {
	if len(result.PeerCerts) == 0 {
		return fmt.Errorf("no peer certificates")
	}
	leaf := result.PeerCerts[0]
	now := time.Now()
	if leaf.NotBefore.IsZero() || leaf.NotAfter.IsZero() {
		return fmt.Errorf("leaf cert has zero validity window")
	}
	if now.Before(leaf.NotBefore) {
		return fmt.Errorf("leaf cert is not yet valid (NotBefore=%s)", leaf.NotBefore)
	}
	if now.After(leaf.NotAfter) {
		return fmt.Errorf("leaf cert has expired (NotAfter=%s)", leaf.NotAfter)
	}
	return nil
}

// AssertJWTSPIFFEID verifies the JWT "sub" claim equals the expected SPIFFE ID.
func AssertJWTSPIFFEID(result *prober.JWTProbeResult, want string) error {
	if result.SPIFFEID != want {
		return fmt.Errorf("expected SPIFFE ID %q; got %q", want, result.SPIFFEID)
	}
	return nil
}
