// Package workloadapi registers Workload API protocol-behavior conformance
// test cases. These cover requirements from the Workload API specification
// that govern how an SDK consumes streamed responses: default-identity
// selection, mandatory-field handling, and hint deduplication.
package workloadapi

import (
	"context"
	"fmt"
	"time"

	"github.com/arndt-s/spiffe-conformance-test-suite/internal/ca"
	"github.com/arndt-s/spiffe-conformance-test-suite/internal/prober"
	mockwlapi "github.com/arndt-s/spiffe-conformance-test-suite/internal/workloadapi"
	"github.com/arndt-s/spiffe-conformance-test-suite/suite"
)

func init() {
	suite.Register(suite.TestCase{
		Name:        "W4",
		Description: "SDK selects the first SVID in the response as the default identity",
		Run:         runW4,
	})
	suite.Register(suite.TestCase{
		Name:        "W5",
		Description: "SDK rejects a Workload API response missing a mandatory field and continues to use its cached SVID",
		Run:         runW5,
	})
	suite.Register(suite.TestCase{
		Name:        "W6",
		Description: "SDK selects the first SVID when multiple SVIDs share the same hint value",
		Run:         runW6,
	})
}

// runW4 verifies WLAPI-17: the first SVID in the response list is the
// default identity exposed to consumers that do not select by hint.
//
// The test serves two SVIDs in a single response, with /w4-first listed
// before /w4-second, then asserts the SDK presents /w4-first on its
// default X.509 port.
func runW4(ctx context.Context, env *suite.TestEnv) error {
	first, err := env.IssueX509SVID("spiffe://test.example.org/w4-first")
	if err != nil {
		return fmt.Errorf("issue first SVID: %w", err)
	}
	second, err := env.IssueX509SVID("spiffe://test.example.org/w4-second")
	if err != nil {
		return fmt.Errorf("issue second SVID: %w", err)
	}

	env.SetX509State(&mockwlapi.X509State{
		Materials:   []*ca.X509SVIDMaterial{first, second},
		TrustBundle: [][]byte{env.CA().CACertDER()},
	})

	result, err := probeUntilSPIFFEID(ctx, env, "spiffe://test.example.org/w4-first", 5*time.Second)
	if err != nil {
		return err
	}
	// Defence in depth: if the SDK ever exposes /w4-second as the default,
	// the polling loop above would not have returned, but verify explicitly.
	for _, id := range result.SpiffeIDs {
		if id == "spiffe://test.example.org/w4-second" {
			return fmt.Errorf("SDK presented /w4-second as default; expected first SVID /w4-first")
		}
	}
	return nil
}

// runW5 verifies WLAPI-08: a response with a missing mandatory field
// (here, an empty `x509_svid` byte field) must be rejected by the SDK.
// We assert the SDK keeps serving its previously-cached SVID rather than
// adopting the malformed material.
func runW5(ctx context.Context, env *suite.TestEnv) error {
	// Confirm the SDK is currently serving the bootstrap default identity.
	if _, err := probeUntilSPIFFEID(ctx, env, "spiffe://test.example.org/default", 5*time.Second); err != nil {
		return fmt.Errorf("waiting for SDK ready: %w", err)
	}

	bad, err := env.IssueX509SVID("spiffe://test.example.org/w5-bad")
	if err != nil {
		return fmt.Errorf("issue bad SVID: %w", err)
	}
	env.SetX509State(&mockwlapi.X509State{
		Materials:   []*ca.X509SVIDMaterial{bad},
		TrustBundle: [][]byte{env.CA().CACertDER()},
		Corruption: mockwlapi.X509Corruption{
			SVIDBytes: mockwlapi.ByteOverride{Mode: mockwlapi.OverrideEmpty},
		},
	})

	// Give the SDK time to ingest (and reject) the malformed response.
	time.Sleep(500 * time.Millisecond)

	result, err := env.ProbeX509()
	if err != nil {
		return fmt.Errorf("probe after malformed push: %w", err)
	}
	for _, id := range result.SpiffeIDs {
		if id == "spiffe://test.example.org/w5-bad" {
			return fmt.Errorf("SDK accepted malformed X509SVID response (presented /w5-bad)")
		}
	}
	return suite.AssertX509SPIFFEID(result, "spiffe://test.example.org/default")
}

// runW6 verifies WLAPI-10: when multiple SVIDs in a single response share
// the same hint value, the client SHOULD select the first one. We serve
// two SVIDs with identical hint="dup" and assert the SDK exposes the
// first as its default identity.
func runW6(ctx context.Context, env *suite.TestEnv) error {
	first, err := env.IssueX509SVID("spiffe://test.example.org/w6-first")
	if err != nil {
		return fmt.Errorf("issue first SVID: %w", err)
	}
	second, err := env.IssueX509SVID("spiffe://test.example.org/w6-second")
	if err != nil {
		return fmt.Errorf("issue second SVID: %w", err)
	}

	env.SetX509State(&mockwlapi.X509State{
		Materials:     []*ca.X509SVIDMaterial{first, second},
		TrustBundle:   [][]byte{env.CA().CACertDER()},
		HintOverrides: []string{"dup", "dup"},
	})

	result, err := probeUntilSPIFFEID(ctx, env, "spiffe://test.example.org/w6-first", 5*time.Second)
	if err != nil {
		return err
	}
	for _, id := range result.SpiffeIDs {
		if id == "spiffe://test.example.org/w6-second" {
			return fmt.Errorf("SDK presented /w6-second; expected first SVID /w6-first under duplicate hint")
		}
	}
	return nil
}

// probeUntilSPIFFEID polls env.ProbeX509() at 100 ms intervals until the
// expected SPIFFE ID appears in the peer certificate's URI SANs, or the
// timeout expires.
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
