// Package workloadapi provides a controllable mock SPIFFE Workload API server.
package workloadapi

import "github.com/arndt-s/spiffe-conformance-test-suite/internal/ca"

// X509State holds the current X.509 SVID material to serve. Every response the
// server streams is built from the full state (Workload API §4.3).
type X509State struct {
	// Materials is the list of SVIDs to include in the X509SVIDResponse. The
	// first entry is the default identity (Workload API §8).
	Materials []*ca.X509SVIDMaterial
	// TrustBundle holds the DER-encoded CA certificates of the workload's own
	// trust domain. If empty, each SVID's root CA certificate is used.
	TrustBundle [][]byte
	// TrustDomain is the SPIFFE ID of the workload's own trust domain
	// (e.g. "spiffe://example.org"). If empty, it is derived from the first
	// material's SPIFFE ID.
	TrustDomain string
	// FederatedBundles maps a foreign trust domain's SPIFFE ID to its
	// DER-encoded CA certificates.
	FederatedBundles map[string][][]byte
}

// JWTState holds the current JWT SVID material to serve.
type JWTState struct {
	// Materials is the list of JWT SVIDs returned by FetchJWTSVID. If empty,
	// FetchJWTSVID returns PermissionDenied.
	Materials []*ca.JWTSVIDMaterial
	// Bundles maps a trust domain's SPIFFE ID (e.g. "spiffe://example.org") to
	// the JWKS document served by FetchJWTBundles and used by ValidateJWTSVID.
	Bundles map[string][]byte
}
