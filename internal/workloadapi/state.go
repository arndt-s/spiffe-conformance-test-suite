// Package workloadapi provides a controllable mock SPIFFE Workload API server.
package workloadapi

import "github.com/arndt-s/spiffe-conformance-test-suite/internal/ca"

// X509State holds the current X.509 SVID material to serve.
type X509State struct {
	// Materials is the list of SVIDs to include in the X509SVIDResponse.
	Materials []*ca.X509SVIDMaterial
	// TrustBundle is the DER-encoded CA cert to include as the trust bundle.
	// If nil, it is derived from Materials[0].CACertDER.
	TrustBundle [][]byte
	// HintOverrides, when non-empty, supplies a hint string for each
	// material at the same index. An empty string at an index leaves the
	// default hint (trust-domain host) in place. A nil or shorter slice
	// leaves all hints at their defaults.
	HintOverrides []string
	// EmptyX509SVIDBytes, when true, causes the served response to set
	// the `x509_svid` field to empty bytes for every material in this state,
	// producing a response that violates the proto's mandatory-field
	// requirement. Used to test WLAPI-08 (mandatory field handling).
	EmptyX509SVIDBytes bool
}

// JWTState holds the current JWT SVID material to serve.
type JWTState struct {
	// Audience is the requested audience this state applies to.
	Audience string
	// Materials is the list of JWT SVIDs to include in the response.
	Materials []*ca.JWTSVIDMaterial
	// JWKSBundle maps trust-domain host → JWKS JSON served by FetchJWTBundles.
	JWKSBundle map[string][]byte
}
