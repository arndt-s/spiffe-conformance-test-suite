// Package workloadapi provides a controllable mock SPIFFE Workload API server.
package workloadapi

import "github.com/arndt-s/spiffe-conformance-test-suite/internal/ca"

// OverrideMode selects how a ByteOverride mutates a proto field's bytes
// before a response is sent.
type OverrideMode int

const (
	// OverrideDefault leaves the field unchanged.
	OverrideDefault OverrideMode = iota
	// OverrideEmpty replaces the field bytes with an empty slice (nil).
	OverrideEmpty
	// OverrideGarbage replaces the field bytes with a fixed non-parseable
	// byte string, exercising the SDK's handling of malformed data.
	OverrideGarbage
	// OverrideCustom replaces the field bytes with the value of Custom.
	OverrideCustom
)

// ByteOverride lets a test push a malformed value for a single proto byte
// field. Default behaviour (Mode == OverrideDefault) is a no-op.
type ByteOverride struct {
	Mode   OverrideMode
	Custom []byte
}

// Apply returns the bytes the server should emit for the field, given
// the override mode and the original bytes that would otherwise be sent.
func (b ByteOverride) Apply(original []byte) []byte {
	switch b.Mode {
	case OverrideEmpty:
		return nil
	case OverrideGarbage:
		return garbageBytes
	case OverrideCustom:
		return b.Custom
	default:
		return original
	}
}

// garbageBytes is a fixed non-parseable byte string used by OverrideGarbage.
// Chosen to be deterministic (so failures are reproducible) and to be invalid
// as DER, JWS, or any other structure the SDK might attempt to parse.
var garbageBytes = []byte{0x00, 0xFF, 0xDE, 0xAD, 0xBE, 0xEF}

// X509Corruption configures per-field byte overrides applied to every
// X509SVID emitted by the FetchX509SVID stream while this state is current.
type X509Corruption struct {
	// SVIDBytes overrides the leaf-chain `x509_svid` field.
	SVIDBytes ByteOverride
	// KeyBytes overrides the `x509_svid_key` field.
	KeyBytes ByteOverride
	// Bundle overrides the `bundle` field.
	Bundle ByteOverride
}

// JWTCorruption configures per-field byte overrides applied to JWT-related
// responses while the corresponding JWTState is current.
type JWTCorruption struct {
	// JWKSBytes overrides the JWKS bytes returned by FetchJWTBundles.
	JWKSBytes ByteOverride
}

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
	// Corruption applies per-field byte overrides to the served response.
	// The default zero value is a no-op.
	Corruption X509Corruption
}

// JWTState holds the current JWT SVID material to serve.
type JWTState struct {
	// Audience is the requested audience this state applies to.
	Audience string
	// Materials is the list of JWT SVIDs to include in the response.
	Materials []*ca.JWTSVIDMaterial
	// JWKSBundle maps trust-domain host → JWKS JSON served by FetchJWTBundles.
	JWKSBundle map[string][]byte
	// Corruption applies per-field byte overrides to the served response.
	Corruption JWTCorruption
}
