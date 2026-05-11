package ca

import (
	"crypto/x509"
	"net/url"
	"time"
)

// X509SVIDOption is a functional option for IssueX509SVID.
type X509SVIDOption func(*x509SVIDConfig)

type x509SVIDConfig struct {
	ttl         time.Duration
	dnsNames    []string
	notBefore   time.Time
	isCA        bool
	keyUsage    *x509.KeyUsage
	extKeyUsage *[]x509.ExtKeyUsage
	extraURIs   []*url.URL
	uriOverride []*url.URL
	omitURIs    bool
}

func defaultX509Config() x509SVIDConfig {
	return x509SVIDConfig{
		ttl:       time.Hour,
		notBefore: time.Now(),
	}
}

// WithX509TTL sets the certificate lifetime.
func WithX509TTL(d time.Duration) X509SVIDOption {
	return func(c *x509SVIDConfig) { c.ttl = d }
}

// WithX509DNSNames adds DNS SANs to the issued certificate.
func WithX509DNSNames(names ...string) X509SVIDOption {
	return func(c *x509SVIDConfig) { c.dnsNames = append(c.dnsNames, names...) }
}

// WithX509NotBefore sets the certificate validity start time.
func WithX509NotBefore(t time.Time) X509SVIDOption {
	return func(c *x509SVIDConfig) { c.notBefore = t }
}

// WithX509IsCA marks the leaf as a CA (sets IsCA: true, BasicConstraintsValid: true).
// Used by X6 to test that SDKs reject CA certs masquerading as leaf SVIDs.
func WithX509IsCA() X509SVIDOption {
	return func(c *x509SVIDConfig) { c.isCA = true }
}

// WithX509KeyUsage overrides the default key usage flags on the leaf cert.
// Pass 0 to omit the Key Usage extension entirely.
func WithX509KeyUsage(ku x509.KeyUsage) X509SVIDOption {
	return func(c *x509SVIDConfig) { c.keyUsage = &ku }
}

// WithX509ExtKeyUsage overrides the Extended Key Usage flags on the leaf
// cert. Pass no arguments to emit an empty (but present) EKU extension.
func WithX509ExtKeyUsage(eku ...x509.ExtKeyUsage) X509SVIDOption {
	return func(c *x509SVIDConfig) {
		copied := append([]x509.ExtKeyUsage(nil), eku...)
		c.extKeyUsage = &copied
	}
}

// WithX509OmitURIs issues a leaf with no URI SANs at all. The cert is
// otherwise unchanged; the resulting cert violates the SVID requirement
// of containing exactly one SPIFFE URI SAN.
func WithX509OmitURIs() X509SVIDOption {
	return func(c *x509SVIDConfig) { c.omitURIs = true }
}

// WithX509ExtraURIs appends additional URI SANs alongside the SPIFFE ID.
func WithX509ExtraURIs(uris ...*url.URL) X509SVIDOption {
	return func(c *x509SVIDConfig) { c.extraURIs = append(c.extraURIs, uris...) }
}

// WithX509URIOverride replaces the default SPIFFE URI SAN list entirely.
func WithX509URIOverride(uris ...*url.URL) X509SVIDOption {
	return func(c *x509SVIDConfig) { c.uriOverride = uris }
}

// JWTSVIDOption is a functional option for IssueJWT.
type JWTSVIDOption func(*jwtSVIDConfig)

type jwtSVIDConfig struct {
	ttl           time.Duration
	audience      []string
	extra         map[string]interface{}
	deleteClaims  []string
	extraHeaders  map[string]interface{}
	deleteHeaders []string
	signingKID    string
}

func defaultJWTConfig() jwtSVIDConfig {
	return jwtSVIDConfig{
		ttl:      time.Hour,
		audience: []string{"test"},
	}
}

// WithJWTTTL sets the JWT lifetime.
func WithJWTTTL(d time.Duration) JWTSVIDOption {
	return func(c *jwtSVIDConfig) { c.ttl = d }
}

// WithJWTAudience sets the JWT audience claim.
func WithJWTAudience(aud ...string) JWTSVIDOption {
	return func(c *jwtSVIDConfig) { c.audience = aud }
}

// WithJWTClaim adds an extra claim to the JWT payload.
func WithJWTClaim(key string, value interface{}) JWTSVIDOption {
	return func(c *jwtSVIDConfig) {
		if c.extra == nil {
			c.extra = make(map[string]interface{})
		}
		c.extra[key] = value
	}
}

// WithJWTDeleteClaim removes a standard claim from the JWT payload.
// Used by J10 (delete "exp") and J11 (delete "aud").
func WithJWTDeleteClaim(key string) JWTSVIDOption {
	return func(c *jwtSVIDConfig) { c.deleteClaims = append(c.deleteClaims, key) }
}

// WithJWTHeader sets a JWT header field (overrides or adds).
// Used by J12 (set "typ" to an invalid value).
func WithJWTHeader(key string, value interface{}) JWTSVIDOption {
	return func(c *jwtSVIDConfig) {
		if c.extraHeaders == nil {
			c.extraHeaders = make(map[string]interface{})
		}
		c.extraHeaders[key] = value
	}
}

// WithJWTDeleteHeader removes a header field after the default ones have
// been set. Useful for testing optional fields like "typ".
func WithJWTDeleteHeader(key string) JWTSVIDOption {
	return func(c *jwtSVIDConfig) { c.deleteHeaders = append(c.deleteHeaders, key) }
}

// WithJWTSigningKey selects which JWT signing key (by kid) is used to sign
// the issued token. If unset, IssueJWT picks the first registered "sig"
// (or untyped) key.
func WithJWTSigningKey(kid string) JWTSVIDOption {
	return func(c *jwtSVIDConfig) { c.signingKID = kid }
}

// JWTKeyOption configures a JWT signing key registered via (*CA).AddJWTKey.
type JWTKeyOption func(*jwtKeyConfig)

type jwtKeyConfig struct {
	alg string
	use string
	kid string
}

func defaultJWTKeyConfig() jwtKeyConfig {
	return jwtKeyConfig{alg: "ES256", use: "sig"}
}

// WithJWTKeyAlg sets the JWS algorithm for the registered key. Supported
// values are RS256/RS384/RS512, ES256/ES384/ES512, PS256/PS384/PS512.
func WithJWTKeyAlg(alg string) JWTKeyOption {
	return func(c *jwtKeyConfig) { c.alg = alg }
}

// WithJWTKeyUse sets the JWK "use" parameter ("sig", "enc", or empty).
func WithJWTKeyUse(use string) JWTKeyOption {
	return func(c *jwtKeyConfig) { c.use = use }
}

// WithJWTKeyID sets an explicit kid for the registered key. If unset,
// AddJWTKey assigns one of the form "key-<n>".
func WithJWTKeyID(kid string) JWTKeyOption {
	return func(c *jwtKeyConfig) { c.kid = kid }
}
