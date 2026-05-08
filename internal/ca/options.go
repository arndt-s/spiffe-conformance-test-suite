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
	extraURIs   []*url.URL
	uriOverride []*url.URL
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
func WithX509KeyUsage(ku x509.KeyUsage) X509SVIDOption {
	return func(c *x509SVIDConfig) { c.keyUsage = &ku }
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
	ttl          time.Duration
	audience     []string
	extra        map[string]interface{}
	deleteClaims []string
	extraHeaders map[string]interface{}
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
