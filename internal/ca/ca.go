// Package ca provides an ephemeral certificate authority for issuing test SVIDs.
package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// CA is an ephemeral certificate authority for a single trust domain.
type CA struct {
	trustDomain string
	cert        *x509.Certificate
	key         *ecdsa.PrivateKey
	// jwtKey is a separate key used exclusively for JWT signing.
	jwtKey    *ecdsa.PrivateKey
	jwtKeyID  string
}

// X509SVIDMaterial contains the issued leaf certificate and its private key.
type X509SVIDMaterial struct {
	SPIFFEID    string
	Cert        *x509.Certificate
	Key         *ecdsa.PrivateKey
	CACert      *x509.Certificate
	CertDER     []byte
	CACertDER   []byte
}

// CertChainDER returns the leaf + CA chain as a flat DER slice (leaf first).
func (m *X509SVIDMaterial) CertChainDER() [][]byte {
	return [][]byte{m.CertDER, m.CACertDER}
}

// KeyPEM returns the private key in PKCS8 PEM format.
func (m *X509SVIDMaterial) KeyPEM() ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(m.Key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// KeyDER returns the private key as PKCS8 ASN.1 DER bytes.
func (m *X509SVIDMaterial) KeyDER() ([]byte, error) {
	return x509.MarshalPKCS8PrivateKey(m.Key)
}

// JWTSVIDMaterial holds a signed JWT string along with metadata.
type JWTSVIDMaterial struct {
	SPIFFEID string
	Token    string
	Audience []string
	Expiry   time.Time
}

// New creates a new CA for the given trust domain (e.g. "spiffe://example.org").
func New(trustDomain string) (*CA, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}

	jwtKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate JWT key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: trustDomain + " CA"},
		IsCA:                  true,
		BasicConstraintsValid: true,
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("create CA cert: %w", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}

	return &CA{
		trustDomain: trustDomain,
		cert:        caCert,
		key:         caKey,
		jwtKey:      jwtKey,
		jwtKeyID:    "key-1",
	}, nil
}

// TrustDomain returns the trust domain URI this CA represents.
func (c *CA) TrustDomain() string { return c.trustDomain }

// CACertDER returns the raw DER bytes of the CA certificate.
func (c *CA) CACertDER() []byte { return c.cert.Raw }

// CACertPool returns a certificate pool containing this CA's certificate.
func (c *CA) CACertPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(c.cert)
	return pool
}

// TLSCertificate converts the material into a tls.Certificate suitable for
// use as a client or server cert in a crypto/tls config.
func (m *X509SVIDMaterial) TLSCertificate() tls.Certificate {
	return tls.Certificate{
		Certificate: [][]byte{m.CertDER, m.CACertDER},
		PrivateKey:  m.Key,
		Leaf:        m.Cert,
	}
}

// IssueX509SVID issues a leaf X.509 SVID for the given SPIFFE ID.
func (c *CA) IssueX509SVID(spiffeID string, opts ...X509SVIDOption) (*X509SVIDMaterial, error) {
	cfg := defaultX509Config()
	for _, o := range opts {
		o(&cfg)
	}

	spiffeURI, err := url.Parse(spiffeID)
	if err != nil {
		return nil, fmt.Errorf("invalid SPIFFE ID %q: %w", spiffeID, err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	uris := []*url.URL{spiffeURI}
	switch {
	case cfg.omitURIs:
		uris = nil
	case cfg.uriOverride != nil:
		uris = cfg.uriOverride
	default:
		uris = append(uris, cfg.extraURIs...)
	}

	keyUsage := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement
	if cfg.keyUsage != nil {
		keyUsage = *cfg.keyUsage
	}

	extKeyUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	if cfg.extKeyUsage != nil {
		extKeyUsage = *cfg.extKeyUsage
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: spiffeID},
		URIs:                  uris,
		DNSNames:              cfg.dnsNames,
		NotBefore:             cfg.notBefore,
		NotAfter:              cfg.notBefore.Add(cfg.ttl),
		KeyUsage:              keyUsage,
		ExtKeyUsage:           extKeyUsage,
		IsCA:                  cfg.isCA,
		BasicConstraintsValid: cfg.isCA,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &leafKey.PublicKey, c.key)
	if err != nil {
		return nil, fmt.Errorf("create leaf cert: %w", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	return &X509SVIDMaterial{
		SPIFFEID:  spiffeID,
		Cert:      cert,
		Key:       leafKey,
		CACert:    c.cert,
		CertDER:   certDER,
		CACertDER: c.cert.Raw,
	}, nil
}

// IssueJWT issues a signed JWT SVID for the given SPIFFE ID.
func (c *CA) IssueJWT(spiffeID string, opts ...JWTSVIDOption) (*JWTSVIDMaterial, error) {
	cfg := defaultJWTConfig()
	for _, o := range opts {
		o(&cfg)
	}

	now := time.Now()
	expiry := now.Add(cfg.ttl)

	claims := jwt.MapClaims{
		"sub": spiffeID,
		"aud": cfg.audience,
		"iat": now.Unix(),
		"exp": expiry.Unix(),
	}
	for k, v := range cfg.extra {
		claims[k] = v
	}
	for _, k := range cfg.deleteClaims {
		delete(claims, k)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = c.jwtKeyID
	for k, v := range cfg.extraHeaders {
		token.Header[k] = v
	}
	for _, k := range cfg.deleteHeaders {
		delete(token.Header, k)
	}

	signed, err := token.SignedString(c.jwtKey)
	if err != nil {
		return nil, fmt.Errorf("sign JWT: %w", err)
	}

	return &JWTSVIDMaterial{
		SPIFFEID: spiffeID,
		Token:    signed,
		Audience: cfg.audience,
		Expiry:   expiry,
	}, nil
}

// JWKSBytes returns the JSON Web Key Set for JWT verification.
func (c *CA) JWKSBytes() ([]byte, error) {
	pub := c.jwtKey.PublicKey
	x := pub.X.Bytes()
	y := pub.Y.Bytes()

	type jwk struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
		Y   string `json:"y"`
		Kid string `json:"kid"`
		Use string `json:"use"`
	}
	type jwks struct {
		Keys []jwk `json:"keys"`
	}

	import64 := func(b []byte) string {
		// pad to 32 bytes for P-256
		padded := make([]byte, 32)
		copy(padded[32-len(b):], b)
		return encodeBase64URL(padded)
	}

	set := jwks{
		Keys: []jwk{{
			Kty: "EC",
			Crv: "P-256",
			X:   import64(x),
			Y:   import64(y),
			Kid: c.jwtKeyID,
			Use: "sig",
		}},
	}
	return json.Marshal(set)
}

// encodeBase64URL encodes bytes as base64url without padding.
func encodeBase64URL(b []byte) string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	n := len(b)
	out := make([]byte, 0, (n*4+2)/3)
	for i := 0; i < n; i += 3 {
		var v uint32
		v |= uint32(b[i]) << 16
		if i+1 < n {
			v |= uint32(b[i+1]) << 8
		}
		if i+2 < n {
			v |= uint32(b[i+2])
		}
		out = append(out, chars[v>>18&0x3f], chars[v>>12&0x3f])
		if i+1 < n {
			out = append(out, chars[v>>6&0x3f])
		}
		if i+2 < n {
			out = append(out, chars[v&0x3f])
		}
	}
	return string(out)
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	s, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	return s, nil
}
