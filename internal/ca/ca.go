// Package ca provides an ephemeral certificate authority for issuing test SVIDs.
package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

// JWTUse is the JWK "use" value for JWT-SVID signing keys (JWT-SVID §6.1).
const JWTUse = "jwt-svid"

// CA is an ephemeral certificate authority for a single trust domain. It holds
// an X.509 signing certificate (a root, or an intermediate created with
// NewIntermediate) and a set of JWT signing keys.
type CA struct {
	trustDomain string // SPIFFE ID of the trust domain, e.g. "spiffe://example.org"
	cert        *x509.Certificate
	key         *ecdsa.PrivateKey
	root        *x509.Certificate
	// intermediates is the DER chain from this CA up to, but excluding, the
	// root. Empty for a root CA.
	intermediates [][]byte
	jwtKeys       []*JWTKey
}

// JWTKey is a JWT-SVID signing key published in the trust domain's JWT bundle.
type JWTKey struct {
	ID     string
	Alg    string
	Signer crypto.Signer
	// Use is the JWK "use" value published in the bundle. Defaults to JWTUse;
	// tests may override it to publish keys a conformant SDK must ignore.
	Use string
}

// X509SVIDMaterial contains the issued leaf certificate and its private key.
type X509SVIDMaterial struct {
	SPIFFEID string
	Cert     *x509.Certificate
	Key      *ecdsa.PrivateKey
	// CACert is the root of the issuing hierarchy, i.e. what belongs in the bundle.
	CACert    *x509.Certificate
	CertDER   []byte
	CACertDER []byte
	// Intermediates is the DER chain between the leaf and the root, leaf-side first.
	Intermediates [][]byte
	// Hint is sent as the X509SVID hint by the mock Workload API.
	Hint string
}

// CertChainDER returns the leaf followed by any intermediates. The root is not
// included; it is distributed via the trust bundle.
func (m *X509SVIDMaterial) CertChainDER() [][]byte {
	return append([][]byte{m.CertDER}, m.Intermediates...)
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

// TLSCertificate converts the material into a tls.Certificate suitable for
// use as a client or server cert in a crypto/tls config.
func (m *X509SVIDMaterial) TLSCertificate() tls.Certificate {
	return tls.Certificate{
		Certificate: m.CertChainDER(),
		PrivateKey:  m.Key,
		Leaf:        m.Cert,
	}
}

// JWTSVIDMaterial holds a signed JWT string along with metadata.
type JWTSVIDMaterial struct {
	SPIFFEID string
	Token    string
	Audience []string
	Expiry   time.Time
}

// New creates a new root CA for the given trust domain (e.g. "spiffe://example.org")
// with a single ES256 JWT signing key.
func New(trustDomain string) (*CA, error) {
	tdURI, err := url.Parse(trustDomain)
	if err != nil {
		return nil, fmt.Errorf("invalid trust domain %q: %w", trustDomain, err)
	}

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: trustDomain + " CA"},
		URIs:                  []*url.URL{tdURI},
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

	c := &CA{
		trustDomain: trustDomain,
		cert:        caCert,
		key:         caKey,
		root:        caCert,
	}
	if _, err := c.AddJWTKey("ES256"); err != nil {
		return nil, err
	}
	return c, nil
}

// NewIntermediate creates an intermediate CA signed by c. SVIDs issued by the
// intermediate carry it in their chain and validate against c's root. The
// intermediate shares c's JWT keys.
func (c *CA) NewIntermediate() (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate intermediate key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: c.trustDomain + " intermediate CA"},
		URIs:                  c.cert.URIs,
		IsCA:                  true,
		BasicConstraintsValid: true,
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(12 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, fmt.Errorf("create intermediate cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{
		trustDomain:   c.trustDomain,
		cert:          cert,
		key:           key,
		root:          c.root,
		intermediates: append([][]byte{der}, c.intermediates...),
		jwtKeys:       c.jwtKeys,
	}, nil
}

// TrustDomain returns the SPIFFE ID of the trust domain, e.g. "spiffe://example.org".
// This is also the key under which the Workload API publishes its bundles.
func (c *CA) TrustDomain() string { return c.trustDomain }

// CACertDER returns the raw DER bytes of the root CA certificate.
func (c *CA) CACertDER() []byte { return c.root.Raw }

// CACertPool returns a certificate pool containing the root CA certificate.
func (c *CA) CACertPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(c.root)
	return pool
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
	if cfg.uriOverride != nil {
		uris = cfg.uriOverride
	} else {
		uris = append(uris, cfg.extraURIs...)
	}

	keyUsage := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement
	if cfg.keyUsage != nil {
		keyUsage = *cfg.keyUsage
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: spiffeID},
		URIs:         uris,
		DNSNames:     cfg.dnsNames,
		NotBefore:    cfg.notBefore,
		NotAfter:     cfg.notBefore.Add(cfg.ttl),
		KeyUsage:     keyUsage,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IsCA:         cfg.isCA,
		// X509-SVID §4.1: leaves MUST carry basic constraints with cA=false.
		BasicConstraintsValid: true,
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
		SPIFFEID:      spiffeID,
		Cert:          cert,
		Key:           leafKey,
		CACert:        c.root,
		CertDER:       certDER,
		CACertDER:     c.root.Raw,
		Intermediates: c.intermediates,
	}, nil
}

// AddJWTKey generates a new JWT signing key for the given JWS algorithm
// (RS256/384/512, PS256/384/512, ES256/384/512 or EdDSA) with a random key ID,
// and adds it to the CA's JWT bundle.
func (c *CA) AddJWTKey(alg string) (*JWTKey, error) {
	signer, err := generateJWTSigner(alg)
	if err != nil {
		return nil, err
	}
	kid, err := randomKeyID()
	if err != nil {
		return nil, err
	}
	k := &JWTKey{ID: kid, Alg: alg, Signer: signer, Use: JWTUse}
	c.jwtKeys = append(c.jwtKeys, k)
	return k, nil
}

// JWTKeys returns the CA's JWT signing keys, in bundle order.
func (c *CA) JWTKeys() []*JWTKey { return c.jwtKeys }

// IssueJWT issues a signed JWT SVID for the given SPIFFE ID. It signs with the
// CA's first JWT key unless WithJWTKey selects another.
func (c *CA) IssueJWT(spiffeID string, opts ...JWTSVIDOption) (*JWTSVIDMaterial, error) {
	cfg := defaultJWTConfig()
	for _, o := range opts {
		o(&cfg)
	}

	key := cfg.key
	if key == nil {
		if len(c.jwtKeys) == 0 {
			return nil, fmt.Errorf("CA has no JWT signing keys")
		}
		key = c.jwtKeys[0]
	}
	method := jwt.GetSigningMethod(key.Alg)
	if method == nil {
		return nil, fmt.Errorf("unsupported JWT algorithm %q", key.Alg)
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

	token := jwt.NewWithClaims(method, claims)
	token.Header["kid"] = key.ID
	for k, v := range cfg.extraHeaders {
		token.Header[k] = v
	}

	signed, err := token.SignedString(key.Signer)
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

// JWKSBytes returns the CA's JWT bundle as a JWK Set. Each key carries its kid
// and its use (normally "jwt-svid", JWT-SVID §6.1).
func (c *CA) JWKSBytes() ([]byte, error) {
	set := struct {
		Keys []json.RawMessage `json:"keys"`
	}{Keys: []json.RawMessage{}}
	for _, k := range c.jwtKeys {
		b, err := json.Marshal(jose.JSONWebKey{Key: k.Signer.Public(), KeyID: k.ID})
		if err != nil {
			return nil, fmt.Errorf("marshal JWK %s: %w", k.ID, err)
		}
		// go-jose only accepts the RFC 7517 "use" values, so set it on the raw JSON.
		if k.Use != "" {
			var m map[string]any
			if err := json.Unmarshal(b, &m); err != nil {
				return nil, err
			}
			m["use"] = k.Use
			if b, err = json.Marshal(m); err != nil {
				return nil, err
			}
		}
		set.Keys = append(set.Keys, b)
	}
	return json.Marshal(set)
}

func generateJWTSigner(alg string) (crypto.Signer, error) {
	switch alg {
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
		return rsa.GenerateKey(rand.Reader, 2048)
	case "ES256":
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "ES384":
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "ES512":
		return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case "EdDSA":
		_, k, err := ed25519.GenerateKey(rand.Reader)
		return k, err
	default:
		return nil, fmt.Errorf("unsupported JWT algorithm %q", alg)
	}
}

func randomKeyID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate key ID: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	s, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	return s, nil
}
