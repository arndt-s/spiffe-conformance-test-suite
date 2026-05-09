// Package ca provides an ephemeral certificate authority for issuing test SVIDs.
package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

// CA is an ephemeral certificate authority. It may be a root CA or an
// intermediate that chains under a root (depth=2 only).
type CA struct {
	trustDomain string

	// rootCert / rootKey are the trust anchor. For a root CA, these
	// equal signingCert / signingKey.
	rootCert *x509.Certificate
	rootKey  *ecdsa.PrivateKey

	// signingCert / signingKey are used to sign issued leaves. For a
	// root CA they equal rootCert / rootKey; for an intermediate they
	// are the intermediate's own cert / key.
	signingCert *x509.Certificate
	signingKey  *ecdsa.PrivateKey

	// intermediateCert is non-nil iff this CA is an intermediate.
	// When set, leaves include it in their cert chain.
	intermediateCert    *x509.Certificate
	intermediateCertDER []byte

	// jwtKeys holds one or more JWT signing keys. Defaults to a single
	// ES256 key with kid="key-1" and use="sig" for backward compatibility.
	jwtKeys []*jwtKey
}

// jwtKey is a single JWT signing key tracked by the CA.
type jwtKey struct {
	kid     string
	alg     string // "ES256", "RS256", "PS256", ...
	use     string // "sig", "enc", or ""
	privKey crypto.Signer
}

// X509SVIDMaterial contains an issued leaf certificate and its private key,
// along with the issuing chain context needed to build a complete chain.
type X509SVIDMaterial struct {
	SPIFFEID string
	Cert     *x509.Certificate
	Key      *ecdsa.PrivateKey

	// CertDER is the leaf certificate's DER bytes.
	CertDER []byte

	// CACert / CACertDER point at the root trust anchor. The names are
	// preserved (rather than renamed RootCert/RootCertDER) so existing
	// callers continue to work; trust-bundle consumers expect these.
	CACert    *x509.Certificate
	CACertDER []byte

	// IntermediateCertDER is non-nil when the leaf was issued by an
	// intermediate CA, and contains the intermediate's DER bytes.
	IntermediateCertDER []byte
}

// CertChainDER returns the leaf + chain as a flat DER slice (leaf first).
// Includes the intermediate when the issuing CA was an intermediate, plus
// the root trust anchor at the end. Root-issued leaves return [leaf, root].
func (m *X509SVIDMaterial) CertChainDER() [][]byte {
	if m.IntermediateCertDER != nil {
		return [][]byte{m.CertDER, m.IntermediateCertDER, m.CACertDER}
	}
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

// New creates a new root CA for the given trust domain
// (e.g. "spiffe://example.org").
func New(trustDomain string) (*CA, error) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate root key: %w", err)
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

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, fmt.Errorf("create root cert: %w", err)
	}
	rootCert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	c := &CA{
		trustDomain: trustDomain,
		rootCert:    rootCert,
		rootKey:     rootKey,
		signingCert: rootCert,
		signingKey:  rootKey,
	}

	// Default JWT signing key — preserves backward-compatible behaviour.
	if _, err := c.AddJWTKey(WithJWTKeyAlg("ES256"), WithJWTKeyID("key-1"), WithJWTKeyUse("sig")); err != nil {
		return nil, err
	}
	return c, nil
}

// NewIntermediate issues an intermediate CA cert under the receiver and
// returns a CA that signs leaves with the intermediate. The receiver
// must be a root CA; chaining beyond depth=2 is not supported.
//
// The intermediate inherits the root's JWT keys so the intermediate CA
// can also issue JWT SVIDs that validate against the same JWKS bundle.
func (c *CA) NewIntermediate(spiffeID string) (*CA, error) {
	if c.intermediateCert != nil {
		return nil, fmt.Errorf("ca: cannot derive an intermediate from another intermediate (depth=2 only)")
	}
	spiffeURI, err := url.Parse(spiffeID)
	if err != nil {
		return nil, fmt.Errorf("invalid SPIFFE ID %q: %w", spiffeID, err)
	}

	intKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate intermediate key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: spiffeID},
		URIs:                  []*url.URL{spiffeURI},
		IsCA:                  true,
		BasicConstraintsValid: true,
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.rootCert, &intKey.PublicKey, c.rootKey)
	if err != nil {
		return nil, fmt.Errorf("create intermediate cert: %w", err)
	}
	intCert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	return &CA{
		trustDomain:         c.trustDomain,
		rootCert:            c.rootCert,
		rootKey:             c.rootKey,
		signingCert:         intCert,
		signingKey:          intKey,
		intermediateCert:    intCert,
		intermediateCertDER: der,
		jwtKeys:             c.jwtKeys, // share JWT keys with root
	}, nil
}

// TrustDomain returns the trust domain URI this CA represents.
func (c *CA) TrustDomain() string { return c.trustDomain }

// CACertDER returns the root certificate DER (the trust anchor) regardless
// of whether the CA is a root or an intermediate.
func (c *CA) CACertDER() []byte { return c.rootCert.Raw }

// RootCertDER is a synonym for CACertDER with a clearer name.
func (c *CA) RootCertDER() []byte { return c.rootCert.Raw }

// IntermediateCertDER returns the intermediate's DER cert, or nil for a
// root CA.
func (c *CA) IntermediateCertDER() []byte {
	if c.intermediateCert == nil {
		return nil
	}
	return c.intermediateCert.Raw
}

// CACertPool returns a certificate pool containing this CA's root cert.
func (c *CA) CACertPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(c.rootCert)
	return pool
}

// TLSCertificate converts the material into a tls.Certificate suitable
// for use as a client or server cert in a crypto/tls config.
func (m *X509SVIDMaterial) TLSCertificate() tls.Certificate {
	chain := [][]byte{m.CertDER}
	if m.IntermediateCertDER != nil {
		chain = append(chain, m.IntermediateCertDER)
	}
	chain = append(chain, m.CACertDER)
	return tls.Certificate{
		Certificate: chain,
		PrivateKey:  m.Key,
		Leaf:        m.Cert,
	}
}

// IssueX509SVID issues a leaf X.509 SVID for the given SPIFFE ID, signed
// by this CA's signing identity.
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

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, c.signingCert, &leafKey.PublicKey, c.signingKey)
	if err != nil {
		return nil, fmt.Errorf("create leaf cert: %w", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	m := &X509SVIDMaterial{
		SPIFFEID:  spiffeID,
		Cert:      cert,
		Key:       leafKey,
		CertDER:   certDER,
		CACert:    c.rootCert,
		CACertDER: c.rootCert.Raw,
	}
	if c.intermediateCert != nil {
		m.IntermediateCertDER = c.intermediateCertDER
	}
	return m, nil
}

// AddJWTKey appends a new JWT signing key to the CA. Returns the kid the
// key was registered under.
func (c *CA) AddJWTKey(opts ...JWTKeyOption) (string, error) {
	cfg := defaultJWTKeyConfig()
	for _, o := range opts {
		o(&cfg)
	}

	priv, err := generateJWTKey(cfg.alg)
	if err != nil {
		return "", err
	}

	kid := cfg.kid
	if kid == "" {
		kid = fmt.Sprintf("key-%d", len(c.jwtKeys)+1)
	}
	c.jwtKeys = append(c.jwtKeys, &jwtKey{
		kid:     kid,
		alg:     cfg.alg,
		use:     cfg.use,
		privKey: priv,
	})
	return kid, nil
}

// generateJWTKey produces a fresh private key suitable for signing with alg.
func generateJWTKey(alg string) (crypto.Signer, error) {
	switch alg {
	case "ES256":
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "ES384":
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "ES512":
		return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
		return rsa.GenerateKey(rand.Reader, 2048)
	default:
		return nil, fmt.Errorf("unsupported JWT alg %q", alg)
	}
}

// signingMethodFor returns the golang-jwt signing method matching alg.
func signingMethodFor(alg string) jwt.SigningMethod {
	switch alg {
	case "ES256":
		return jwt.SigningMethodES256
	case "ES384":
		return jwt.SigningMethodES384
	case "ES512":
		return jwt.SigningMethodES512
	case "RS256":
		return jwt.SigningMethodRS256
	case "RS384":
		return jwt.SigningMethodRS384
	case "RS512":
		return jwt.SigningMethodRS512
	case "PS256":
		return jwt.SigningMethodPS256
	case "PS384":
		return jwt.SigningMethodPS384
	case "PS512":
		return jwt.SigningMethodPS512
	}
	return nil
}

// IssueJWT issues a signed JWT SVID for the given SPIFFE ID. Without
// WithJWTSigningKey, signs with the first registered "sig" or untyped key.
func (c *CA) IssueJWT(spiffeID string, opts ...JWTSVIDOption) (*JWTSVIDMaterial, error) {
	cfg := defaultJWTConfig()
	for _, o := range opts {
		o(&cfg)
	}

	signKey, err := c.pickSigningKey(cfg.signingKID)
	if err != nil {
		return nil, err
	}
	method := signingMethodFor(signKey.alg)
	if method == nil {
		return nil, fmt.Errorf("ca: no signing method for alg %q", signKey.alg)
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
	token.Header["kid"] = signKey.kid
	for k, v := range cfg.extraHeaders {
		token.Header[k] = v
	}
	for _, k := range cfg.deleteHeaders {
		delete(token.Header, k)
	}

	signed, err := token.SignedString(signKey.privKey)
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

// pickSigningKey selects the JWT key to sign with.
func (c *CA) pickSigningKey(kid string) (*jwtKey, error) {
	if kid != "" {
		for _, k := range c.jwtKeys {
			if k.kid == kid {
				return k, nil
			}
		}
		return nil, fmt.Errorf("ca: no JWT key with kid %q", kid)
	}
	for _, k := range c.jwtKeys {
		if k.use == "sig" || k.use == "" {
			return k, nil
		}
	}
	return nil, fmt.Errorf("ca: no JWT signing keys configured")
}

// JWKSBytes returns the JSON Web Key Set publishing every JWT key the CA
// has registered, including their declared `use` value (for example,
// "enc" keys are emitted as-is so consumers can verify they are ignored
// for signature verification).
func (c *CA) JWKSBytes() ([]byte, error) {
	set := jose.JSONWebKeySet{}
	for _, k := range c.jwtKeys {
		jwk := jose.JSONWebKey{
			Key:       k.privKey.Public(),
			KeyID:     k.kid,
			Algorithm: k.alg,
			Use:       k.use,
		}
		set.Keys = append(set.Keys, jwk)
	}
	return json.Marshal(set)
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	s, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	return s, nil
}
