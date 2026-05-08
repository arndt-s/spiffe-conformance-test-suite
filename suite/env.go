package suite

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/arndt-s/spiffe-conformance-test-suite/internal/ca"
	"github.com/arndt-s/spiffe-conformance-test-suite/internal/harness"
	"github.com/arndt-s/spiffe-conformance-test-suite/internal/prober"
	"github.com/arndt-s/spiffe-conformance-test-suite/internal/workloadapi"
)

// TestEnv provides high-level helpers for all components available to a
// test case. It owns the CA, mock server, and the running harness process.
type TestEnv struct {
	ca        *ca.CA
	server    *workloadapi.Server
	process   *harness.RunningProcess
	probeCert tls.Certificate // valid client cert for ProbeX509 calls
	trustPool *x509.CertPool // trust pool built from test CA
}

// newTestEnv creates and wires up a complete test environment.
// It returns the env, a cleanup func, and any startup error.
func newTestEnv(ctx context.Context, cmd string, args []string, stdout, stderr io.Writer) (*TestEnv, func(), error) {
	tmpDir, err := os.MkdirTemp("", "spiffe-suite-*")
	if err != nil {
		return nil, nil, fmt.Errorf("mktemp: %w", err)
	}
	cleanup := func() { os.RemoveAll(tmpDir) }

	trustDomain := "spiffe://test.example.org"
	authority, err := ca.New(trustDomain)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("create CA: %w", err)
	}

	socketPath := filepath.Join(tmpDir, "workload.sock")
	server := workloadapi.NewServer(socketPath)
	if err := server.Start(); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("start workload server: %w", err)
	}

	// Pre-populate state so the subprocess can complete its startup sequence.
	// NewX509Source blocks until the first X.509 SVID is pushed; FetchJWTSVID
	// returns NotFound if no JWT state is set.  Individual test cases may
	// replace this state after newTestEnv returns.
	defaultX509, err := authority.IssueX509SVID("spiffe://test.example.org/default")
	if err != nil {
		server.Stop()
		cleanup()
		return nil, nil, fmt.Errorf("issue default X.509 SVID: %w", err)
	}
	server.SetX509State(&workloadapi.X509State{
		Materials:   []*ca.X509SVIDMaterial{defaultX509},
		TrustBundle: [][]byte{authority.CACertDER()},
	})

	defaultJWT, err := authority.IssueJWT("spiffe://test.example.org/default")
	if err != nil {
		server.Stop()
		cleanup()
		return nil, nil, fmt.Errorf("issue default JWT SVID: %w", err)
	}
	defaultJWKS, err := authority.JWKSBytes()
	if err != nil {
		server.Stop()
		cleanup()
		return nil, nil, fmt.Errorf("build default JWKS: %w", err)
	}
	u, _ := url.Parse(trustDomain)
	server.SetJWTState(&workloadapi.JWTState{
		Audience:   "test",
		Materials:  []*ca.JWTSVIDMaterial{defaultJWT},
		JWKSBundle: map[string][]byte{u.Host: defaultJWKS},
	})

	probeSVID, err := authority.IssueX509SVID("spiffe://test.example.org/probe")
	if err != nil {
		server.Stop()
		cleanup()
		return nil, nil, fmt.Errorf("issue probe SVID: %w", err)
	}

	process, err := harness.Start(ctx, harness.Config{
		Cmd:        cmd,
		Args:       splitArgs(args),
		SocketPath: socketPath,
		StdOut:     stdout,
		StdErr:     stderr,
	})
	if err != nil {
		server.Stop()
		cleanup()
		return nil, nil, fmt.Errorf("start harness: %w", err)
	}

	env := &TestEnv{
		ca:        authority,
		server:    server,
		process:   process,
		probeCert: probeSVID.TLSCertificate(),
		trustPool: authority.CACertPool(),
	}

	fullCleanup := func() {
		_ = process.Stop()
		server.Stop()
		cleanup()
	}
	return env, fullCleanup, nil
}

// CA returns the underlying CA for direct access when needed.
func (e *TestEnv) CA() *ca.CA { return e.ca }

// IssueX509SVID issues an X.509 SVID from the test CA.
func (e *TestEnv) IssueX509SVID(spiffeID string, opts ...ca.X509SVIDOption) (*ca.X509SVIDMaterial, error) {
	return e.ca.IssueX509SVID(spiffeID, opts...)
}

// IssueJWT issues a JWT SVID from the test CA.
func (e *TestEnv) IssueJWT(spiffeID string, opts ...ca.JWTSVIDOption) (*ca.JWTSVIDMaterial, error) {
	return e.ca.IssueJWT(spiffeID, opts...)
}

// ServeX509 sets the X.509 state so the mock server returns the given materials.
func (e *TestEnv) ServeX509(materials ...*ca.X509SVIDMaterial) {
	e.server.SetX509State(&workloadapi.X509State{
		Materials:   materials,
		TrustBundle: [][]byte{e.ca.CACertDER()},
	})
}

// PushX509Update replaces the X.509 state and triggers a streaming update.
func (e *TestEnv) PushX509Update(materials ...*ca.X509SVIDMaterial) {
	e.ServeX509(materials...)
}

// ServeJWTBundle sets only the JWKS bundle in the JWT state, without changing SVID materials.
// Use this when the test only needs the SDK to be able to validate tokens (not fetch them).
func (e *TestEnv) ServeJWTBundle() error {
	jwks, err := e.ca.JWKSBytes()
	if err != nil {
		return fmt.Errorf("build JWKS: %w", err)
	}
	u, _ := url.Parse(e.ca.TrustDomain())
	e.server.SetJWTState(&workloadapi.JWTState{
		JWKSBundle: map[string][]byte{u.Host: jwks},
	})
	return nil
}

// ServeJWT sets the JWT state so the mock server returns the given materials.
// It automatically populates JWKSBundle from the test CA so the SDK can validate tokens.
func (e *TestEnv) ServeJWT(audience string, materials ...*ca.JWTSVIDMaterial) error {
	jwks, err := e.ca.JWKSBytes()
	if err != nil {
		return fmt.Errorf("build JWKS: %w", err)
	}
	u, _ := url.Parse(e.ca.TrustDomain())
	e.server.SetJWTState(&workloadapi.JWTState{
		Audience:   audience,
		Materials:  materials,
		JWKSBundle: map[string][]byte{u.Host: jwks},
	})
	return nil
}

// SetX509State is a raw escape hatch for setting X.509 server state directly.
func (e *TestEnv) SetX509State(state *workloadapi.X509State) {
	e.server.SetX509State(state)
}

// SetJWTState is a raw escape hatch for setting JWT server state directly.
func (e *TestEnv) SetJWTState(state *workloadapi.JWTState) {
	e.server.SetJWTState(state)
}

// ProbeX509 probes the SDK's X.509 port via mTLS using the probe SVID
// issued at env creation time and the CA trust pool.
func (e *TestEnv) ProbeX509() (*prober.X509ProbeResult, error) {
	return prober.ProbeX509(e.process.X509Port(), e.probeCert, e.trustPool)
}

// ProbeX509WithCert dials the SDK's X.509 port presenting the given SVID as
// the client certificate. Returns an error if the TLS handshake fails (i.e.
// the SDK rejected the cert) — which is the expected outcome for X10–X13.
func (e *TestEnv) ProbeX509WithCert(clientSVID *ca.X509SVIDMaterial) (*prober.X509ProbeResult, error) {
	return prober.ProbeX509(e.process.X509Port(), clientSVID.TLSCertificate(), e.trustPool)
}

// ProbeJWT probes the SDK's JWT port with the given JWT token and returns the result.
func (e *TestEnv) ProbeJWT(jwtToken string) (*prober.JWTProbeResult, error) {
	return prober.ProbeJWT(e.process.JWTPort(), jwtToken)
}

// X509Port returns the port on which the SDK exposes X.509 SVIDs.
func (e *TestEnv) X509Port() int { return e.process.X509Port() }

// JWTPort returns the port on which the SDK exposes JWT SVIDs.
func (e *TestEnv) JWTPort() int { return e.process.JWTPort() }

func splitArgs(args []string) []string {
	if len(args) == 1 && strings.Contains(args[0], " ") {
		return strings.Fields(args[0])
	}
	return args
}
