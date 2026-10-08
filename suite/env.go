package suite

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/arndt-s/spiffe-conformance-test-suite/internal/ca"
	"github.com/arndt-s/spiffe-conformance-test-suite/internal/harness"
	"github.com/arndt-s/spiffe-conformance-test-suite/internal/prober"
	"github.com/arndt-s/spiffe-conformance-test-suite/internal/workloadapi"
)

// TrustDomain is the SPIFFE ID of the trust domain the suite's CA serves.
const TrustDomain = "spiffe://test.example.org"

// DefaultSVIDID is the SPIFFE ID of the X.509-SVID served when a test starts.
const DefaultSVIDID = TrustDomain + "/default"

// Audience is the audience the suite asks SDKs to validate JWT-SVIDs for.
const Audience = "conformance"

// EnvOptions changes how a test's environment is set up.
type EnvOptions struct {
	// ManualStart leaves the harness stopped; the test calls StartHarness.
	ManualStart bool
	// TCPEndpoint serves the mock Workload API on tcp://127.0.0.1:<port>
	// instead of a Unix domain socket.
	TCPEndpoint bool
	// DeferServerStart creates the mock server without listening; the test
	// calls Server().Start(). Requires ManualStart.
	DeferServerStart bool
}

// TestEnv provides high-level helpers for all components available to a
// test case. It owns the CA, mock server, and the running harness process.
type TestEnv struct {
	cfg      RunnerConfig
	opts     EnvOptions
	ca       *ca.CA
	server   *workloadapi.Server
	endpoint string
	tmpDir   string

	process *harness.RunningProcess
	control *prober.Control

	probeCert tls.Certificate // valid client cert for ProbeX509 calls

	trustMu   sync.Mutex
	trustPool *x509.CertPool // roots the suite uses to verify what the SDK presents
}

var barrierSeq atomic.Uint64

// newTestEnv creates the CA and mock server, serves a default X.509-SVID,
// JWT-SVID and JWT bundle, and (unless opts.ManualStart) starts the harness.
func newTestEnv(ctx context.Context, cfg RunnerConfig, opts EnvOptions) (*TestEnv, error) {
	if opts.DeferServerStart && !opts.ManualStart {
		return nil, fmt.Errorf("DeferServerStart requires ManualStart")
	}
	// Short base path: Unix socket paths are limited to ~108 bytes.
	tmpDir, err := os.MkdirTemp("", "scts-*")
	if err != nil {
		return nil, fmt.Errorf("mktemp: %w", err)
	}

	authority, err := ca.New(TrustDomain)
	if err != nil {
		os.RemoveAll(tmpDir)
		return nil, fmt.Errorf("create CA: %w", err)
	}

	e := &TestEnv{cfg: cfg, opts: opts, ca: authority, tmpDir: tmpDir, trustPool: authority.CACertPool()}
	if opts.TCPEndpoint {
		e.server = workloadapi.NewTCPServer("127.0.0.1:0")
	} else {
		socket := filepath.Join(tmpDir, "api.sock")
		e.server = workloadapi.NewServer(socket)
		e.endpoint = "unix://" + socket
	}
	if !opts.DeferServerStart {
		if err := e.server.Start(); err != nil {
			e.close()
			return nil, fmt.Errorf("start workload server: %w", err)
		}
	}
	if opts.TCPEndpoint {
		e.endpoint = "tcp://" + e.server.SocketPath()
	}

	defaultX509, err := authority.IssueX509SVID(DefaultSVIDID)
	if err != nil {
		e.close()
		return nil, fmt.Errorf("issue default X.509 SVID: %w", err)
	}
	e.ServeX509(defaultX509)

	defaultJWT, err := authority.IssueJWT(DefaultSVIDID)
	if err != nil {
		e.close()
		return nil, fmt.Errorf("issue default JWT SVID: %w", err)
	}
	if err := e.ServeJWT(defaultJWT); err != nil {
		e.close()
		return nil, err
	}

	probeSVID, err := authority.IssueX509SVID(TrustDomain + "/probe")
	if err != nil {
		e.close()
		return nil, fmt.Errorf("issue probe SVID: %w", err)
	}
	e.probeCert = probeSVID.TLSCertificate()

	if !opts.ManualStart {
		timeout := cfg.ReadyTimeout
		if timeout == 0 {
			timeout = harness.DefaultReadinessTimeout
		}
		if err := e.StartHarness(ctx, timeout); err != nil {
			e.close()
			return nil, err
		}
	}
	return e, nil
}

func (e *TestEnv) close() {
	if e.process != nil {
		e.process.Stop()
	}
	e.server.Stop()
	os.RemoveAll(e.tmpDir)
}

// Endpoint returns the SPIFFE_ENDPOINT_SOCKET value the harness is given.
// With DeferServerStart and TCPEndpoint it is only known after Server().Start().
func (e *TestEnv) Endpoint() string { return e.endpoint }

// StartHarness starts the harness with the environment's endpoint and waits
// up to timeout for READY. See StartHarnessWithEndpoint.
func (e *TestEnv) StartHarness(ctx context.Context, timeout time.Duration) error {
	return e.StartHarnessWithEndpoint(ctx, e.endpoint, timeout)
}

// StartHarnessWithEndpoint starts the harness with SPIFFE_ENDPOINT_SOCKET set
// to endpoint and waits up to timeout for READY. It returns an error if the
// harness did not become ready; in a ManualStart test that may be the
// expected outcome, so the error is not an ExecutionError.
func (e *TestEnv) StartHarnessWithEndpoint(ctx context.Context, endpoint string, timeout time.Duration) error {
	if e.process != nil {
		return ExecErrorf("harness already started")
	}
	p, err := harness.Start(ctx, harness.Config{
		Cmd:              e.cfg.Cmd,
		Args:             splitArgs(e.cfg.Args),
		Endpoint:         endpoint,
		ReadinessTimeout: timeout,
		StdOut:           e.cfg.StOut,
		StdErr:           e.cfg.StErr,
	})
	if err != nil {
		return fmt.Errorf("start harness: %w", err)
	}
	e.process = p
	e.control = prober.NewControl(p.ControlPort())
	return nil
}

// Server returns the mock Workload API server, e.g. to inject errors or
// inspect recorded calls.
func (e *TestEnv) Server() *workloadapi.Server { return e.server }

// CA returns the suite's CA for TrustDomain.
func (e *TestEnv) CA() *ca.CA { return e.ca }

// TrustRoot adds c's root to the roots the suite uses to verify SVIDs the
// SDK presents. Call it before serving SVIDs issued by another CA.
func (e *TestEnv) TrustRoot(c *ca.CA) {
	cert, err := x509.ParseCertificate(c.CACertDER())
	if err != nil {
		panic(err) // c.CACertDER is always a valid certificate
	}
	e.trustMu.Lock()
	defer e.trustMu.Unlock()
	e.trustPool.AddCert(cert)
}

func (e *TestEnv) roots() *x509.CertPool {
	e.trustMu.Lock()
	defer e.trustMu.Unlock()
	return e.trustPool.Clone()
}

// IssueX509SVID issues an X.509 SVID from the suite's CA.
func (e *TestEnv) IssueX509SVID(spiffeID string, opts ...ca.X509SVIDOption) (*ca.X509SVIDMaterial, error) {
	return e.ca.IssueX509SVID(spiffeID, opts...)
}

// IssueJWT issues a JWT SVID from the suite's CA.
func (e *TestEnv) IssueJWT(spiffeID string, opts ...ca.JWTSVIDOption) (*ca.JWTSVIDMaterial, error) {
	return e.ca.IssueJWT(spiffeID, opts...)
}

// ServeX509 serves the given SVIDs with the suite CA's bundle.
func (e *TestEnv) ServeX509(materials ...*ca.X509SVIDMaterial) {
	e.server.SetX509State(&workloadapi.X509State{
		Materials:   materials,
		TrustBundle: [][]byte{e.ca.CACertDER()},
		TrustDomain: e.ca.TrustDomain(),
	})
}

// SetX509State is a raw escape hatch for setting X.509 server state directly.
func (e *TestEnv) SetX509State(state *workloadapi.X509State) {
	e.server.SetX509State(state)
}

// ServeJWTBundle serves the suite CA's JWT bundle and no JWT-SVIDs.
func (e *TestEnv) ServeJWTBundle() error {
	jwks, err := e.ca.JWKSBytes()
	if err != nil {
		return ExecErrorf("build JWKS: %w", err)
	}
	e.server.SetJWTState(&workloadapi.JWTState{
		Bundles: map[string][]byte{e.ca.TrustDomain(): jwks},
	})
	return nil
}

// ServeJWT serves the given JWT-SVIDs (for FetchJWTSVID) with the suite CA's
// JWT bundle.
func (e *TestEnv) ServeJWT(materials ...*ca.JWTSVIDMaterial) error {
	jwks, err := e.ca.JWKSBytes()
	if err != nil {
		return ExecErrorf("build JWKS: %w", err)
	}
	e.server.SetJWTState(&workloadapi.JWTState{
		Materials: materials,
		Bundles:   map[string][]byte{e.ca.TrustDomain(): jwks},
	})
	return nil
}

// SetJWTState is a raw escape hatch for setting JWT server state directly
// (bundles keyed by trust domain SPIFFE ID).
func (e *TestEnv) SetJWTState(state *workloadapi.JWTState) {
	e.server.SetJWTState(state)
}

// ProbeX509 connects to the SDK's X.509 port presenting the suite's valid
// probe SVID, verifying the SDK's SVID against the trusted roots. It returns
// an error if the connection fails or the SDK rejects the probe certificate.
func (e *TestEnv) ProbeX509() (*prober.X509ProbeResult, error) {
	if e.process == nil {
		return nil, ExecErrorf("harness not started")
	}
	return prober.ProbeX509(e.process.X509Port(), e.probeCert, e.roots())
}

// UnauthenticatedPeerLine is what a harness writes on the X.509 port when
// the SDK cannot authenticate peer X.509-SVIDs (harness contract §3).
const UnauthenticatedPeerLine = "-"

// ClientCertVerdict connects to the SDK's X.509 port presenting clientSVID as
// the client certificate and reports whether the SDK accepted it. It returns a
// SkipError if the harness declares that the SDK cannot authenticate peers.
func (e *TestEnv) ClientCertVerdict(clientSVID *ca.X509SVIDMaterial) (bool, error) {
	if e.process == nil {
		return false, ExecErrorf("harness not started")
	}
	res, err := prober.ProbeX509(e.process.X509Port(), clientSVID.TLSCertificate(), e.roots())
	if err != nil {
		return false, nil
	}
	if res.PeerLine == UnauthenticatedPeerLine {
		return false, Skipf("SDK cannot authenticate peer X.509-SVIDs (harness wrote %q)", UnauthenticatedPeerLine)
	}
	return true, nil
}

// JWTVerdict is the SDK's decision on a JWT-SVID.
type JWTVerdict struct {
	Accepted bool
	// SPIFFEID is the SPIFFE ID the SDK extracted (accepted tokens only).
	SPIFFEID string
	// Message is the harness's explanation, if any.
	Message string
}

// ValidateJWT asks the SDK to validate token for audience. An SDK rejection is
// a verdict, not an error. If the harness cannot perform the validation the
// returned error is an ExecutionError, or a SkipError if the harness does not
// support JWT validation.
func (e *TestEnv) ValidateJWT(token, audience string) (JWTVerdict, error) {
	if e.control == nil {
		return JWTVerdict{}, ExecErrorf("harness not started")
	}
	res, err := e.control.ValidateJWT(token, audience)
	if err != nil {
		return JWTVerdict{}, &ExecutionError{Err: e.withStderr(err)}
	}
	switch res.Status {
	case prober.OutcomeOK:
		return JWTVerdict{Accepted: true, SPIFFEID: res.SPIFFEID, Message: res.Message}, nil
	case prober.OutcomeRejected:
		return JWTVerdict{Accepted: false, Message: res.Message}, nil
	case prober.OutcomeUnsupported:
		return JWTVerdict{}, Skipf("harness does not support JWT validation: %s", res.Message)
	default:
		return JWTVerdict{}, ExecErrorf("harness could not validate the JWT: %s", res.Message)
	}
}

// FetchJWTFromSDK asks the SDK to fetch JWT-SVIDs for the given audiences.
// The returned error is an ExecutionError or SkipError as for ValidateJWT; a
// harness "error" outcome (e.g. the SDK surfaced a Workload API error) is
// returned as a response with Status OutcomeError, not as an error.
func (e *TestEnv) FetchJWTFromSDK(audience []string, spiffeID string) (*prober.ControlResponse, error) {
	if e.control == nil {
		return nil, ExecErrorf("harness not started")
	}
	res, err := e.control.FetchJWT(audience, spiffeID)
	if err != nil {
		return nil, &ExecutionError{Err: e.withStderr(err)}
	}
	if res.Status == prober.OutcomeUnsupported {
		return nil, Skipf("harness does not support JWT fetching: %s", res.Message)
	}
	return res, nil
}

// DialVerdict is the SDK's decision on a server certificate when it acts as
// an mTLS client.
type DialVerdict struct {
	Accepted bool
	// ServerID is the server SPIFFE ID the SDK reported (accepted only).
	ServerID string
	// ClientID is the SPIFFE ID of the client certificate the SDK presented,
	// as seen by the suite's server; empty if the handshake did not complete.
	ClientID string
	Message  string
}

// DialFromSDK starts a one-shot TLS server presenting serverSVID, and asks the
// SDK to connect to it as an mTLS client. The server requires a client
// certificate that verifies against the trusted roots.
func (e *TestEnv) DialFromSDK(serverSVID *ca.X509SVIDMaterial) (DialVerdict, error) {
	if e.control == nil {
		return DialVerdict{}, ExecErrorf("harness not started")
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{serverSVID.TLSCertificate()},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    e.roots(),
	})
	if err != nil {
		return DialVerdict{}, ExecErrorf("listen: %v", err)
	}
	defer ln.Close()

	clientID := make(chan string, 1)
	go func() {
		defer close(clientID)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		tc := conn.(*tls.Conn)
		_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
		if err := tc.Handshake(); err != nil {
			return
		}
		if certs := tc.ConnectionState().PeerCertificates; len(certs) > 0 && len(certs[0].URIs) > 0 {
			clientID <- certs[0].URIs[0].String()
		}
	}()

	res, err := e.control.DialX509(ln.Addr().(*net.TCPAddr).String())
	if err != nil {
		return DialVerdict{}, &ExecutionError{Err: e.withStderr(err)}
	}
	ln.Close()
	v := DialVerdict{ServerID: res.SPIFFEID, Message: res.Message, ClientID: <-clientID}
	switch res.Status {
	case prober.OutcomeOK:
		v.Accepted = true
		return v, nil
	case prober.OutcomeRejected:
		return v, nil
	case prober.OutcomeUnsupported:
		return DialVerdict{}, Skipf("harness does not support acting as TLS client: %s", res.Message)
	default:
		return DialVerdict{}, ExecErrorf("harness could not dial: %s", res.Message)
	}
}

func (e *TestEnv) withStderr(err error) error {
	if e.process == nil {
		return err
	}
	tail := strings.TrimSpace(e.process.StderrTail())
	if tail == "" {
		return err
	}
	return fmt.Errorf("%w\n--- harness stderr (tail) ---\n%s", err, tail)
}

func splitArgs(args []string) []string {
	if len(args) == 1 && strings.Contains(args[0], " ") {
		return strings.Fields(args[0])
	}
	return args
}
