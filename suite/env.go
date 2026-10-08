package suite

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

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
	control   *prober.Control // nil for v0 harnesses
	probeCert tls.Certificate // valid client cert for ProbeX509 calls
	trustPool *x509.CertPool  // trust pool built from test CA
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
	// Individual test cases may replace this state after newTestEnv returns.
	defaultX509, err := authority.IssueX509SVID("spiffe://test.example.org/default")
	if err != nil {
		server.Stop()
		cleanup()
		return nil, nil, fmt.Errorf("issue default X.509 SVID: %w", err)
	}
	server.SetX509State(&workloadapi.X509State{
		Materials:   []*ca.X509SVIDMaterial{defaultX509},
		TrustBundle: [][]byte{authority.CACertDER()},
		TrustDomain: authority.TrustDomain(),
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
	server.SetJWTState(&workloadapi.JWTState{
		Materials: []*ca.JWTSVIDMaterial{defaultJWT},
		Bundles:   map[string][]byte{authority.TrustDomain(): defaultJWKS},
	})

	probeSVID, err := authority.IssueX509SVID("spiffe://test.example.org/probe")
	if err != nil {
		server.Stop()
		cleanup()
		return nil, nil, fmt.Errorf("issue probe SVID: %w", err)
	}

	process, err := harness.Start(ctx, harness.Config{
		Cmd:      cmd,
		Args:     splitArgs(args),
		Endpoint: "unix://" + socketPath,
		StdOut:   stdout,
		StdErr:   stderr,
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
	if process.Version() >= 1 {
		env.control = prober.NewControl(process.ControlPort())
	}

	fullCleanup := func() {
		process.Stop()
		server.Stop()
		cleanup()
	}
	return env, fullCleanup, nil
}

// HarnessVersion returns the harness contract version the SDK harness speaks.
func (e *TestEnv) HarnessVersion() int { return e.process.Version() }

// Server returns the mock Workload API server, e.g. to inject errors or
// inspect recorded calls.
func (e *TestEnv) Server() *workloadapi.Server { return e.server }

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
		TrustDomain: e.ca.TrustDomain(),
	})
}

// PushX509Update replaces the X.509 state and triggers a streaming update.
func (e *TestEnv) PushX509Update(materials ...*ca.X509SVIDMaterial) {
	e.ServeX509(materials...)
}

// ServeJWTBundle sets only the JWT bundle in the JWT state, without SVID materials.
func (e *TestEnv) ServeJWTBundle() error {
	jwks, err := e.ca.JWKSBytes()
	if err != nil {
		return fmt.Errorf("build JWKS: %w", err)
	}
	e.server.SetJWTState(&workloadapi.JWTState{
		Bundles: map[string][]byte{e.ca.TrustDomain(): jwks},
	})
	return nil
}

// ServeJWT sets the JWT state so the mock server returns the given materials.
// It automatically populates the JWT bundle from the test CA so the SDK can validate tokens.
func (e *TestEnv) ServeJWT(materials ...*ca.JWTSVIDMaterial) error {
	jwks, err := e.ca.JWKSBytes()
	if err != nil {
		return fmt.Errorf("build JWKS: %w", err)
	}
	e.server.SetJWTState(&workloadapi.JWTState{
		Materials: materials,
		Bundles:   map[string][]byte{e.ca.TrustDomain(): jwks},
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

// ProbeX509 connects to the SDK's X.509 port presenting the suite's valid
// probe SVID. It returns an error if the connection fails or the SDK rejects
// the probe certificate.
func (e *TestEnv) ProbeX509() (*prober.X509ProbeResult, error) {
	return prober.ProbeX509(e.process.X509Port(), e.probeCert, e.trustPool, e.process.Version() >= 1)
}

// ProbeX509WithCert connects to the SDK's X.509 port presenting the given SVID
// as the client certificate. It returns an error if the SDK rejected it.
func (e *TestEnv) ProbeX509WithCert(clientSVID *ca.X509SVIDMaterial) (*prober.X509ProbeResult, error) {
	return prober.ProbeX509(e.process.X509Port(), clientSVID.TLSCertificate(), e.trustPool, e.process.Version() >= 1)
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
		// v0: fixed audience, and no way to tell rejection from error.
		if audience != "conformance" {
			return JWTVerdict{}, Skipf("v0 harnesses only validate for audience %q", "conformance")
		}
		res, err := prober.ProbeJWT(e.process.JWTPort(), token)
		if err != nil {
			return JWTVerdict{}, &ExecutionError{Err: e.withStderr(err)}
		}
		return JWTVerdict{
			Accepted: res.HTTPStatus == 200 && res.Status == "valid",
			SPIFFEID: res.SPIFFEID,
			Message:  res.Message,
		}, nil
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
		return nil, Skipf("JWT fetching requires harness contract v1")
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
// SDK to connect to it as an mTLS client.
func (e *TestEnv) DialFromSDK(serverSVID *ca.X509SVIDMaterial) (DialVerdict, error) {
	if e.control == nil {
		return DialVerdict{}, Skipf("acting as TLS client requires harness contract v1")
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{serverSVID.TLSCertificate()},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    e.trustPool,
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

// X509Port returns the port on which the SDK exposes X.509 SVIDs.
func (e *TestEnv) X509Port() int { return e.process.X509Port() }

func (e *TestEnv) withStderr(err error) error {
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
