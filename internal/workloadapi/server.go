package workloadapi

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"sync"
	"time"

	workloadv1 "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/arndt-s/spiffe-conformance-test-suite/internal/ca"
)

// MethodCall records a single observation of an RPC invocation.
type MethodCall struct {
	Method     string
	At         time.Time
	HeaderSeen bool
}

// Server is a controllable mock SPIFFE Workload API gRPC server.
type Server struct {
	workloadv1.UnimplementedSpiffeWorkloadAPIServer
	grpcServer *grpc.Server
	socketPath string

	mu   sync.RWMutex
	x509 *X509State
	jwt  *JWTState
	// notify is closed and replaced whenever state is updated.
	// Streaming RPCs select on this to detect state changes.
	notify chan struct{}

	// failMode, when set for a method, causes the corresponding RPC
	// to immediately return that gRPC error code instead of serving state.
	// Keyed by RPC method short name: "FetchX509SVID", "FetchX509Bundles",
	// "FetchJWTSVID", "FetchJWTBundles".
	failMode map[string]codes.Code

	// closeStreamOnce, when set, causes the named streaming RPC to send
	// its current state once and then return OK (closing the stream)
	// before the next state change. The flag is cleared after the first use.
	closeStreamOnce map[string]bool

	// calls records every RPC invocation observed by the server.
	calls []MethodCall
}

// NewServer creates a Server that will listen on the given UDS path.
func NewServer(socketPath string) *Server {
	s := &Server{
		socketPath:      socketPath,
		notify:          make(chan struct{}),
		failMode:        make(map[string]codes.Code),
		closeStreamOnce: make(map[string]bool),
	}
	s.grpcServer = grpc.NewServer()
	workloadv1.RegisterSpiffeWorkloadAPIServer(s.grpcServer, s)
	return s
}

// Start begins accepting connections. It returns once the listener is ready.
func (s *Server) Start() error {
	ln, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.socketPath, err)
	}
	go func() { _ = s.grpcServer.Serve(ln) }()
	return nil
}

// Stop gracefully stops the server.
func (s *Server) Stop() {
	s.grpcServer.GracefulStop()
}

// SetX509State atomically replaces the X.509 state and notifies active streams.
func (s *Server) SetX509State(state *X509State) {
	s.mu.Lock()
	s.x509 = state
	old := s.notify
	s.notify = make(chan struct{})
	s.mu.Unlock()
	close(old) // wake streaming goroutines
}

// SetJWTState atomically replaces the JWT state.
func (s *Server) SetJWTState(state *JWTState) {
	s.mu.Lock()
	s.jwt = state
	s.mu.Unlock()
}

// SocketPath returns the UDS path.
func (s *Server) SocketPath() string { return s.socketPath }

// SetFailMode causes the named RPC to return the given gRPC code on every
// subsequent invocation. Pass codes.OK to clear the override.
// Method names: "FetchX509SVID", "FetchX509Bundles", "FetchJWTSVID", "FetchJWTBundles".
func (s *Server) SetFailMode(method string, code codes.Code) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if code == codes.OK {
		delete(s.failMode, method)
		return
	}
	s.failMode[method] = code
}

// CloseStreamOnce flags the named streaming RPC to return cleanly (OK)
// on its next iteration, simulating a server-initiated stream termination.
// The flag clears after one use. The method also wakes any in-flight
// stream waiting on the notify channel so it observes the flag promptly.
func (s *Server) CloseStreamOnce(method string) {
	s.mu.Lock()
	s.closeStreamOnce[method] = true
	old := s.notify
	s.notify = make(chan struct{})
	s.mu.Unlock()
	close(old)
}

// Calls returns a snapshot of every RPC invocation recorded so far.
func (s *Server) Calls() []MethodCall {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]MethodCall, len(s.calls))
	copy(out, s.calls)
	return out
}

// ResetCalls clears the recorded RPC invocation log.
func (s *Server) ResetCalls() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = nil
}

// --- gRPC handler implementations ---

// recordCall logs an invocation and validates the workload metadata header.
// It returns the configured failMode error, if any, after recording.
func (s *Server) recordCall(ctx context.Context, method string) error {
	hdrOK := false
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		vals := md.Get("workload.spiffe.io")
		if len(vals) > 0 && vals[0] == "true" {
			hdrOK = true
		}
	}
	s.mu.Lock()
	s.calls = append(s.calls, MethodCall{Method: method, At: time.Now(), HeaderSeen: hdrOK})
	failCode, hasFail := s.failMode[method]
	s.mu.Unlock()

	if !hdrOK {
		return status.Error(codes.InvalidArgument, "missing workload.spiffe.io:true header")
	}
	if hasFail {
		return status.Error(failCode, "configured fail mode")
	}
	return nil
}

func (s *Server) FetchX509SVID(
	_ *workloadv1.X509SVIDRequest,
	stream workloadv1.SpiffeWorkloadAPI_FetchX509SVIDServer,
) error {
	if err := s.recordCall(stream.Context(), "FetchX509SVID"); err != nil {
		return err
	}

	for {
		s.mu.RLock()
		state := s.x509
		notifyCh := s.notify
		closeOnce := s.closeStreamOnce["FetchX509SVID"]
		s.mu.RUnlock()

		if state != nil {
			resp, err := x509StateToProto(state)
			if err != nil {
				return status.Errorf(codes.Internal, "build response: %v", err)
			}
			if err := stream.Send(resp); err != nil {
				return err
			}
		}

		if closeOnce {
			s.mu.Lock()
			delete(s.closeStreamOnce, "FetchX509SVID")
			s.mu.Unlock()
			return nil
		}

		select {
		case <-stream.Context().Done():
			return nil
		case <-notifyCh:
			// state updated — loop and resend
		}
	}
}

func (s *Server) FetchX509Bundles(
	_ *workloadv1.X509BundlesRequest,
	stream workloadv1.SpiffeWorkloadAPI_FetchX509BundlesServer,
) error {
	if err := s.recordCall(stream.Context(), "FetchX509Bundles"); err != nil {
		return err
	}

	for {
		s.mu.RLock()
		state := s.x509
		notifyCh := s.notify
		closeOnce := s.closeStreamOnce["FetchX509Bundles"]
		s.mu.RUnlock()

		if state != nil {
			bundles := map[string][]byte{}
			for _, m := range state.Materials {
				td := materialTrustDomain(m)
				if td == "" {
					continue
				}
				bundles[td] = state.Corruption.Bundle.Apply(m.CACertDER)
			}
			if err := stream.Send(&workloadv1.X509BundlesResponse{Bundles: bundles}); err != nil {
				return err
			}
		}

		if closeOnce {
			s.mu.Lock()
			delete(s.closeStreamOnce, "FetchX509Bundles")
			s.mu.Unlock()
			return nil
		}

		select {
		case <-stream.Context().Done():
			return nil
		case <-notifyCh:
		}
	}
}

func (s *Server) FetchJWTSVID(
	ctx context.Context,
	req *workloadv1.JWTSVIDRequest,
) (*workloadv1.JWTSVIDResponse, error) {
	if err := s.recordCall(ctx, "FetchJWTSVID"); err != nil {
		return nil, err
	}

	s.mu.RLock()
	state := s.jwt
	s.mu.RUnlock()

	if state == nil {
		return nil, status.Error(codes.NotFound, "no JWT state configured")
	}

	var svids []*workloadv1.JWTSVID
	for _, m := range state.Materials {
		svids = append(svids, &workloadv1.JWTSVID{
			SpiffeId: m.SPIFFEID,
			Svid:     m.Token,
		})
	}
	return &workloadv1.JWTSVIDResponse{Svids: svids}, nil
}

func (s *Server) FetchJWTBundles(
	_ *workloadv1.JWTBundlesRequest,
	stream workloadv1.SpiffeWorkloadAPI_FetchJWTBundlesServer,
) error {
	if err := s.recordCall(stream.Context(), "FetchJWTBundles"); err != nil {
		return err
	}

	s.mu.RLock()
	state := s.jwt
	closeOnce := s.closeStreamOnce["FetchJWTBundles"]
	s.mu.RUnlock()

	bundles := map[string][]byte{}
	if state != nil {
		for td, jwks := range state.JWKSBundle {
			bundles[td] = state.Corruption.JWKSBytes.Apply(jwks)
		}
	}
	if err := stream.Send(&workloadv1.JWTBundlesResponse{Bundles: bundles}); err != nil {
		return err
	}
	if closeOnce {
		s.mu.Lock()
		delete(s.closeStreamOnce, "FetchJWTBundles")
		s.mu.Unlock()
		return nil
	}
	<-stream.Context().Done()
	return nil
}

// ValidateJWTSVID validates a JWT SVID against the current trust bundle.
func (s *Server) ValidateJWTSVID(
	ctx context.Context,
	req *workloadv1.ValidateJWTSVIDRequest,
) (*workloadv1.ValidateJWTSVIDResponse, error) {
	return nil, status.Error(codes.Unimplemented, "ValidateJWTSVID not implemented")
}

// x509StateToProto converts X509State to the wire proto, applying any
// configured per-field corruption overrides.
func x509StateToProto(state *X509State) (*workloadv1.X509SVIDResponse, error) {
	var svids []*workloadv1.X509SVID
	for i, m := range state.Materials {
		der, err := encodePrivateKey(m)
		if err != nil {
			return nil, err
		}
		bundle := m.CACertDER
		if len(state.TrustBundle) > 0 {
			var flat []byte
			for _, b := range state.TrustBundle {
				flat = append(flat, b...)
			}
			bundle = flat
		}
		hint := materialTrustDomain(m)
		if i < len(state.HintOverrides) && state.HintOverrides[i] != "" {
			hint = state.HintOverrides[i]
		}
		svids = append(svids, &workloadv1.X509SVID{
			SpiffeId:    m.SPIFFEID,
			X509Svid:    state.Corruption.SVIDBytes.Apply(flattenDER(m.CertChainDER())),
			X509SvidKey: state.Corruption.KeyBytes.Apply(der),
			Bundle:      state.Corruption.Bundle.Apply(bundle),
			Hint:        hint,
		})
	}
	return &workloadv1.X509SVIDResponse{Svids: svids}, nil
}

// materialTrustDomain returns the trust-domain host for an X.509 SVID
// material, preferring the CA cert's URI SAN and falling back to the
// SPIFFE ID's host. Returns "" if neither is parseable.
func materialTrustDomain(m *ca.X509SVIDMaterial) string {
	if m.CACert != nil && len(m.CACert.URIs) > 0 {
		return m.CACert.URIs[0].Host
	}
	if u, err := url.Parse(m.SPIFFEID); err == nil {
		return u.Host
	}
	return ""
}

func flattenDER(chain [][]byte) []byte {
	var out []byte
	for _, d := range chain {
		out = append(out, d...)
	}
	return out
}

func encodePrivateKey(m interface{ KeyDER() ([]byte, error) }) ([]byte, error) {
	return m.KeyDER()
}
