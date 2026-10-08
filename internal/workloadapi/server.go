package workloadapi

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	workloadv1 "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

// RPC method names, as used by InjectError and recorded in Call.Method.
const (
	MethodFetchX509SVID    = "FetchX509SVID"
	MethodFetchX509Bundles = "FetchX509Bundles"
	MethodFetchJWTSVID     = "FetchJWTSVID"
	MethodFetchJWTBundles  = "FetchJWTBundles"
	MethodValidateJWTSVID  = "ValidateJWTSVID"
)

// Call records one RPC received by the server.
type Call struct {
	Method string
	Time   time.Time
	// HasHeader reports whether the request carried "workload.spiffe.io: true".
	HasHeader bool
	// Request is the request message.
	Request proto.Message
	// Code is the status the server answered with at the start of the call
	// (codes.OK when the call was accepted).
	Code codes.Code
}

type fault struct {
	code      codes.Code
	remaining int // < 0 means unlimited
}

// Server is a controllable mock SPIFFE Workload API gRPC server.
type Server struct {
	workloadv1.UnimplementedSpiffeWorkloadAPIServer
	grpcServer *grpc.Server
	network    string
	address    string

	mu   sync.Mutex
	x509 *X509State
	jwt  *JWTState
	// x509Notify and jwtNotify are closed and replaced whenever the
	// corresponding state changes; streaming RPCs wait on them.
	x509Notify chan struct{}
	jwtNotify  chan struct{}
	// kill is closed and replaced by CloseStreams.
	kill     chan struct{}
	killCode codes.Code
	faults   map[string]*fault
	calls    []Call
}

// NewServer creates a Server that will listen on the given UDS path.
func NewServer(socketPath string) *Server {
	return newServer("unix", socketPath)
}

// NewTCPServer creates a Server that will listen on the given TCP address
// (e.g. "127.0.0.1:0").
func NewTCPServer(address string) *Server {
	return newServer("tcp", address)
}

func newServer(network, address string) *Server {
	s := &Server{
		network:    network,
		address:    address,
		x509Notify: make(chan struct{}),
		jwtNotify:  make(chan struct{}),
		kill:       make(chan struct{}),
		faults:     map[string]*fault{},
	}
	s.grpcServer = grpc.NewServer()
	workloadv1.RegisterSpiffeWorkloadAPIServer(s.grpcServer, s)
	return s
}

// Start begins accepting connections. It returns once the listener is ready.
func (s *Server) Start() error {
	ln, err := net.Listen(s.network, s.address)
	if err != nil {
		return fmt.Errorf("listen %s %s: %w", s.network, s.address, err)
	}
	s.address = ln.Addr().String()
	go func() { _ = s.grpcServer.Serve(ln) }()
	return nil
}

// Stop stops the server immediately, terminating open streams.
func (s *Server) Stop() {
	s.grpcServer.Stop()
}

// SocketPath returns the listen address: the UDS path, or host:port for TCP.
func (s *Server) SocketPath() string { return s.address }

// SetX509State atomically replaces the X.509 state and notifies active streams.
func (s *Server) SetX509State(state *X509State) {
	s.mu.Lock()
	s.x509 = state
	close(s.x509Notify)
	s.x509Notify = make(chan struct{})
	s.mu.Unlock()
}

// SetJWTState atomically replaces the JWT state and notifies active
// FetchJWTBundles streams.
func (s *Server) SetJWTState(state *JWTState) {
	s.mu.Lock()
	s.jwt = state
	close(s.jwtNotify)
	s.jwtNotify = make(chan struct{})
	s.mu.Unlock()
}

// InjectError makes the next count calls to method fail with code. A negative
// count fails every call until ClearErrors is called.
func (s *Server) InjectError(method string, code codes.Code, count int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.faults[method] = &fault{code: code, remaining: count}
}

// ClearErrors removes all injected errors.
func (s *Server) ClearErrors() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.faults = map[string]*fault{}
}

// CloseStreams terminates every open stream with the given status code.
// Streams opened afterwards are unaffected.
func (s *Server) CloseStreams(code codes.Code) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.killCode = code
	close(s.kill)
	s.kill = make(chan struct{})
}

// Calls returns a snapshot of every RPC received so far.
func (s *Server) Calls() []Call {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Call, len(s.calls))
	copy(out, s.calls)
	return out
}

// begin records the call and decides whether to accept it: it checks the
// mandatory security header (Workload Endpoint §3) and applies injected faults.
func (s *Server) begin(ctx context.Context, method string, req proto.Message) error {
	hasHeader := false
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		vals := md.Get("workload.spiffe.io")
		hasHeader = len(vals) > 0 && vals[0] == "true"
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var err error
	switch f := s.faults[method]; {
	case !hasHeader:
		err = status.Error(codes.InvalidArgument, "missing workload.spiffe.io:true header")
	case f != nil && f.remaining != 0:
		if f.remaining > 0 {
			f.remaining--
		}
		err = status.Errorf(f.code, "injected %s", f.code)
	}

	s.calls = append(s.calls, Call{
		Method:    method,
		Time:      time.Now(),
		HasHeader: hasHeader,
		Request:   req,
		Code:      status.Code(err),
	})
	return err
}

// stream runs a server-streaming RPC: it sends the current response, then
// waits for a state change, the client going away, or CloseStreams. send
// returns false if there is nothing to send yet.
func (s *Server) stream(ctx context.Context, notifyOf func() chan struct{}, send func() (bool, error)) error {
	for {
		s.mu.Lock()
		notify := notifyOf()
		kill := s.kill
		s.mu.Unlock()

		if _, err := send(); err != nil {
			return err
		}

		select {
		case <-ctx.Done():
			return nil
		case <-notify:
		case <-kill:
			s.mu.Lock()
			code := s.killCode
			s.mu.Unlock()
			return status.Error(code, "stream closed by test")
		}
	}
}

func (s *Server) x509Snapshot() *X509State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.x509
}

func (s *Server) jwtSnapshot() *JWTState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.jwt
}

// --- gRPC handler implementations ---

func (s *Server) FetchX509SVID(
	req *workloadv1.X509SVIDRequest,
	stream workloadv1.SpiffeWorkloadAPI_FetchX509SVIDServer,
) error {
	if err := s.begin(stream.Context(), MethodFetchX509SVID, req); err != nil {
		return err
	}
	return s.stream(stream.Context(), func() chan struct{} { return s.x509Notify }, func() (bool, error) {
		state := s.x509Snapshot()
		if state == nil {
			return false, nil
		}
		resp, err := x509StateToProto(state)
		if err != nil {
			return false, status.Errorf(codes.Internal, "build response: %v", err)
		}
		return true, stream.Send(resp)
	})
}

func (s *Server) FetchX509Bundles(
	req *workloadv1.X509BundlesRequest,
	stream workloadv1.SpiffeWorkloadAPI_FetchX509BundlesServer,
) error {
	if err := s.begin(stream.Context(), MethodFetchX509Bundles, req); err != nil {
		return err
	}
	return s.stream(stream.Context(), func() chan struct{} { return s.x509Notify }, func() (bool, error) {
		state := s.x509Snapshot()
		if state == nil {
			return false, nil
		}
		bundles := map[string][]byte{}
		if td := trustDomainOf(state); td != "" {
			bundles[td] = ownBundle(state)
		}
		for td, certs := range state.FederatedBundles {
			bundles[td] = bytes.Join(certs, nil)
		}
		return true, stream.Send(&workloadv1.X509BundlesResponse{Bundles: bundles})
	})
}

func (s *Server) FetchJWTSVID(
	ctx context.Context,
	req *workloadv1.JWTSVIDRequest,
) (*workloadv1.JWTSVIDResponse, error) {
	if err := s.begin(ctx, MethodFetchJWTSVID, req); err != nil {
		return nil, err
	}
	if len(req.Audience) == 0 {
		return nil, status.Error(codes.InvalidArgument, "audience must be specified")
	}

	state := s.jwtSnapshot()
	var svids []*workloadv1.JWTSVID
	if state != nil {
		for _, m := range state.Materials {
			if req.SpiffeId != "" && req.SpiffeId != m.SPIFFEID {
				continue
			}
			svids = append(svids, &workloadv1.JWTSVID{SpiffeId: m.SPIFFEID, Svid: m.Token})
		}
	}
	if len(svids) == 0 {
		return nil, status.Error(codes.PermissionDenied, "no JWT-SVIDs available")
	}
	return &workloadv1.JWTSVIDResponse{Svids: svids}, nil
}

func (s *Server) FetchJWTBundles(
	req *workloadv1.JWTBundlesRequest,
	stream workloadv1.SpiffeWorkloadAPI_FetchJWTBundlesServer,
) error {
	if err := s.begin(stream.Context(), MethodFetchJWTBundles, req); err != nil {
		return err
	}
	return s.stream(stream.Context(), func() chan struct{} { return s.jwtNotify }, func() (bool, error) {
		state := s.jwtSnapshot()
		if state == nil {
			return false, nil
		}
		bundles := make(map[string][]byte, len(state.Bundles))
		for td, jwks := range state.Bundles {
			bundles[td] = jwks
		}
		return true, stream.Send(&workloadv1.JWTBundlesResponse{Bundles: bundles})
	})
}

// ValidateJWTSVID validates a JWT-SVID against the current JWT bundles. It
// delegates to go-spiffe, so SDKs that use this RPC are only as well tested as
// go-spiffe's validator; the suite flags such runs as delegated.
func (s *Server) ValidateJWTSVID(
	ctx context.Context,
	req *workloadv1.ValidateJWTSVIDRequest,
) (*workloadv1.ValidateJWTSVIDResponse, error) {
	if err := s.begin(ctx, MethodValidateJWTSVID, req); err != nil {
		return nil, err
	}
	if req.Audience == "" || req.Svid == "" {
		return nil, status.Error(codes.InvalidArgument, "audience and svid are required")
	}

	set := jwtbundle.NewSet()
	if state := s.jwtSnapshot(); state != nil {
		for tdStr, jwks := range state.Bundles {
			td, err := spiffeid.TrustDomainFromString(tdStr)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "bad trust domain %q in state: %v", tdStr, err)
			}
			b, err := jwtbundle.Parse(td, jwks)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "bad JWKS for %q in state: %v", tdStr, err)
			}
			set.Add(b)
		}
	}

	svid, err := jwtsvid.ParseAndValidate(req.Svid, set, []string{req.Audience})
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid JWT-SVID: %v", err)
	}
	claims, err := structpb.NewStruct(svid.Claims)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "convert claims: %v", err)
	}
	return &workloadv1.ValidateJWTSVIDResponse{SpiffeId: svid.ID.String(), Claims: claims}, nil
}

// x509StateToProto converts X509State to the wire proto.
func x509StateToProto(state *X509State) (*workloadv1.X509SVIDResponse, error) {
	bundle := ownBundle(state)
	var svids []*workloadv1.X509SVID
	for _, m := range state.Materials {
		key, err := m.KeyDER()
		if err != nil {
			return nil, err
		}
		svids = append(svids, &workloadv1.X509SVID{
			SpiffeId:    m.SPIFFEID,
			X509Svid:    bytes.Join(m.CertChainDER(), nil),
			X509SvidKey: key,
			Bundle:      bundle,
			Hint:        m.Hint,
		})
	}
	var federated map[string][]byte
	if len(state.FederatedBundles) > 0 {
		federated = make(map[string][]byte, len(state.FederatedBundles))
		for td, certs := range state.FederatedBundles {
			federated[td] = bytes.Join(certs, nil)
		}
	}
	return &workloadv1.X509SVIDResponse{Svids: svids, FederatedBundles: federated}, nil
}

// ownBundle returns the concatenated DER of the workload's own trust bundle.
func ownBundle(state *X509State) []byte {
	if len(state.TrustBundle) > 0 {
		return bytes.Join(state.TrustBundle, nil)
	}
	if len(state.Materials) > 0 {
		return state.Materials[0].CACertDER
	}
	return nil
}

// trustDomainOf returns the SPIFFE ID of the workload's own trust domain.
func trustDomainOf(state *X509State) string {
	if state.TrustDomain != "" {
		return state.TrustDomain
	}
	if len(state.Materials) == 0 {
		return ""
	}
	u, err := url.Parse(state.Materials[0].SPIFFEID)
	if err != nil || u.Host == "" {
		return ""
	}
	return "spiffe://" + u.Host
}
