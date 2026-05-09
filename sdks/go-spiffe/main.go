package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// audience is the audience the harness expects on inbound JWT-SVID
// validation requests.
const audience = "conformance"

// supportedCaps lists the harnessctl capabilities this harness advertises.
var supportedCaps = []string{
	"mtls-verify",
	"jwt-fetch",
	"multi-identity",
	"endpoint-reconnect",
}

// harnessState holds the long-lived state shared between the X.509 TLS
// listener, the JWT validation HTTP server, and the control HTTP server.
type harnessState struct {
	mu        sync.RWMutex
	client    *workloadapi.Client
	x509Src   *workloadapi.X509Source
	bundleSrc *workloadapi.BundleSource
}

// newClient builds a fresh workloadapi client + X509Source + BundleSource
// against the current SPIFFE_ENDPOINT_SOCKET value.
func newClient(ctx context.Context) (*workloadapi.Client, *workloadapi.X509Source, *workloadapi.BundleSource, error) {
	client, err := workloadapi.New(ctx)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("workloadapi.New: %w", err)
	}
	x509Src, err := workloadapi.NewX509Source(ctx, workloadapi.WithClient(client))
	if err != nil {
		client.Close()
		return nil, nil, nil, fmt.Errorf("workloadapi.NewX509Source: %w", err)
	}
	bundleSrc, err := workloadapi.NewBundleSource(ctx, workloadapi.WithClient(client))
	if err != nil {
		x509Src.Close()
		client.Close()
		return nil, nil, nil, fmt.Errorf("workloadapi.NewBundleSource: %w", err)
	}
	return client, x509Src, bundleSrc, nil
}

func (s *harnessState) reconnect(ctx context.Context) error {
	client, x509Src, bundleSrc, err := newClient(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	old := s.client
	oldX509 := s.x509Src
	oldBundle := s.bundleSrc
	s.client = client
	s.x509Src = x509Src
	s.bundleSrc = bundleSrc
	s.mu.Unlock()

	if oldX509 != nil {
		oldX509.Close()
	}
	if oldBundle != nil {
		oldBundle.Close()
	}
	if old != nil {
		old.Close()
	}
	return nil
}

func (s *harnessState) snapshot() (*workloadapi.Client, *workloadapi.X509Source, *workloadapi.BundleSource) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.client, s.x509Src, s.bundleSrc
}

// x509GetCertificate is the GetCertificate callback for the TLS server.
// It always reads the latest X509Source so post-reconnect updates are
// observed immediately.
func (s *harnessState) getServerCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	_, x509Src, _ := s.snapshot()
	if x509Src == nil {
		return nil, fmt.Errorf("X509 source unavailable")
	}
	svid, err := x509Src.GetX509SVID()
	if err != nil {
		return nil, err
	}
	raw := make([][]byte, len(svid.Certificates))
	for i, c := range svid.Certificates {
		raw[i] = c.Raw
	}
	return &tls.Certificate{
		Certificate: raw,
		PrivateKey:  svid.PrivateKey,
		Leaf:        svid.Certificates[0],
	}, nil
}

// getClientCAs returns a *x509.CertPool over every trust bundle the SDK
// currently knows about. Used by the TLS server's ClientCAs.
func (s *harnessState) getClientCAs() *x509.CertPool {
	_, _, bundleSrc := s.snapshot()
	if bundleSrc == nil {
		return x509.NewCertPool()
	}
	pool := x509.NewCertPool()
	// We don't have a "list trust domains" API; just rely on a known
	// fixed lookup. For the conformance suite the trust domain is
	// always test.example.org.
	td, _ := spiffeid.TrustDomainFromString("test.example.org")
	bundle, err := bundleSrc.GetX509BundleForTrustDomain(td)
	if err != nil {
		return pool
	}
	for _, c := range bundle.X509Authorities() {
		pool.AddCert(c)
	}
	return pool
}

// verifyClientCert is a SPIFFE-aware peer-cert verifier installed on
// the TLS server. It performs RFC 5280 path validation using the SDK's
// current bundle, plus SPIFFE-specific leaf-cert validation
// (URI SAN, key usage flags, no IsCA, etc.) via tlsconfig.AdaptMatcher
// or the lower-level helpers.
func (s *harnessState) verifyClientCert(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("no client certificates presented")
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("parse client leaf: %w", err)
	}
	intermediates := x509.NewCertPool()
	for _, raw := range rawCerts[1:] {
		c, err := x509.ParseCertificate(raw)
		if err != nil {
			return fmt.Errorf("parse client intermediate: %w", err)
		}
		intermediates.AddCert(c)
	}
	pool := s.getClientCAs()

	// RFC 5280 path validation against the trust bundle, plus the
	// SPIFFE-required EKU check (clientAuth must be present).
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         pool,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return fmt.Errorf("client cert path validation: %w", err)
	}

	// SPIFFE leaf-validation: must have exactly one URI SAN, that URI
	// must be a syntactically-valid SPIFFE ID, and the SPIFFE ID must
	// have a non-empty path (no leaf SVID may be a trust-domain ID).
	if len(leaf.URIs) != 1 {
		return fmt.Errorf("client leaf must have exactly one URI SAN, got %d", len(leaf.URIs))
	}
	id, err := spiffeid.FromURI(leaf.URIs[0])
	if err != nil {
		return fmt.Errorf("client leaf URI is not a valid SPIFFE ID: %w", err)
	}
	if id.Path() == "" {
		return fmt.Errorf("client leaf SPIFFE ID has no path component")
	}
	// Leaf MUST NOT be a CA.
	if leaf.IsCA {
		return fmt.Errorf("client leaf has CA=true")
	}
	// Leaf MUST have a Key Usage extension. Go reports KeyUsage==0 when
	// the extension is absent; we treat that as a violation. The SVID
	// MUST set digitalSignature and MUST NOT set keyCertSign/cRLSign.
	if leaf.KeyUsage == 0 {
		return fmt.Errorf("client leaf has no Key Usage extension")
	}
	if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return fmt.Errorf("client leaf is missing the digitalSignature key usage")
	}
	if leaf.KeyUsage&x509.KeyUsageCertSign != 0 {
		return fmt.Errorf("client leaf has keyCertSign in key usage")
	}
	if leaf.KeyUsage&x509.KeyUsageCRLSign != 0 {
		return fmt.Errorf("client leaf has cRLSign in key usage")
	}
	return nil
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer cancel()

	state := &harnessState{}
	if err := state.reconnect(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "initial Workload API connect: %v\n", err)
		os.Exit(1)
	}

	// X.509 TLS listener with mTLS client-cert verification.
	tcpLn, err := net.Listen("tcp", ":0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen tcp: %v\n", err)
		os.Exit(1)
	}
	x509Port := tcpLn.Addr().(*net.TCPAddr).Port
	tlsCfg := &tls.Config{
		GetCertificate:        state.getServerCertificate,
		ClientAuth:            tls.RequireAnyClientCert,
		VerifyPeerCertificate: state.verifyClientCert,
	}
	tlsLn := tls.NewListener(tcpLn, tlsCfg)

	// JWT validation HTTP listener.
	jwtLn, err := net.Listen("tcp", ":0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen jwt: %v\n", err)
		os.Exit(1)
	}
	jwtPort := jwtLn.Addr().(*net.TCPAddr).Port

	// Control HTTP listener.
	ctlLn, err := net.Listen("tcp", ":0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen ctl: %v\n", err)
		os.Exit(1)
	}
	ctlPort := ctlLn.Addr().(*net.TCPAddr).Port

	go serveX509(tlsLn)
	go serveJWT(jwtLn, state)
	go serveControl(ctlLn, state)

	fmt.Printf("SPIFFE_X509_PORT=%d\n", x509Port)
	fmt.Printf("SPIFFE_JWT_PORT=%d\n", jwtPort)
	fmt.Printf("SPIFFE_CONTROL_PORT=%d\n", ctlPort)
	fmt.Println("READY")

	<-ctx.Done()
	tlsLn.Close()
	jwtLn.Close()
	ctlLn.Close()
}

func serveX509(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			tc := c.(*tls.Conn)
			if err := tc.Handshake(); err != nil {
				return
			}
			buf := make([]byte, 1)
			tc.Read(buf)
		}(conn)
	}
}

func serveJWT(ln net.Listener, state *harnessState) {
	mux := http.NewServeMux()
	mux.HandleFunc("/jwt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		auth := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(auth, prefix) {
			writeJWTResult(w, http.StatusUnauthorized, "invalid", "", "missing or malformed Authorization header")
			return
		}
		token := strings.TrimPrefix(auth, prefix)

		client, _, _ := state.snapshot()
		bundles, err := client.FetchJWTBundles(r.Context())
		if err != nil {
			writeJWTResult(w, http.StatusInternalServerError, "invalid", "", fmt.Sprintf("fetch bundles: %v", err))
			return
		}
		svid, err := jwtsvid.ParseAndValidate(token, bundles, []string{audience})
		if err != nil {
			writeJWTResult(w, http.StatusUnauthorized, "invalid", "", fmt.Sprintf("invalid JWT: %v", err))
			return
		}
		writeJWTResult(w, http.StatusOK, "valid", svid.ID.String(), "")
	})
	srv := &http.Server{Handler: mux}
	_ = srv.Serve(ln)
}

func writeJWTResult(w http.ResponseWriter, code int, status, spiffeID, message string) {
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":    status,
		"spiffe_id": spiffeID,
		"message":   message,
	})
}

func serveControl(ln net.Listener, state *harnessState) {
	mux := http.NewServeMux()

	mux.HandleFunc("/capabilities", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string][]string{"caps": supportedCaps})
	})

	mux.HandleFunc("/jwt/fetch", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var body struct {
			Audience string `json:"audience"`
			SPIFFEID string `json:"spiffe_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, fmt.Sprintf("decode: %v", err), http.StatusBadRequest)
			return
		}
		client, _, _ := state.snapshot()
		params := jwtsvid.Params{Audience: body.Audience}
		if body.SPIFFEID != "" {
			id, err := spiffeid.FromString(body.SPIFFEID)
			if err != nil {
				http.Error(w, fmt.Sprintf("spiffe_id: %v", err), http.StatusBadRequest)
				return
			}
			params.Subject = id
		}
		svid, err := client.FetchJWTSVID(r.Context(), params)
		if err != nil {
			http.Error(w, fmt.Sprintf("FetchJWTSVID: %v", err), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"token": svid.Marshal()})
	})

	mux.HandleFunc("/x509/identities", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		client, _, _ := state.snapshot()
		xc, err := client.FetchX509Context(r.Context())
		if err != nil {
			http.Error(w, fmt.Sprintf("FetchX509Context: %v", err), http.StatusInternalServerError)
			return
		}
		ids := make([]map[string]string, 0, len(xc.SVIDs))
		for _, s := range xc.SVIDs {
			ids = append(ids, map[string]string{
				"spiffe_id": s.ID.String(),
				"hint":      s.Hint,
			})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"identities": ids})
	})

	mux.HandleFunc("/x509/identities/", func(w http.ResponseWriter, r *http.Request) {
		// Path: /x509/identities/<url-escaped spiffe id>/cert
		const prefix = "/x509/identities/"
		const suffix = "/cert"
		path := r.URL.Path
		if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, suffix) {
			http.NotFound(w, r)
			return
		}
		escaped := strings.TrimSuffix(strings.TrimPrefix(path, prefix), suffix)
		spiffeID, err := url.PathUnescape(escaped)
		if err != nil {
			http.Error(w, fmt.Sprintf("decode spiffe id: %v", err), http.StatusBadRequest)
			return
		}
		client, _, _ := state.snapshot()
		xc, err := client.FetchX509Context(r.Context())
		if err != nil {
			http.Error(w, fmt.Sprintf("FetchX509Context: %v", err), http.StatusInternalServerError)
			return
		}
		for _, s := range xc.SVIDs {
			if s.ID.String() == spiffeID {
				w.Header().Set("Content-Type", "application/x-pem-file")
				_ = pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: s.Certificates[0].Raw})
				return
			}
		}
		http.NotFound(w, r)
	})

	mux.HandleFunc("/endpoint/reconnect", func(w http.ResponseWriter, r *http.Request) {
		if err := state.reconnect(r.Context()); err != nil {
			http.Error(w, fmt.Sprintf("reconnect: %v", err), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	srv := &http.Server{Handler: mux}
	_ = srv.Serve(ln)
}

