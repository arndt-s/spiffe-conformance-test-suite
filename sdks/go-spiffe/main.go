// Command go-spiffe is the conformance harness for go-spiffe v2. It implements
// harness contract v1 (docs/HARNESS_CONTRACT.md) using only go-spiffe's
// idiomatic APIs: workloadapi sources, spiffetls/tlsconfig and jwtsvid.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

func main() {
	log.SetOutput(os.Stderr)
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer cancel()

	// The client discovers the endpoint from SPIFFE_ENDPOINT_SOCKET.
	client, err := workloadapi.New(ctx)
	if err != nil {
		log.Fatalf("create Workload API client: %v", err)
	}
	defer client.Close()

	// Blocks until the first X.509-SVID has been received.
	x509Source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClient(client))
	if err != nil {
		log.Fatalf("create X509Source: %v", err)
	}
	defer x509Source.Close()

	// The JWT source is created lazily so that a missing JWT bundle does not
	// prevent X.509 tests from running.
	jwtSources := newLazyJWTSource(client)
	defer jwtSources.Close()

	x509Ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("listen X.509: %v", err)
	}
	controlLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("listen control: %v", err)
	}

	go serveX509(tls.NewListener(x509Ln, tlsconfig.MTLSServerConfig(x509Source, x509Source, tlsconfig.AuthorizeAny())))

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/jwt/validate", handleValidate(jwtSources))
	mux.HandleFunc("POST /v1/jwt/fetch", handleFetch(client))
	mux.HandleFunc("POST /v1/x509/dial", handleDial(x509Source))
	mux.HandleFunc("GET /v1/info", handleInfo)
	controlServer := &http.Server{Handler: mux}
	go func() { _ = controlServer.Serve(controlLn) }()

	fmt.Println("SPIFFE_HARNESS_VERSION=1")
	fmt.Printf("SPIFFE_X509_PORT=%d\n", x509Ln.Addr().(*net.TCPAddr).Port)
	fmt.Printf("SPIFFE_CONTROL_PORT=%d\n", controlLn.Addr().(*net.TCPAddr).Port)
	fmt.Println("READY")

	<-ctx.Done()
	_ = controlServer.Close()
	_ = x509Ln.Close()
}

// serveX509 completes the mTLS handshake (go-spiffe authenticates the client
// against the bundle for its trust domain), writes the client's SPIFFE ID and
// closes the connection.
func serveX509(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func(conn *tls.Conn) {
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
			if err := conn.Handshake(); err != nil {
				log.Printf("X.509 handshake rejected: %v", err)
				return
			}
			id, err := x509svid.IDFromCert(conn.ConnectionState().PeerCertificates[0])
			if err != nil {
				log.Printf("peer ID: %v", err)
				return
			}
			_, _ = conn.Write([]byte(id.String() + "\n"))
		}(conn.(*tls.Conn))
	}
}

func handleValidate(sources *lazyJWTSource) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Token    string `json:"token"`
			Audience string `json:"audience"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			reply(w, http.StatusInternalServerError, "error", fmt.Sprintf("bad request: %v", err), nil)
			return
		}
		source, err := sources.Get(r.Context())
		if err != nil {
			reply(w, http.StatusInternalServerError, "error", fmt.Sprintf("JWT source: %v", err), nil)
			return
		}
		svid, err := jwtsvid.ParseAndValidate(req.Token, source, []string{req.Audience})
		if err != nil {
			reply(w, http.StatusUnprocessableEntity, "rejected", err.Error(), nil)
			return
		}
		reply(w, http.StatusOK, "ok", "", map[string]any{"spiffe_id": svid.ID.String(), "claims": svid.Claims})
	}
}

func handleFetch(client *workloadapi.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Audience []string `json:"audience"`
			SPIFFEID string   `json:"spiffe_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Audience) == 0 {
			reply(w, http.StatusInternalServerError, "error", "bad request: audience required", nil)
			return
		}
		params := jwtsvid.Params{Audience: req.Audience[0], ExtraAudiences: req.Audience[1:]}
		if req.SPIFFEID != "" {
			id, err := spiffeid.FromString(req.SPIFFEID)
			if err != nil {
				reply(w, http.StatusInternalServerError, "error", fmt.Sprintf("bad spiffe_id: %v", err), nil)
				return
			}
			params.Subject = id
		}
		svids, err := client.FetchJWTSVIDs(r.Context(), params)
		if err != nil {
			reply(w, http.StatusInternalServerError, "error", err.Error(), nil)
			return
		}
		out := make([]map[string]string, 0, len(svids))
		for _, s := range svids {
			out = append(out, map[string]string{"spiffe_id": s.ID.String(), "token": s.Marshal(), "hint": s.Hint})
		}
		reply(w, http.StatusOK, "ok", "", map[string]any{"svids": out})
	}
}

func handleDial(source *workloadapi.X509Source) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Address string `json:"address"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			reply(w, http.StatusInternalServerError, "error", fmt.Sprintf("bad request: %v", err), nil)
			return
		}
		raw, err := net.DialTimeout("tcp", req.Address, 5*time.Second)
		if err != nil {
			reply(w, http.StatusInternalServerError, "error", err.Error(), nil)
			return
		}
		conn := tls.Client(raw, tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeAny()))
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if err := conn.Handshake(); err != nil {
			reply(w, http.StatusUnprocessableEntity, "rejected", err.Error(), nil)
			return
		}
		id, err := x509svid.IDFromCert(conn.ConnectionState().PeerCertificates[0])
		if err != nil {
			reply(w, http.StatusUnprocessableEntity, "rejected", err.Error(), nil)
			return
		}
		reply(w, http.StatusOK, "ok", "", map[string]any{"spiffe_id": id.String()})
	}
}

func handleInfo(w http.ResponseWriter, _ *http.Request) {
	version := "unknown"
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range bi.Deps {
			if dep.Path == "github.com/spiffe/go-spiffe/v2" {
				version = dep.Version
			}
		}
	}
	reply(w, http.StatusOK, "ok", "", map[string]any{"sdk": "go-spiffe", "sdk_version": version, "language": "go"})
}

func reply(w http.ResponseWriter, code int, status, message string, fields map[string]any) {
	body := map[string]any{"status": status}
	if message != "" {
		body["message"] = message
	}
	for k, v := range fields {
		body[k] = v
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

// lazyJWTSource creates a workloadapi.JWTSource on first use and reuses it.
type lazyJWTSource struct {
	client *workloadapi.Client
	source *workloadapi.JWTSource
	ready  chan struct{}
	err    error
	start  chan struct{}
}

func newLazyJWTSource(client *workloadapi.Client) *lazyJWTSource {
	l := &lazyJWTSource{client: client, ready: make(chan struct{}), start: make(chan struct{}, 1)}
	l.start <- struct{}{}
	return l
}

func (l *lazyJWTSource) Get(ctx context.Context) (*workloadapi.JWTSource, error) {
	select {
	case <-l.start:
		go func() {
			l.source, l.err = workloadapi.NewJWTSource(context.Background(), workloadapi.WithClient(l.client))
			close(l.ready)
		}()
	default:
	}
	select {
	case <-l.ready:
		return l.source, l.err
	case <-ctx.Done():
		return nil, errors.New("timed out waiting for the first JWT bundle")
	}
}

func (l *lazyJWTSource) Close() {
	select {
	case <-l.ready:
		if l.source != nil {
			_ = l.source.Close()
		}
	default:
	}
}
