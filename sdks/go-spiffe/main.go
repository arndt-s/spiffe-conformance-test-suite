package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

func tlsCertFromSVID(svid *x509svid.SVID) *tls.Certificate {
	raw := make([][]byte, len(svid.Certificates))
	for i, c := range svid.Certificates {
		raw[i] = c.Raw
	}
	return &tls.Certificate{
		Certificate: raw,
		PrivateKey:  svid.PrivateKey,
		Leaf:        svid.Certificates[0],
	}
}

func certFromSource(src *workloadapi.X509Source) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
		svid, err := src.GetX509SVID()
		if err != nil {
			return nil, err
		}
		return tlsCertFromSVID(svid), nil
	}
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer cancel()

	audience := "conformance"

	client, err := workloadapi.New(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create workload API client: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()

	x509Source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClient(client))
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create X509Source: %v\n", err)
		os.Exit(1)
	}
	defer x509Source.Close()

	// X.509 TLS listener
	tcpLn, err := net.Listen("tcp", ":0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to listen on TCP: %v\n", err)
		os.Exit(1)
	}
	x509Port := tcpLn.Addr().(*net.TCPAddr).Port
	tlsLn := tls.NewListener(tcpLn, &tls.Config{
		GetCertificate: certFromSource(x509Source),
	})

	// JWT HTTP listener
	httpLn, err := net.Listen("tcp", ":0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to listen for HTTP: %v\n", err)
		os.Exit(1)
	}
	jwtPort := httpLn.Addr().(*net.TCPAddr).Port

	mux := http.NewServeMux()
	mux.HandleFunc("/jwt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Extract JWT from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			fmt.Fprintf(os.Stderr, "JWT validation failed: missing Authorization header\n")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"status":    "invalid",
				"spiffe_id": "",
				"message":   "missing Authorization header",
			})
			return
		}

		// Expect "Bearer <token>" format
		const prefix = "Bearer "
		if !strings.HasPrefix(authHeader, prefix) {
			fmt.Fprintf(os.Stderr, "JWT validation failed: invalid Authorization header format\n")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"status":    "invalid",
				"spiffe_id": "",
				"message":   "invalid Authorization header format",
			})
			return
		}

		token := strings.TrimPrefix(authHeader, prefix)
		if token == "" {
			fmt.Fprintf(os.Stderr, "JWT validation failed: empty token\n")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"status":    "invalid",
				"spiffe_id": "",
				"message":   "empty token",
			})
			return
		}

		// Fetch JWT bundles and validate
		bundles, err := client.FetchJWTBundles(r.Context())
		if err != nil {
			fmt.Fprintf(os.Stderr, "JWT validation failed: failed to fetch JWT bundles: %v\n", err)
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"status":    "invalid",
				"spiffe_id": "",
				"message":   fmt.Sprintf("failed to fetch JWT bundles: %v", err),
			})
			return
		}

		// Parse and validate the JWT
		svid, err := jwtsvid.ParseAndValidate(token, bundles, []string{audience})
		if err != nil {
			fmt.Fprintf(os.Stderr, "JWT validation failed: invalid JWT: %v\n", err)
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"status":    "invalid",
				"spiffe_id": "",
				"message":   fmt.Sprintf("invalid JWT: %v", err),
			})
			return
		}

		fmt.Printf("Validated JWT for SPIFFE ID: %s\n", svid.ID)

		// Return validation success with SPIFFE ID
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":    "valid",
			"spiffe_id": svid.ID.String(),
			"message":   "JWT validation successful",
		})
	})
	httpServer := &http.Server{Handler: mux}

	// Serve X.509
	go func() {
		for {
			conn, err := tlsLn.Accept()
			if err != nil {
				fmt.Fprintf(os.Stderr, "X.509 TLS listener stopped: %v\n", err)
				return
			}
			// Complete the TLS handshake and keep the connection open until closed.
			go func(c net.Conn) {
				defer c.Close()
				tlsConn := c.(*tls.Conn)
				if err := tlsConn.Handshake(); err != nil {
					fmt.Fprintf(os.Stderr, "TLS handshake failed: %v\n", err)
					return
				}
				// Hold open until client closes.
				buf := make([]byte, 1)
				tlsConn.Read(buf)
			}(conn)
		}
	}()

	// Serve JWT HTTP
	go func() {
		if err := httpServer.Serve(httpLn); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "JWT HTTP server error: %v\n", err)
		}
	}()

	// Announce ports
	fmt.Printf("SPIFFE_X509_PORT=%d\n", x509Port)
	fmt.Printf("SPIFFE_JWT_PORT=%d\n", jwtPort)
	fmt.Println("READY")

	<-ctx.Done()
	httpServer.Shutdown(context.Background())
	tlsLn.Close()
}
