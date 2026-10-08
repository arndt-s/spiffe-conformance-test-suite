package prober

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"strings"
	"testing"

	"github.com/arndt-s/spiffe-conformance-test-suite/internal/ca"
)

const td = "spiffe://test.example.org"

// serve runs a TLS server that requires client certificates verified against
// clientRoots and handles each accepted connection with onConn.
func serve(t *testing.T, serverCert tls.Certificate, clientRoots *x509.CertPool, version uint16, onConn func(*tls.Conn)) int {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientRoots,
		MinVersion:   version,
		MaxVersion:   version,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c *tls.Conn) {
				defer c.Close()
				if err := c.Handshake(); err != nil {
					return
				}
				onConn(c)
			}(c.(*tls.Conn))
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func fixtures(t *testing.T) (*ca.CA, tls.Certificate, tls.Certificate) {
	t.Helper()
	authority, err := ca.New(td)
	if err != nil {
		t.Fatal(err)
	}
	server, err := authority.IssueX509SVID(td + "/server")
	if err != nil {
		t.Fatal(err)
	}
	client, err := authority.IssueX509SVID(td + "/client")
	if err != nil {
		t.Fatal(err)
	}
	return authority, server.TLSCertificate(), client.TLSCertificate()
}

func TestProbeX509DetectsRejectionAfterHandshake(t *testing.T) {
	for _, v := range []struct {
		name    string
		version uint16
	}{{"TLS1.2", tls.VersionTLS12}, {"TLS1.3", tls.VersionTLS13}} {
		t.Run(v.name, func(t *testing.T) {
			authority, serverCert, clientCert := fixtures(t)
			other, err := ca.New(td)
			if err != nil {
				t.Fatal(err)
			}
			// The server only trusts a different CA, so it rejects our client.
			port := serve(t, serverCert, other.CACertPool(), v.version, func(*tls.Conn) {})

			if _, err := ProbeX509(port, clientCert, authority.CACertPool()); err == nil {
				t.Fatal("ProbeX509 reported acceptance for a rejected client certificate")
			}
		})
	}
}

func TestProbeX509ReadsPeerLine(t *testing.T) {
	authority, serverCert, clientCert := fixtures(t)
	port := serve(t, serverCert, authority.CACertPool(), tls.VersionTLS13, func(c *tls.Conn) {
		id := c.ConnectionState().PeerCertificates[0].URIs[0].String()
		_, _ = c.Write([]byte(id + "\n"))
	})

	res, err := ProbeX509(port, clientCert, authority.CACertPool())
	if err != nil {
		t.Fatal(err)
	}
	if res.PeerLine != td+"/client" {
		t.Fatalf("PeerLine = %q, want %q", res.PeerLine, td+"/client")
	}
	if len(res.SpiffeIDs) != 1 || res.SpiffeIDs[0] != td+"/server" {
		t.Fatalf("SpiffeIDs = %v", res.SpiffeIDs)
	}
}

func TestProbeX509AcceptsServerHoldingConnectionOpen(t *testing.T) {
	authority, serverCert, clientCert := fixtures(t)
	port := serve(t, serverCert, authority.CACertPool(), tls.VersionTLS13, func(c *tls.Conn) {
		_, _ = c.Read(make([]byte, 1)) // v0 harness behaviour
	})

	res, err := ProbeX509(port, clientCert, authority.CACertPool())
	if err != nil {
		t.Fatalf("v0-style server treated as rejection: %v", err)
	}
	if res.PeerLine != "" {
		t.Fatalf("unexpected PeerLine %q", res.PeerLine)
	}
}

func TestProbeX509RejectsUntrustedServer(t *testing.T) {
	authority, serverCert, clientCert := fixtures(t)
	port := serve(t, serverCert, authority.CACertPool(), tls.VersionTLS13, func(*tls.Conn) {})
	other, err := ca.New(td)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ProbeX509(port, clientCert, other.CACertPool())
	if err == nil || !strings.Contains(err.Error(), "TLS dial") {
		t.Fatalf("got %v, want a TLS dial verification error", err)
	}
}
