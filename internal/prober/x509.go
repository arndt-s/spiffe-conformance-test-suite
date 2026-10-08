// Package prober provides network probers for inspecting SDK-exposed endpoints.
package prober

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	// v0PostHandshakeWait bounds how long ProbeX509 waits after the handshake
	// for a v0 harness (which never writes) to reject the client.
	v0PostHandshakeWait = 250 * time.Millisecond
	// v1PeerLineWait bounds how long ProbeX509 waits for a v1 harness to write
	// the peer-ID line. v1 harnesses write or close immediately.
	v1PeerLineWait = 5 * time.Second
)

// X509ProbeResult holds the result of probing the SDK's X.509 port.
type X509ProbeResult struct {
	// PeerCerts is the full certificate chain presented by the peer (leaf first).
	PeerCerts []*x509.Certificate
	// SpiffeIDs is the list of SPIFFE URIs found in the leaf certificate.
	SpiffeIDs []string
	// PeerLine is the line the server wrote after the handshake: the client's
	// SPIFFE ID under harness contract v1. Empty for v0 harnesses.
	PeerLine string
}

// ProbeX509 dials the SDK's X.509 port via mTLS using the provided client
// cert/key and trust bundle, then returns the presented certificate chain.
//
// A server can reject the client certificate after the client considers the
// handshake complete (always under TLS 1.3), so ProbeX509 also reads from the
// connection. With requirePeerLine (harness contract v1) the client was
// accepted only if the server wrote the peer-ID line. Without it (v0), a TLS
// alert or a close without data means rejected, and silence until
// v0PostHandshakeWait expires means accepted, since v0 harnesses hold the
// connection open. ProbeX509 returns an error if the client was rejected.
func ProbeX509(port int, clientCert tls.Certificate, trustBundle *x509.CertPool, requirePeerLine bool) (*X509ProbeResult, error) {
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 5 * time.Second},
		"tcp",
		addr,
		&tls.Config{
			Certificates: []tls.Certificate{clientCert},
			// SPIFFE SVIDs carry a URI SAN, not a DNS or IP SAN, so standard
			// hostname verification always fails when dialing 127.0.0.1.
			// We skip it and do chain verification ourselves via VerifyConnection.
			InsecureSkipVerify: true, //nolint:gosec // hostname check replaced by VerifyConnection below
			VerifyConnection: func(cs tls.ConnectionState) error {
				if len(cs.PeerCertificates) == 0 {
					return fmt.Errorf("no peer certificates presented")
				}
				opts := x509.VerifyOptions{
					Roots:         trustBundle,
					Intermediates: x509.NewCertPool(),
				}
				for _, cert := range cs.PeerCertificates[1:] {
					opts.Intermediates.AddCert(cert)
				}
				_, err := cs.PeerCertificates[0].Verify(opts)
				return err
			},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("TLS dial %s: %w", addr, err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	result := &X509ProbeResult{
		PeerCerts: state.PeerCertificates,
	}
	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		for _, u := range leaf.URIs {
			result.SpiffeIDs = append(result.SpiffeIDs, u.String())
		}
	}

	wait := v0PostHandshakeWait
	if requirePeerLine {
		wait = v1PeerLineWait
	}
	if err := conn.SetReadDeadline(time.Now().Add(wait)); err != nil {
		return nil, fmt.Errorf("set read deadline: %w", err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	var netErr net.Error
	switch {
	case requirePeerLine && strings.TrimSpace(line) == "":
		return nil, fmt.Errorf("server did not accept client (no peer-ID line): %v", err)
	case err == nil || line != "":
		result.PeerLine = strings.TrimSpace(line)
	case requirePeerLine:
		return nil, fmt.Errorf("server did not accept client (no peer-ID line): %w", err)
	case errors.As(err, &netErr) && netErr.Timeout():
		// Server is holding the connection open: accepted (v0 harness).
	default:
		return nil, fmt.Errorf("server rejected client after TLS handshake: %w", err)
	}
	return result, nil
}
