// Package prober provides network probers for inspecting SDK-exposed endpoints.
package prober

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// isExpectedReadError reports whether err is a "connection healthy
// but no data" outcome from the brief post-handshake Read above. We
// treat io.EOF, the timeout from our own deadline, and Go's
// "use of closed network connection" as expected; anything else
// (including TLS alerts) is bubbled up so callers see the rejection.
func isExpectedReadError(err error) bool {
	if err == io.EOF {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	return false
}

// X509ProbeResult holds the result of probing the SDK's X.509 port.
type X509ProbeResult struct {
	// PeerCerts is the full certificate chain presented by the peer (leaf first).
	PeerCerts []*x509.Certificate
	// SpiffeIDs is the list of SPIFFE URIs found in the leaf certificate.
	SpiffeIDs []string
}

// ProbeX509 dials the SDK's X.509 port via mTLS using the provided client
// cert/key and trust bundle, then returns the presented certificate chain.
//
// clientCert is the client certificate to present during the TLS handshake.
// trustBundle is the pool of trusted CA certificates for verifying the peer.
// port is the port number on localhost.
func ProbeX509(port int, clientCert tls.Certificate, trustBundle *x509.CertPool) (*X509ProbeResult, error) {
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

	// Under TLS 1.3 the client may finish the handshake locally before the
	// server's alert (e.g. after a server-side VerifyPeerCertificate
	// rejection) arrives. Force a short Read so any alert surfaces here
	// rather than being silently dropped by Close().
	_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err != nil {
		// io.EOF / "connection closed" / read-deadline exceeded are all
		// expected for healthy connections; only treat real I/O errors
		// (TLS alerts) as a probe failure.
		if !isExpectedReadError(err) {
			return nil, fmt.Errorf("TLS post-handshake read %s: %w", addr, err)
		}
	}

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

	return result, nil
}
