// Package prober provides network probers for inspecting SDK-exposed endpoints.
package prober

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"
)

// ProbeX509InsecureForTesting dials the SDK's X.509 port without client auth
// and without server certificate verification. Intended for skeleton/smoke tests
// only; production test cases should use ProbeX509 with a proper trust bundle.
func ProbeX509InsecureForTesting(port int) (*X509ProbeResult, error) {
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 5 * time.Second},
		"tcp",
		addr,
		&tls.Config{InsecureSkipVerify: true}, //nolint:gosec // intentional for test skeleton
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
	return result, nil
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
