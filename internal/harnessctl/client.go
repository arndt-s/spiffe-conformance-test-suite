// Package harnessctl provides a typed client for the SDK harness's
// control HTTP port.
//
// The control port lets the suite drive the harness beyond the basic
// "expose an X.509 SVID and validate JWTs" surface — for example,
// asking the SDK to issue a JWT-SVID, listing every identity the
// harness has fetched, or telling the harness to reconnect to its
// Workload API endpoint.
//
// Each route is gated by a capability advertised at GET /capabilities.
// Tests probe the client's Capabilities() before invoking
// capability-gated routes; when a capability is missing they should
// return suite.Skip(...) rather than fail.
//
// PR-B (this commit) introduces the client skeleton only; harness-side
// implementations land in PR-C, at which point Capabilities() will
// return a non-empty set on harnesses that advertise capabilities.
package harnessctl

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Capability names recognised by the suite.
const (
	CapMTLSVerify        = "mtls-verify"
	CapJWTFetch          = "jwt-fetch"
	CapMultiIdentity     = "multi-identity"
	CapEndpointReconnect = "endpoint-reconnect"
)

// ErrCapabilityMissing is returned by capability-gated client methods
// when the harness has not advertised the required capability.
var ErrCapabilityMissing = errors.New("harnessctl: capability missing")

// ErrControlPortUnavailable is returned when the harness did not
// advertise a control port at all.
var ErrControlPortUnavailable = errors.New("harnessctl: control port unavailable")

// Client talks to a harness's control port. The zero value is unusable;
// construct via New.
type Client struct {
	base       string
	httpClient *http.Client
	caps       map[string]bool
}

// New constructs a Client targeting the given control-port base URL
// (e.g. "http://127.0.0.1:42042"). When port == 0 the returned client
// reports no capabilities and every capability-gated method returns
// ErrControlPortUnavailable, which lets the suite stay quiet on
// harnesses that have not yet adopted the v2 contract.
func New(port int) *Client {
	c := &Client{
		httpClient: &http.Client{Timeout: 5 * time.Second},
		caps:       map[string]bool{},
	}
	if port > 0 {
		c.base = fmt.Sprintf("http://127.0.0.1:%d", port)
	}
	return c
}

// LoadCapabilities fetches GET /capabilities from the control port and
// caches the advertised set. Safe to call multiple times. When the
// control port is not configured, returns nil (empty capabilities).
func (c *Client) LoadCapabilities() error {
	if c.base == "" {
		return nil
	}
	resp, err := c.httpClient.Get(c.base + "/capabilities")
	if err != nil {
		return fmt.Errorf("harnessctl: GET /capabilities: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("harnessctl: /capabilities returned %d: %s", resp.StatusCode, body)
	}
	var payload struct {
		Caps []string `json:"caps"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return fmt.Errorf("harnessctl: decode /capabilities: %w", err)
	}
	for _, name := range payload.Caps {
		c.caps[name] = true
	}
	return nil
}

// Capabilities returns the sorted list of capability names advertised
// by the harness. Returns an empty slice when no capabilities are known
// (typically: harness has not adopted v2, or LoadCapabilities was not
// called).
func (c *Client) Capabilities() []string {
	out := make([]string, 0, len(c.caps))
	for k := range c.caps {
		out = append(out, k)
	}
	return out
}

// HasCapability reports whether the harness advertised the given cap.
func (c *Client) HasCapability(name string) bool {
	return c.caps[name]
}

// FetchJWT asks the harness to call FetchJWTSVID on its Workload API
// client for the given audience and (optional) SPIFFE ID. Requires the
// CapJWTFetch capability. Returns the resulting compact-serialized JWT.
//
// Wire shape (defined for PR-C, returned in PR-B as ErrCapabilityMissing
// or ErrControlPortUnavailable):
//
//	POST /jwt/fetch  {"audience":"<aud>","spiffe_id":"<id>"}
//	200 {"token":"<compact JWT>"}
func (c *Client) FetchJWT(audience, spiffeID string) (string, error) {
	if c.base == "" {
		return "", ErrControlPortUnavailable
	}
	if !c.caps[CapJWTFetch] {
		return "", fmt.Errorf("%w: %s", ErrCapabilityMissing, CapJWTFetch)
	}
	return "", errNotImplementedYet // wired in PR-C
}

// Identity is a single SVID held by the harness.
type Identity struct {
	SPIFFEID string `json:"spiffe_id"`
	Hint     string `json:"hint"`
}

// ListIdentities returns the harness's known X.509 SVIDs. Requires
// CapMultiIdentity.
func (c *Client) ListIdentities() ([]Identity, error) {
	if c.base == "" {
		return nil, ErrControlPortUnavailable
	}
	if !c.caps[CapMultiIdentity] {
		return nil, fmt.Errorf("%w: %s", ErrCapabilityMissing, CapMultiIdentity)
	}
	return nil, errNotImplementedYet
}

// IdentityCertPEM returns the leaf cert for a specific SPIFFE ID held
// by the harness, in PEM form. Requires CapMultiIdentity.
func (c *Client) IdentityCertPEM(spiffeID string) ([]byte, error) {
	if c.base == "" {
		return nil, ErrControlPortUnavailable
	}
	if !c.caps[CapMultiIdentity] {
		return nil, fmt.Errorf("%w: %s", ErrCapabilityMissing, CapMultiIdentity)
	}
	return nil, errNotImplementedYet
}

// Reconnect tells the harness to re-create its Workload API client
// against the current SPIFFE_ENDPOINT_SOCKET value. Requires
// CapEndpointReconnect.
func (c *Client) Reconnect() error {
	if c.base == "" {
		return ErrControlPortUnavailable
	}
	if !c.caps[CapEndpointReconnect] {
		return fmt.Errorf("%w: %s", ErrCapabilityMissing, CapEndpointReconnect)
	}
	return errNotImplementedYet
}

// errNotImplementedYet is a placeholder returned by control-port
// methods until PR-C lands the harness-side protocol. Tests that depend
// on these methods must be added in PR-E onward.
var errNotImplementedYet = errors.New("harnessctl: route not implemented until PR-C")
