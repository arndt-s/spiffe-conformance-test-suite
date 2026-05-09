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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
// CapJWTFetch capability.
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
	body, _ := json.Marshal(map[string]string{"audience": audience, "spiffe_id": spiffeID})
	resp, err := c.httpClient.Post(c.base+"/jwt/fetch", "application/json", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("harnessctl: POST /jwt/fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("harnessctl: /jwt/fetch returned %d: %s", resp.StatusCode, raw)
	}
	var payload struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", fmt.Errorf("harnessctl: decode /jwt/fetch: %w", err)
	}
	return payload.Token, nil
}

// Identity is a single SVID held by the harness.
type Identity struct {
	SPIFFEID string `json:"spiffe_id"`
	Hint     string `json:"hint"`
}

// ListIdentities returns the harness's known X.509 SVIDs. Requires
// CapMultiIdentity.
//
//	GET /x509/identities
//	200 {"identities":[{"spiffe_id":"…","hint":"…"}, …]}
func (c *Client) ListIdentities() ([]Identity, error) {
	if c.base == "" {
		return nil, ErrControlPortUnavailable
	}
	if !c.caps[CapMultiIdentity] {
		return nil, fmt.Errorf("%w: %s", ErrCapabilityMissing, CapMultiIdentity)
	}
	resp, err := c.httpClient.Get(c.base + "/x509/identities")
	if err != nil {
		return nil, fmt.Errorf("harnessctl: GET /x509/identities: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("harnessctl: /x509/identities returned %d: %s", resp.StatusCode, raw)
	}
	var payload struct {
		Identities []Identity `json:"identities"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("harnessctl: decode /x509/identities: %w", err)
	}
	return payload.Identities, nil
}

// IdentityCertPEM returns the leaf cert for a specific SPIFFE ID held
// by the harness, in PEM form. Requires CapMultiIdentity.
//
//	GET /x509/identities/<url-escaped spiffe id>/cert
//	200 application/x-pem-file
func (c *Client) IdentityCertPEM(spiffeID string) ([]byte, error) {
	if c.base == "" {
		return nil, ErrControlPortUnavailable
	}
	if !c.caps[CapMultiIdentity] {
		return nil, fmt.Errorf("%w: %s", ErrCapabilityMissing, CapMultiIdentity)
	}
	endpoint := c.base + "/x509/identities/" + url.PathEscape(spiffeID) + "/cert"
	resp, err := c.httpClient.Get(endpoint)
	if err != nil {
		return nil, fmt.Errorf("harnessctl: GET %s: %w", endpoint, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("harnessctl: %s returned %d: %s", endpoint, resp.StatusCode, raw)
	}
	return io.ReadAll(resp.Body)
}

// Reconnect tells the harness to re-create its Workload API client
// against the current SPIFFE_ENDPOINT_SOCKET value. Requires
// CapEndpointReconnect.
//
//	POST /endpoint/reconnect
//	204 No Content
func (c *Client) Reconnect() error {
	if c.base == "" {
		return ErrControlPortUnavailable
	}
	if !c.caps[CapEndpointReconnect] {
		return fmt.Errorf("%w: %s", ErrCapabilityMissing, CapEndpointReconnect)
	}
	resp, err := c.httpClient.Post(c.base+"/endpoint/reconnect", "application/json", nil)
	if err != nil {
		return fmt.Errorf("harnessctl: POST /endpoint/reconnect: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("harnessctl: /endpoint/reconnect returned %d: %s", resp.StatusCode, raw)
	}
	return nil
}
