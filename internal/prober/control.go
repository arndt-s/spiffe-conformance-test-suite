package prober

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Outcome is the harness's answer to a control-port request
// (harness contract v1 §4.1).
type Outcome string

const (
	OutcomeOK          Outcome = "ok"
	OutcomeRejected    Outcome = "rejected"
	OutcomeError       Outcome = "error"
	OutcomeUnsupported Outcome = "unsupported"
)

// ControlResponse is the decoded response envelope plus endpoint-specific fields.
type ControlResponse struct {
	HTTPStatus int             `json:"-"`
	Status     Outcome         `json:"status"`
	Message    string          `json:"message,omitempty"`
	SPIFFEID   string          `json:"spiffe_id,omitempty"`
	Claims     map[string]any  `json:"claims,omitempty"`
	SVIDs      []FetchedJWT    `json:"svids,omitempty"`
	Raw        json.RawMessage `json:"-"`
}

// FetchedJWT is one entry of a /v1/jwt/fetch response.
type FetchedJWT struct {
	SPIFFEID string `json:"spiffe_id"`
	Token    string `json:"token"`
	Hint     string `json:"hint"`
}

// Control is a client for a v1 harness control port.
type Control struct {
	port   int
	client *http.Client
}

// NewControl returns a client for the control port on 127.0.0.1.
func NewControl(port int) *Control {
	return &Control{port: port, client: &http.Client{Timeout: 10 * time.Second}}
}

// ValidateJWT calls POST /v1/jwt/validate.
func (c *Control) ValidateJWT(token, audience string) (*ControlResponse, error) {
	return c.post("/v1/jwt/validate", map[string]any{"token": token, "audience": audience})
}

// FetchJWT calls POST /v1/jwt/fetch.
func (c *Control) FetchJWT(audience []string, spiffeID string) (*ControlResponse, error) {
	return c.post("/v1/jwt/fetch", map[string]any{"audience": audience, "spiffe_id": spiffeID})
}

// DialX509 calls POST /v1/x509/dial.
func (c *Control) DialX509(address string) (*ControlResponse, error) {
	return c.post("/v1/x509/dial", map[string]any{"address": address})
}

func (c *Control) post(path string, body any) (*ControlResponse, error) {
	reqBody, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	url := fmt.Sprintf("http://127.0.0.1:%d%s", c.port, path)
	resp, err := c.client.Post(url, "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("POST %s: %w", path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read %s response: %w", path, err)
	}

	out := &ControlResponse{HTTPStatus: resp.StatusCode, Raw: raw}
	if err := json.Unmarshal(raw, out); err != nil {
		if resp.StatusCode == http.StatusNotImplemented || resp.StatusCode == http.StatusNotFound {
			// A harness without the endpoint at all.
			out.Status = OutcomeUnsupported
			return out, nil
		}
		return nil, fmt.Errorf("%s: HTTP %d with non-JSON body %q", path, resp.StatusCode, truncate(raw))
	}
	if want := statusFor(out.Status); want == 0 || want != resp.StatusCode {
		return nil, fmt.Errorf("%s: contract violation: HTTP %d with status %q", path, resp.StatusCode, out.Status)
	}
	return out, nil
}

func statusFor(o Outcome) int {
	switch o {
	case OutcomeOK:
		return http.StatusOK
	case OutcomeRejected:
		return http.StatusUnprocessableEntity
	case OutcomeError:
		return http.StatusInternalServerError
	case OutcomeUnsupported:
		return http.StatusNotImplemented
	}
	return 0
}

func truncate(b []byte) string {
	if len(b) > 200 {
		return string(b[:200]) + "…"
	}
	return string(b)
}
