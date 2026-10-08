package prober

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// JWTProbeResult holds the result of probing the SDK's JWT port.
type JWTProbeResult struct {
	// HTTPStatus is the HTTP status code returned by the SDK.
	HTTPStatus int `json:"-"`
	// Status is the validation status returned by the SDK ("valid" on success).
	Status string `json:"status"`
	// SPIFFEID is the validated SPIFFE ID returned by the SDK.
	SPIFFEID string `json:"spiffe_id"`
	// Message is an optional error message returned by the SDK on validation failure.
	Message string `json:"message,omitempty"`
}

// ProbeJWT sends an HTTP request to the SDK's JWT endpoint with a JWT token
// in the Authorization header. The SDK is expected to validate the token and
// return JSON: {"status": "valid", "spiffe_id": "..."}.
func ProbeJWT(port int, jwtToken string) (*JWTProbeResult, error) {
	url := fmt.Sprintf("http://127.0.0.1:%d/jwt", port)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+jwtToken)

	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	var result JWTProbeResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parse response JSON: %w", err)
	}
	result.HTTPStatus = resp.StatusCode

	return &result, nil
}
