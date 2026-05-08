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

// decodeJWTPayload base64url-decodes the payload segment of a JWT without
// verifying the signature. Useful for inspecting claims in test scenarios.
func decodeJWTPayload(token string) (map[string]interface{}, error) {
	// Split header.payload.signature
	parts := splitJWT(token)
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed JWT: expected 3 parts, got %d", len(parts))
	}
	payload, err := base64URLDecode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("unmarshal claims: %w", err)
	}
	return claims, nil
}

func splitJWT(token string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			parts = append(parts, token[start:i])
			start = i + 1
		}
	}
	parts = append(parts, token[start:])
	return parts
}

func base64URLDecode(s string) ([]byte, error) {
	// Add padding if needed
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	// Replace URL-safe chars
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '-':
			b[i] = '+'
		case '_':
			b[i] = '/'
		default:
			b[i] = s[i]
		}
	}
	import64 := make([]byte, len(b)*3/4+3)
	n, err := decodeBase64(b, import64)
	if err != nil {
		return nil, err
	}
	return import64[:n], nil
}

func decodeBase64(src, dst []byte) (int, error) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	index := [256]byte{}
	for i := 0; i < 256; i++ {
		index[i] = 0xff
	}
	for i, c := range alphabet {
		index[c] = byte(i)
	}
	index['='] = 0

	n := 0
	for i := 0; i < len(src); i += 4 {
		end := i + 4
		if end > len(src) {
			end = len(src)
		}
		chunk := src[i:end]
		if len(chunk) < 2 {
			break
		}
		b0 := index[chunk[0]]
		b1 := index[chunk[1]]
		if b0 == 0xff || b1 == 0xff {
			return 0, fmt.Errorf("invalid base64 character")
		}
		dst[n] = (b0 << 2) | (b1 >> 4)
		n++
		if len(chunk) > 2 && chunk[2] != '=' {
			b2 := index[chunk[2]]
			if b2 == 0xff {
				return 0, fmt.Errorf("invalid base64 character")
			}
			dst[n] = (b1 << 4) | (b2 >> 2)
			n++
			if len(chunk) > 3 && chunk[3] != '=' {
				b3 := index[chunk[3]]
				if b3 == 0xff {
					return 0, fmt.Errorf("invalid base64 character")
				}
				dst[n] = (b2 << 6) | b3
				n++
			}
		}
	}
	return n, nil
}
