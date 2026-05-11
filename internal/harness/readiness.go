package harness

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Readiness holds the ports parsed from the SDK harness stdout.
type Readiness struct {
	X509Port    int
	JWTPort     int
	ControlPort int // optional; 0 when the harness does not advertise one
	Ready       bool
}

// IsComplete reports whether all three required values have been observed.
func (r *Readiness) IsComplete() bool {
	return r.X509Port != 0 && r.JWTPort != 0 && r.Ready
}

// parseStdout reads lines from r and populates the Readiness struct.
// It blocks until IsComplete() is true or the reader is exhausted/errors.
func parseStdout(reader io.Reader, r *Readiness) error {
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		if err := parseLine(line, r); err != nil {
			return err
		}
		if r.IsComplete() {
			return nil
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("reading stdout: %w", err)
	}
	if !r.IsComplete() {
		return fmt.Errorf("stdout closed before readiness: %+v", r)
	}
	return nil
}

func parseLine(line string, r *Readiness) error {
	line = strings.TrimSpace(line)
	switch {
	case line == "READY":
		r.Ready = true
	case strings.HasPrefix(line, "SPIFFE_X509_PORT="):
		p, err := strconv.Atoi(strings.TrimPrefix(line, "SPIFFE_X509_PORT="))
		if err != nil {
			return fmt.Errorf("parse SPIFFE_X509_PORT: %w", err)
		}
		r.X509Port = p
	case strings.HasPrefix(line, "SPIFFE_JWT_PORT="):
		p, err := strconv.Atoi(strings.TrimPrefix(line, "SPIFFE_JWT_PORT="))
		if err != nil {
			return fmt.Errorf("parse SPIFFE_JWT_PORT: %w", err)
		}
		r.JWTPort = p
	case strings.HasPrefix(line, "SPIFFE_CONTROL_PORT="):
		p, err := strconv.Atoi(strings.TrimPrefix(line, "SPIFFE_CONTROL_PORT="))
		if err != nil {
			return fmt.Errorf("parse SPIFFE_CONTROL_PORT: %w", err)
		}
		r.ControlPort = p
	}
	return nil
}
