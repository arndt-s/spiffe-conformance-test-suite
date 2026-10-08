package harness

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Readiness holds what the harness announced on stdout before READY.
type Readiness struct {
	// Version is the harness contract version (0 if no SPIFFE_HARNESS_VERSION line).
	Version     int
	X509Port    int
	ControlPort int
	Ready       bool
}

// parseStdout reads lines from reader until READY and validates that the
// announcement is complete for the declared contract version.
func parseStdout(reader io.Reader, r *Readiness) error {
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		if err := parseLine(scanner.Text(), r); err != nil {
			return err
		}
		if r.Ready {
			return r.validate()
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("reading stdout: %w", err)
	}
	return fmt.Errorf("stdout closed before READY (harness exited?); saw %+v", *r)
}

func (r *Readiness) validate() error {
	switch r.Version {
	case 0:
		return fmt.Errorf("harness did not announce SPIFFE_HARNESS_VERSION; the v0 protocol is no longer supported (see docs/HARNESS_CONTRACT.md)")
	case 1:
		if r.X509Port == 0 || r.ControlPort == 0 {
			return fmt.Errorf("READY before SPIFFE_X509_PORT and SPIFFE_CONTROL_PORT were announced: %+v", *r)
		}
	default:
		return fmt.Errorf("unsupported SPIFFE_HARNESS_VERSION=%d (suite supports 1)", r.Version)
	}
	return nil
}

func parseLine(line string, r *Readiness) error {
	line = strings.TrimSpace(line)
	if line == "READY" {
		r.Ready = true
		return nil
	}
	key, value, ok := strings.Cut(line, "=")
	if !ok {
		return nil
	}
	var dst *int
	switch key {
	case "SPIFFE_HARNESS_VERSION":
		dst = &r.Version
	case "SPIFFE_X509_PORT":
		dst = &r.X509Port
	case "SPIFFE_CONTROL_PORT":
		dst = &r.ControlPort
	default:
		return nil
	}
	n, err := strconv.Atoi(value)
	if err != nil {
		return fmt.Errorf("parse %s: %w", key, err)
	}
	*dst = n
	return nil
}
