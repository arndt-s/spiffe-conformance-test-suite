package harness

import (
	"strings"
	"testing"
)

func TestParseStdout(t *testing.T) {
	cases := []struct {
		name    string
		out     string
		want    Readiness
		wantErr string
	}{
		{"v0 rejected", "SPIFFE_JWT_PORT=2\nlog line\nSPIFFE_X509_PORT=1\nREADY\n",
			Readiness{}, "no longer supported"},
		{"v1", "SPIFFE_HARNESS_VERSION=1\nlog line\nSPIFFE_CONTROL_PORT=3\nSPIFFE_X509_PORT=1\nREADY\n",
			Readiness{Version: 1, X509Port: 1, ControlPort: 3, Ready: true}, ""},
		{"v1 missing control port", "SPIFFE_HARNESS_VERSION=1\nSPIFFE_X509_PORT=1\nREADY\n",
			Readiness{}, "SPIFFE_CONTROL_PORT"},
		{"unknown version", "SPIFFE_HARNESS_VERSION=7\nSPIFFE_X509_PORT=1\nREADY\n", Readiness{}, "unsupported"},
		{"exits before READY", "SPIFFE_X509_PORT=1\n", Readiness{}, "before READY"},
		{"bad port", "SPIFFE_X509_PORT=abc\n", Readiness{}, "parse SPIFFE_X509_PORT"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var r Readiness
			err := parseStdout(strings.NewReader(c.out), &r)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if r != c.want {
				t.Fatalf("got %+v, want %+v", r, c.want)
			}
		})
	}
}
