package cli

import (
	"fmt"
	"io"

	"github.com/arndt-s/spiffe-conformance-test-suite/internal/result"
)

// printText writes the human-readable report: one line per test case, then
// counts by level and the conformance claim per feature.
func printText(w io.Writer, report result.Report) {
	for _, r := range report.Results {
		note := ""
		if r.Delegated {
			note = " [delegated]"
		}
		fmt.Fprintf(w, "[%-5s] %-22s %-6s %s (%s)%s\n", r.Status, r.Name, r.Level, r.Description, r.Ref, note)
		if r.Message != "" {
			fmt.Fprintf(w, "        %s\n", r.Message)
		}
	}

	fmt.Fprintf(w, "\nPassed: %d  Failed: %d  Errors: %d  Skipped: %d\n",
		report.Passed, report.Failed, report.Errors, report.Skipped)
	for _, l := range []result.Level{result.LevelMust, result.LevelShould, result.LevelOpt} {
		c, ok := report.Levels[l]
		if !ok {
			continue
		}
		fmt.Fprintf(w, "  %-6s passed %d, failed %d, errors %d, skipped %d\n", l, c.Passed, c.Failed, c.Errors, c.Skipped)
	}

	fmt.Fprintln(w, "\nConformance (MUST tests per feature):")
	for _, c := range report.Claims {
		if c.Status == result.ClaimNotRun {
			continue
		}
		note := ""
		if c.Delegated {
			note = "  (JWT validation delegated to the Workload API)"
		}
		fmt.Fprintf(w, "  %-13s %-15s %d passed, %d failed, %d skipped, %d errors%s\n",
			c.Feature, c.Status, c.Passed, c.Failed, c.Skipped, c.Errors, note)
	}
	if report.Partial {
		fmt.Fprintln(w, "  (partial run: claims cover only the selected test cases)")
	}
}
