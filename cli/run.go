package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/arndt-s/spiffe-conformance-test-suite/internal/result"
	"github.com/arndt-s/spiffe-conformance-test-suite/suite"
	_ "github.com/arndt-s/spiffe-conformance-test-suite/tests" // register all test cases
	"github.com/spf13/cobra"
)

type runFlags struct {
	cmd         string
	args        string
	tests       string
	output      string
	resultsFile string
	parallel    int
	verbose     bool
}

// ExitCodeNotExecuted is the exit status when one or more test cases could not
// be executed (status ERROR). Test outcomes (PASS/FAIL/SKIP) never affect the
// exit status: a FAIL is a valid result, not a failed run.
const ExitCodeNotExecuted = 2

// ExitError carries a specific process exit code.
type ExitError struct {
	Code int
	Msg  string
}

func (e *ExitError) Error() string { return e.Msg }

func newRunCmd() *cobra.Command {
	var flags runFlags

	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run the conformance test suite against an SDK harness",
		Long: `Run the conformance test suite against an SDK harness.

The exit status reports whether the run could be carried out, not whether the
SDK conforms. It is 0 when every selected test case executed, whatever its
result (PASS, FAIL or SKIP); 2 when one or more test cases could not be
executed (ERROR); and 1 for invalid usage or internal errors.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runSuite(cmd.Context(), cmd, flags)
		},
		SilenceUsage: true,
	}

	cmd.Flags().StringVar(&flags.cmd, "cmd", "", "Path to the SDK harness binary (required)")
	cmd.Flags().StringVar(&flags.args, "args", "", "Comma-separated arguments to pass to the harness")
	cmd.Flags().StringVar(&flags.tests, "tests", "", "Comma-separated test IDs or groups to run (e.g. XV-8,JV,EP-5); empty runs all")
	cmd.Flags().IntVar(&flags.parallel, "parallel", 1, "Number of test cases to run concurrently")
	cmd.Flags().StringVar(&flags.output, "output", "text", "Output format for stdout: text or json")
	cmd.Flags().StringVar(&flags.resultsFile, "results-file", "", "Also write the results as JSON to this file")
	cmd.Flags().BoolVarP(&flags.verbose, "verbose", "v", false, "Enable verbose logging")
	_ = cmd.MarkFlagRequired("cmd")

	return cmd
}

func runSuite(ctx context.Context, cmd *cobra.Command, flags runFlags) error {
	args := parseList(flags.args)
	include := parseList(flags.tests)

	var stOut, stErr io.Writer
	if flags.verbose {
		stOut = cmd.ErrOrStderr()
		stErr = stOut
	}

	if flags.verbose {
		fmt.Fprintf(cmd.ErrOrStderr(), "Running suite with\ncmd:\t%s\nargs:\t%s\n", flags.cmd, flags.args)
	}

	cfg := suite.RunnerConfig{Cmd: flags.cmd, Args: args, Parallel: flags.parallel, StOut: stOut, StErr: stErr}

	cases, err := suite.Select(include)
	if err != nil {
		return err
	}

	var report result.Report
	for _, res := range suite.Run(ctx, cases, cfg) {
		report.Add(res)
	}
	report.Partial = len(include) > 0

	if err := printReport(report, flags.output); err != nil {
		return err
	}

	if flags.resultsFile != "" {
		b, err := report.JSON()
		if err != nil {
			return fmt.Errorf("marshal report: %w", err)
		}
		if err := os.WriteFile(flags.resultsFile, append(b, '\n'), 0o644); err != nil {
			return fmt.Errorf("write results file: %w", err)
		}
	}

	if report.Errors > 0 {
		return &ExitError{
			Code: ExitCodeNotExecuted,
			Msg:  fmt.Sprintf("%d test case(s) could not be executed", report.Errors),
		}
	}
	return nil
}

func printReport(report result.Report, format string) error {
	switch format {
	case "json":
		b, err := report.JSON()
		if err != nil {
			return fmt.Errorf("marshal report: %w", err)
		}
		fmt.Println(string(b))
	default:
		printText(os.Stdout, report)
	}
	return nil
}

func parseList(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, a := range strings.Split(s, ",") {
		a = strings.TrimSpace(a)
		if a != "" {
			out = append(out, a)
		}
	}
	return out
}
