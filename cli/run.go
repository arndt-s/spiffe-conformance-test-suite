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
	cmd          string
	args         string
	tests        string
	allowFailure string
	output       string
	verbose      bool
	strict       bool
}

func newRunCmd() *cobra.Command {
	var flags runFlags

	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run the conformance test suite against an SDK harness",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runSuite(cmd.Context(), cmd, flags)
		},
		SilenceUsage: true,
	}

	cmd.Flags().StringVar(&flags.cmd, "cmd", "", "Path to the SDK harness binary (required)")
	cmd.Flags().StringVar(&flags.args, "args", "", "Comma-separated arguments to pass to the harness")
	cmd.Flags().StringVar(&flags.tests, "tests", "", "Comma-separated list of test cases to run (e.g. X1,J3); empty runs all")
	cmd.Flags().StringVar(&flags.allowFailure, "allow-failure", "", "Comma-separated list of tests whose failures should be tolerated (reported as SKIP)")
	cmd.Flags().StringVar(&flags.output, "output", "text", "Output format: text or json")
	cmd.Flags().BoolVarP(&flags.verbose, "verbose", "v", false, "Enable verbose logging")
	cmd.Flags().BoolVar(&flags.strict, "strict", false, "Exit non-zero if any non-tolerated test fails or errors")
	_ = cmd.MarkFlagRequired("cmd")

	return cmd
}

func runSuite(ctx context.Context, cmd *cobra.Command, flags runFlags) error {
	args := parseList(flags.args)
	include := parseList(flags.tests)
	allow := toSet(parseList(flags.allowFailure))

	var stOut, stErr io.Writer
	if flags.verbose {
		stOut = cmd.ErrOrStderr()
		stErr = stOut
	}

	if flags.verbose {
		fmt.Fprintf(cmd.ErrOrStderr(), "Running suite with\ncmd:\t%s\nargs:\t%s\n", flags.cmd, flags.args)
	}

	cfg := suite.RunnerConfig{Cmd: flags.cmd, Args: args, StOut: stOut, StErr: stErr}

	cases, err := selectCases(include)
	if err != nil {
		return err
	}

	var report result.Report
	for _, tc := range cases {
		res, err := suite.RunOne(ctx, tc.Name, cfg)
		if err != nil {
			return err
		}
		if allow[res.Name] && (res.Status == result.StatusFail || res.Status == result.StatusError) {
			orig := res.Message
			res.Status = result.StatusSkip
			if orig != "" {
				res.Message = "tolerated failure: " + orig
			} else {
				res.Message = "tolerated failure"
			}
		}
		report.Add(res)
	}

	if err := printReport(report, flags.output); err != nil {
		return err
	}

	if flags.strict && (report.Failed > 0 || report.Errors > 0) {
		return fmt.Errorf("strict: %d failed, %d errored", report.Failed, report.Errors)
	}
	return nil
}

func selectCases(include []string) ([]suite.TestCase, error) {
	all := suite.All()
	if len(include) == 0 {
		return all, nil
	}
	want := toSet(include)
	var out []suite.TestCase
	for _, tc := range all {
		if want[tc.Name] {
			out = append(out, tc)
			delete(want, tc.Name)
		}
	}
	if len(want) > 0 {
		missing := make([]string, 0, len(want))
		for n := range want {
			missing = append(missing, n)
		}
		return nil, fmt.Errorf("unknown test case(s): %s", strings.Join(missing, ","))
	}
	return out, nil
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
		for _, r := range report.Results {
			fmt.Fprintf(os.Stdout, "[%s] %s: %s\n", r.Status, r.Name, r.Description)
			if r.Message != "" {
				fmt.Fprintf(os.Stdout, "       %s\n", r.Message)
			}
		}
		fmt.Fprintf(os.Stdout, "\nPassed: %d  Failed: %d  Errors: %d  Skipped: %d\n",
			report.Passed, report.Failed, report.Errors, report.Skipped)
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

func toSet(items []string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, i := range items {
		m[i] = true
	}
	return m
}
