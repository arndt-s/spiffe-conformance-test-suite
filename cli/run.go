package cli

import (
	"context"
	"encoding/json"
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
	cmd     string
	args    string
	run     string
	output  string
	verbose bool
}

func newRunCmd() *cobra.Command {
	var flags runFlags

	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run the conformance test suite against an SDK harness",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runSuite(cmd.Context(), cmd, flags)
		},
	}

	cmd.Flags().StringVar(&flags.cmd, "cmd", "", "Path to the SDK harness binary (required)")
	cmd.Flags().StringVar(&flags.args, "args", "", "Comma-separated arguments to pass to the harness")
	cmd.Flags().StringVar(&flags.run, "run", "", "Run only the named test case (e.g. X1)")
	cmd.Flags().StringVar(&flags.output, "output", "text", "Output format: text or json")
	cmd.Flags().BoolVarP(&flags.verbose, "verbose", "v", false, "Enable verbose logging")
	_ = cmd.MarkFlagRequired("cmd")

	return cmd
}

func runSuite(ctx context.Context, cmd *cobra.Command, flags runFlags) error {
	args := parseArgs(flags.args)

	var stOut, stErr io.Writer
	if flags.verbose {
		stOut = cmd.ErrOrStderr()
		stErr = stOut
	}

	if flags.verbose {
		fmt.Fprintf(cmd.ErrOrStderr(), "Running suite with\ncmd:\t%s\nargs:\t%s\n", flags.cmd, flags.args)
	}

	cfg := suite.RunnerConfig{Cmd: flags.cmd, Args: args, StOut: stOut, StErr: stErr}

	var report result.Report
	if flags.run != "" {
		res, err := suite.RunOne(ctx, flags.run, cfg)
		if err != nil {
			return err
		}
		report.Add(res)
	} else {
		report = suite.RunAll(ctx, cfg)
	}

	return printReport(report, flags.output)
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

func parseArgs(s string) []string {
	if s == "" {
		return nil
	}
	var args []string
	for _, a := range strings.Split(s, ",") {
		a = strings.TrimSpace(a)
		if a != "" {
			args = append(args, a)
		}
	}
	return args
}

// Ensure json import is used (it's used in printReport via report.JSON()).
var _ = json.Marshal
