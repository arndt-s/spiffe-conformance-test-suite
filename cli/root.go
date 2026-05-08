// Package cli provides the cobra command tree for the SPIFFE Conformance Test Suite.
package cli

import "github.com/spf13/cobra"

// NewRootCmd builds and returns the root cobra command.
func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "suite",
		Short: "SPIFFE Conformance Test Suite",
		Long: `suite validates SPIFFE Workload API SDK implementations by acting as
a mock Workload API server and driving the SDK under test as a subprocess.`,
	}
	root.AddCommand(newRunCmd())
	return root
}
