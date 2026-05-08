// Command suite is the CLI entry point for the SPIFFE Conformance Test Suite.
package main

import (
	"fmt"
	"os"

	"github.com/arndt-s/spiffe-conformance-test-suite/cli"
)

func main() {
	if err := cli.NewRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
