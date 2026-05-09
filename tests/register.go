// Package tests is a blank-import aggregator that ensures all test-case
// init() functions run when the CLI imports this package.
package tests

import (
	_ "github.com/arndt-s/spiffe-conformance-test-suite/tests/endpoint"
	_ "github.com/arndt-s/spiffe-conformance-test-suite/tests/jwt"
	_ "github.com/arndt-s/spiffe-conformance-test-suite/tests/workloadapi"
	_ "github.com/arndt-s/spiffe-conformance-test-suite/tests/x509"
)
