# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

SPIFFE Conformance Test Suite — a black-box test suite for validating SPIFFE Workload API SDK implementations. The suite acts as a mock Workload API server, spawns an SDK under test as a subprocess, and validates correct SDK behavior by observing how it uses issued SVIDs.

Module: `github.com/arndt-s/spiffe-conformance-test-suite`

## Commands

```bash
go build ./...          # build all packages
go test ./...           # run all tests
go test ./... -run X1   # run a single test case by name
go vet ./...            # static analysis
```

## Architecture

### Control Flow

The suite drives each test case by:
1. Creating a fresh UDS path under a temp directory
2. Spawning `<cmd> <args>` with `SPIFFE_WORKLOAD_ENDPOINT=unix://<tmp-socket-path>`
3. Reading stdout until it sees `SPIFFE_JWT_PORT=<port>`, `SPIFFE_X509_PORT=<port>`, and `READY`
4. Running the test case (probing the SDK's exposed ports)
5. Terminating the subprocess and cleaning up

### Key Components

- **Mock Workload API server** — gRPC server over UDS implementing the SPIFFE Workload API; issues X.509 and JWT SVIDs under full test control
- **Test harness runner** — subprocess lifecycle management, stdout parsing, readiness detection (10s default timeout)
- **X.509 TLS prober** — dials the SDK's X.509 port via mTLS and inspects the presented certificate chain
- **JWT HTTP prober** — HTTP client to the SDK's JWT port; inspects returned token claims and signature
- **CA / key factory** — generates ephemeral trust domains, CA certs, and leaf SVIDs per test case

### Isolation Model

Each test case gets a fresh subprocess and UDS socket. No state is shared between test cases.

### SDK Harness Contract (stdout protocol)

```
SPIFFE_JWT_PORT=<os-assigned-port>
SPIFFE_X509_PORT=<os-assigned-port>
READY
```

Lines may appear in any order; `READY` must be last. The harness must have connected to the UDS before writing `READY`.

### MVP Test Cases

- **X1–X5**: X.509 SVID issuance, cert validity, trust bundle, SVID rotation, bundle-before-SVID rotation
- **J1–J5**: JWT SVID issuance, algorithm conformance, audience matching, expiry handling, bundle consistency

### CLI

```
suite run --cmd <binary> --args <arg1,arg2,...>
```

Supports `--output json` for machine-readable CI output.
