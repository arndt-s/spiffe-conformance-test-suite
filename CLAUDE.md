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
2. Spawning `<cmd> <args>` with `SPIFFE_ENDPOINT_SOCKET=unix://<tmp-socket-path>`
3. Reading stdout until `READY` (contract v1: `SPIFFE_HARNESS_VERSION=1`, `SPIFFE_X509_PORT`, `SPIFFE_CONTROL_PORT`; deprecated v0: `SPIFFE_X509_PORT`, `SPIFFE_JWT_PORT`)
4. Running the test case (probing the SDK's exposed ports)
5. Terminating the subprocess and cleaning up

### Key Components

- **Mock Workload API server** — gRPC server over UDS implementing the SPIFFE Workload API; issues X.509 and JWT SVIDs under full test control
- **Test harness runner** — subprocess lifecycle (own process group, SIGTERM then SIGKILL), stdout parsing, readiness detection (10s default timeout), stderr tail in errors
- **X.509 TLS prober** — dials the SDK's X.509 port via mTLS and inspects the presented certificate chain
- **Control-port client** — HTTP client for the harness's v1 control endpoints (JWT validate/fetch, X.509 dial)
- **CA / key factory** — generates ephemeral trust domains, CA certs, and leaf SVIDs per test case

### Isolation Model

Each test case gets a fresh subprocess and UDS socket. No state is shared between test cases.

### SDK Harness Contract

Defined in `docs/HARNESS_CONTRACT.md` (v1). Harnesses live in `sdks/<name>/`; `sdks/go-spiffe` is the reference. Test cases and their spec references are defined in `docs/TEST_CATALOGUE.md`.

Test results (PASS/FAIL/SKIP) never fail a run; only ERROR (test could not be executed) does. Tests return `suite.ExecErrorf` for setup problems and `suite.Skipf` when the harness lacks a capability.

### Test Cases

Currently registered: X1–X13 and J1–J13 (legacy IDs, mapped to catalogue IDs in `docs/TEST_CATALOGUE.md` §9), plus catalogue tests JF-1 and XV-1/client. New tests use catalogue IDs.

### CLI

```
suite run --cmd <binary> --args <arg1,arg2,...>
```

Supports `--output json` for machine-readable CI output.
