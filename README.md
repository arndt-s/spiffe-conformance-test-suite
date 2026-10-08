# SPIFFE Conformance Test Suite

A black-box test suite for validating SPIFFE Workload API SDK implementations. The suite acts as a mock Workload API server, spawns an SDK under test as a subprocess, and validates correct SDK behavior by observing how it uses issued SVIDs.

## How It Works

The test suite validates SDK implementations by:

1. Creating a fresh Unix Domain Socket (UDS) under a temporary directory
2. Spawning the SDK under test with `SPIFFE_ENDPOINT_SOCKET=unix://<tmp-socket-path>`
3. Waiting for the SDK to signal readiness via stdout
4. Running test cases that probe the SDK's behavior
5. Terminating the subprocess and cleaning up

Each test case runs in complete isolation with its own subprocess, UDS socket, and ephemeral certificates.

## Running the suite

```bash
go run ./cmd/suite run --cmd <harness binary> [--args a,b,c] [--tests XV,JV-2] [--parallel 4] [--output json] [--results-file results.json]
```

- `--tests` selects test cases by catalogue ID, sub-result or group: `XV-8`
  runs `XV-8/server` and `XV-8/client`, `JV` runs every JWT validation test.
  Without it, every test case runs.
- `--parallel` runs that many test cases at once. Each test case still gets its
  own harness process and mock Workload API.

The report lists each result with its level (MUST/SHOULD/OPT) and spec
reference, followed by a **conformance claim per feature**:

| Claim | Meaning |
| --- | --- |
| `conformant` | Every MUST test of the feature passed. |
| `non-conformant` | At least one MUST test failed. |
| `incomplete` | No MUST test failed, but some were skipped or could not run. |
| `unsupported` | The harness does not support the feature. |

## Harnesses

The suite talks to an SDK through a small **harness** program that exposes the
SDK over a TLS port and an HTTP control port. The protocol is defined in
[docs/HARNESS_CONTRACT.md](docs/HARNESS_CONTRACT.md); `sdks/go-spiffe` is the
reference implementation.

Harnesses in this repository:

| SDK | Language | Directory |
| --- | --- | --- |
| [go-spiffe](https://github.com/spiffe/go-spiffe) | Go | `sdks/go-spiffe` |
| [java-spiffe](https://github.com/spiffe/java-spiffe) | Java | `sdks/java-spiffe` |
| [py-spiffe](https://github.com/HewlettPackard/py-spiffe) + spiffe-tls | Python | `sdks/py-spiffe` |
| [rust-spiffe](https://github.com/maxlambrecht/rust-spiffe) + spiffe-rustls | Rust | `sdks/rust-spiffe` |
| spiffe-defakto | Python | `sdks/spiffe-defakto-py` |
| @defakto/spiffe | TypeScript | `sdks/defakto-spiffe-ts` |
| [spiffe](https://github.com/depot/node-spiffe) (Depot) | TypeScript | `sdks/node-spiffe` |
| [@jeengbe/spiffe](https://github.com/jeengbe/ts-packages) | TypeScript | `sdks/jeengbe-spiffe` |

Each directory's README has its build and run commands.

## Test cases

Every test case is derived from a requirement the SPIFFE specifications place on
Workload API clients, and is listed in
[docs/TEST_CATALOGUE.md](docs/TEST_CATALOGUE.md) with its level and spec
reference:

| Group | Covers |
| --- | --- |
| `EP` | Workload Endpoint: discovery, security header, error codes and retries |
| `WA` | Workload API client behaviour: reconnects, malformed responses, default identity |
| `XS` | The X.509-SVID the SDK presents: chains, rotation, bundle updates |
| `XV` | Peer X.509-SVID validation, as TLS server and as TLS client |
| `XF` | X.509 federation |
| `JV` | JWT-SVID validation |
| `JB` | JWT bundles: rotation, key selection, JWK handling |
| `JF` | Fetching JWT-SVIDs |
| `ID` | SPIFFE ID parsing |
| `HX` | Optional hardening (not required by any spec) |

## GitHub Action

This repository ships a composite GitHub Action that installs the suite and runs it against your SDK harness.

```yaml
jobs:
  conformance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Build your SDK harness here, e.g.:
      # - run: go build -o ./bin/harness ./cmd/harness

      - uses: arndt-s/spiffe-conformance-test-suite@v1
        with:
          cmd: ./bin/harness
          args: --foo,--bar
          tests: XS,XV,JV           # optional; runs all if omitted
          results-file: conformance.json

      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: conformance-results
          path: conformance.json
```

### Inputs

| Input            | Required | Default  | Description                                                                                |
| ---------------- | -------- | -------- | ------------------------------------------------------------------------------------------ |
| `cmd`            | yes      | —        | Path to the SDK harness binary to test.                                                    |
| `args`           | no       | `''`     | Comma-separated arguments to pass to the harness.                                          |
| `tests`          | no       | `''`     | Comma-separated test IDs or groups to run (e.g. `XV,JV-2`). Empty runs all.                |
| `output`         | no       | `text`   | Log output format: `text` or `json`.                                                       |
| `parallel`       | no       | `1`      | Number of test cases to run concurrently.                                                  |
| `ready-timeout`  | no       | `10s`    | How long to wait for the harness to print `READY`.                                         |
| `results-file`   | no       | `''`     | Also write the results as JSON to this path (defaults to a file in `$RUNNER_TEMP`).        |
| `verbose`        | no       | `false`  | Enable verbose logging.                                                                    |
| `suite-version`  | no       | `latest` | Suite version to install (git tag, branch, or `latest`).                                   |
| `go-version`     | no       | `stable` | Go toolchain version used to install the suite.                                            |

### Results vs. run status

A test result is the outcome of the run, not a reason to fail it. An SDK that
fails test cases is reported as such, and the run still succeeds.

- `suite run` exits **0** when every selected test case executed, whatever its
  result (`PASS`, `FAIL`, `SKIP`); **2** when one or more test cases could not be
  executed (`ERROR`: the harness did not start, the suite could not build its
  fixtures, or a test panicked); and **1** for invalid usage.
- The action fails only in the `ERROR` case. It writes a results table to the job
  summary and exposes the counts as outputs (`passed`, `failed`, `skipped`,
  `errors`, `results-file`), so a workflow that wants to gate on results can do so
  explicitly:

```yaml
      - id: conformance
        uses: arndt-s/spiffe-conformance-test-suite@v1
        with:
          cmd: ./bin/harness
      - if: steps.conformance.outputs.failed != '0'
        run: exit 1
```
