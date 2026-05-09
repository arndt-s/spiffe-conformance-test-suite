# SPIFFE Conformance Test Suite

A black-box test suite for validating SPIFFE Workload API SDK implementations. The suite acts as a mock Workload API server, spawns an SDK under test as a subprocess, and validates correct SDK behavior by observing how it uses issued SVIDs.

## How It Works

The test suite validates SDK implementations by:

1. Creating a fresh Unix Domain Socket (UDS) under a temporary directory
2. Spawning the SDK under test with `SPIFFE_WORKLOAD_ENDPOINT=unix://<tmp-socket-path>`
3. Waiting for the SDK to signal readiness via stdout
4. Running test cases that probe the SDK's behavior
5. Terminating the subprocess and cleaning up

Each test case runs in complete isolation with its own subprocess, UDS socket, and ephemeral certificates.

## SDK Requirements

To be compatible with this conformance test suite, SDKs must implement the following behavior:

### Initialization

Upon invocation, the SDK must:

1. **Read the Workload API endpoint** from the `SPIFFE_WORKLOAD_ENDPOINT` environment variable
2. **Connect to the Workload API** over the Unix Domain Socket
3. **Print readiness signals** to stdout in the following format:
   ```
   SPIFFE_JWT_PORT=<port>
   SPIFFE_X509_PORT=<port>
   READY
   ```
   - Lines may appear in any order
   - `READY` must be the last line printed
   - Ports should be OS-assigned (typically using `:0`)
   - The SDK must have successfully connected to the Workload API before printing `READY`

### JWT SVID Endpoint

The SDK must expose an HTTP server on `SPIFFE_JWT_PORT` that:

- **Accepts requests** at `GET /jwt` or `POST /jwt`
- **Validates JWT-SVIDs** passed in the `Authorization: Bearer <JWT-SVID>` header
- **Checks audience** — must validate for audience `"conformance"` and reject any other audience
- **Returns JSON responses** with the following structure:

  ```json
  {
    "status": "valid",
    "spiffe_id": "spiffe://example.org/workload",
    "message": "Optional context message"
  }
  ```

  - `status`: `"valid"` on success, `"invalid"` or `"error"` on failure
  - `spiffe_id`: The SPIFFE ID extracted from the validated JWT-SVID
  - `message`: Optional human-readable context (especially useful for errors)

- **Use appropriate HTTP status codes**:
  - `200 OK` — JWT is valid and audience matches
  - `401 Unauthorized` — JWT is invalid, expired, or audience doesn't match

### X.509 SVID Endpoint

The SDK must expose a TLS server on `SPIFFE_X509_PORT` that:

- **Performs mutual TLS (mTLS)** using the X.509 SVID obtained from the Workload API
- **Presents the X.509 SVID certificate** to connecting clients
- **Validates client certificates** against the trust bundle from the Workload API
- **Accepts connections** from clients presenting valid certificates in the trust bundle

The test suite will connect to this port and verify:
- The presented certificate chain is valid
- The leaf certificate contains the expected SPIFFE ID
- Certificate rotation is handled correctly
- Trust bundle updates are applied

## Test Cases

### X.509 SVID Tests (X1–X5)

- **X1**: X.509 SVID issuance — verify SDK receives and uses a valid X.509 SVID
- **X2**: Certificate validity — ensure SDK rejects expired or invalid certificates
- **X3**: Trust bundle handling — validate SDK uses the correct trust bundle
- **X4**: SVID rotation — confirm SDK picks up new SVIDs when rotated
- **X5**: Bundle-before-SVID rotation — test rotation sequence edge cases

### JWT SVID Tests (J1–J5)

- **J1**: JWT SVID issuance — verify SDK receives and validates JWT SVIDs
- **J2**: Algorithm conformance — ensure SDK supports required signature algorithms
- **J3**: Audience matching — validate proper audience claim validation
- **J4**: Expiry handling — confirm SDK rejects expired JWTs
- **J5**: Bundle consistency — verify JWT validation uses current bundle

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
          tests: X1,X2,J1,J3        # optional; runs all if omitted
          allow-failure: X10,X11    # optional; failures here become SKIP
          strict: 'true'            # fail the job on any non-tolerated failure
          output: json
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
| `tests`          | no       | `''`     | Comma-separated test cases to run (e.g. `X1,J3`). Empty runs all.                          |
| `allow-failure`  | no       | `''`     | Comma-separated tests whose failures are tolerated (reported as `SKIP`, ignored by strict).|
| `strict`         | no       | `false`  | If `true`, fail the action on any non-tolerated test failure or error.                     |
| `output`         | no       | `text`   | Output format: `text` or `json`.                                                           |
| `results-file`   | no       | `''`     | Also write suite output to this path.                                                      |
| `verbose`        | no       | `false`  | Enable verbose logging.                                                                    |
| `suite-version`  | no       | `latest` | Suite version to install (git tag, branch, or `latest`).                                   |
| `go-version`     | no       | `stable` | Go toolchain version used to install the suite.                                            |

