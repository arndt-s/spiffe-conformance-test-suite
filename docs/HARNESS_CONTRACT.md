# SDK Harness Contract — v1 (draft)

> **Status: Draft, implemented.** The suite speaks v1. It still accepts v0
> harnesses (no `SPIFFE_HARNESS_VERSION` line, `SPIFFE_JWT_PORT`) so that existing
> harnesses keep working, but tests that need v1 endpoints are reported as `SKIP`
> for them. v0 support will be removed before the first tagged release.
> `sdks/go-spiffe` is the reference v1 harness.

A *harness* is a small program, written once per SDK, that exposes the SDK's
behaviour to the suite over the network. The suite never links against an SDK; it
only observes what the harness does. Everything a harness author needs to know is
in this document.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Design rules

1. **The harness is a thin shim.** It MUST delegate every SPIFFE decision (endpoint
   discovery, stream handling, SVID selection, bundle selection, certificate and
   token validation) to the SDK using the SDK's documented, idiomatic APIs. A
   harness that re-implements validation is testing itself, not the SDK.
2. **Authorization is out of scope.** Wherever the harness authenticates a peer it
   MUST authorize *any* SPIFFE ID (e.g. go-spiffe `tlsconfig.AuthorizeAny()`).
   The suite tests authentication; authorization policy is application code.
3. **Stream handling is the SDK's job.** Reconnecting, retrying after errors and
   re-subscribing are behaviours the suite tests (`EP`, `WA`). The harness MUST
   NOT add them. If the SDK's watch or stream ends and the SDK does not recover,
   the harness keeps serving whatever the SDK last provided.
4. **Unsupported means unsupported.** If the SDK cannot perform an operation, the
   harness MUST answer `501 Not Implemented` (see §5). The suite reports the
   affected tests as `SKIP`, never as `PASS`.

## 2. Process lifecycle

The suite starts the harness as `<cmd> <args...>` once per test case. No state may
survive between runs (no files, no caches outside the process).

### 2.1 Environment

| Variable | Value |
| --- | --- |
| `SPIFFE_ENDPOINT_SOCKET` | `unix:///<absolute path>` of the mock Workload API |

The harness MUST NOT configure the Workload API address explicitly. It MUST let
the SDK discover it from `SPIFFE_ENDPOINT_SOCKET`, which is the fallback the
Workload Endpoint specification (§4) requires. Some test cases deliberately set
malformed or `tcp://` values.

### 2.2 Listeners

The harness opens two listeners on `127.0.0.1` with OS-assigned ports (`:0`):

- the **X.509 port**: a TLS server (§3)
- the **control port**: a plain HTTP/1.1 server (§4)

### 2.3 Readiness (stdout)

The harness prints the following lines to **stdout**, each terminated by `\n`:

```
SPIFFE_HARNESS_VERSION=1
SPIFFE_X509_PORT=<port>
SPIFFE_CONTROL_PORT=<port>
READY
```

- The first three lines may appear in any order; `READY` MUST come last.
- `READY` MUST NOT be printed until both listeners accept connections **and** the
  SDK has received at least one X.509-SVID from the Workload API.
- Any other stdout lines are ignored. Logs SHOULD go to stderr; the suite attaches
  the tail of stderr to `ERROR` results.
- If the SDK never receives an SVID (for example, a test that answers every call
  with `InvalidArgument`), the harness simply never prints `READY`. It MAY exit.

The default readiness timeout is 10 s. Test cases that inject Workload API errors
extend it.

### 2.4 Termination

The suite sends `SIGTERM` to the harness's process group, waits up to 5 s, then
sends `SIGKILL`. The harness SHOULD exit promptly on `SIGTERM`.

## 3. X.509 port

A TLS server (TLS 1.2 or 1.3; 1.3 recommended) that:

1. presents the SDK's **current default X.509-SVID** (the first SVID in the latest
   `X509SVIDResponse`, Workload API §8), together with any intermediates, leaf
   first. Rotations MUST take effect for new connections without a restart.
2. **requires** a client certificate and authenticates it as an X.509-SVID
   (X509-SVID §5), using the bundle for the client's trust domain: the SDK's own
   trust domain bundle or a federated bundle.
3. after a successful handshake, writes the client's SPIFFE ID followed by `\n`,
   then closes the connection.
4. on authentication failure, aborts the handshake (TLS alert) or closes the
   connection without writing anything.

The line MUST be the client's SPIFFE ID as extracted by the SDK. An empty line
is treated as a rejection.

**SDKs without peer authentication.** If the SDK offers no way to authenticate
peer X.509-SVIDs, the harness MUST NOT substitute another mechanism (e.g. plain
OpenSSL/Node chain verification against the bundle). Instead it serves the
SDK's SVID without requesting a client certificate and writes `-\n` after every
handshake. The suite then reports peer-authentication tests as `SKIP`, while
tests of the presented SVID still run.

The suite reads the line to tell an accepted client from a rejected one.
Rejection is otherwise invisible under TLS 1.3, where the client's handshake
completes before the server has checked the client certificate.

## 4. Control port

Plain HTTP/1.1 on `127.0.0.1`. Requests and responses are JSON
(`Content-Type: application/json`). All endpoints are `POST` unless noted.

### 4.1 Response envelope

| HTTP status | `status` field | Meaning |
| --- | --- | --- |
| 200 | `"ok"` | The SDK performed the operation and it succeeded. |
| 422 | `"rejected"` | The SDK performed the operation and rejected the input (e.g. invalid token, untrusted peer). |
| 500 | `"error"` | The harness could not perform the operation (bad request, SDK crash, Workload API unreachable). |
| 501 | `"unsupported"` | The SDK does not support this operation. |

Every response body carries `status` and MAY carry `message` (free text, shown in
reports). Negative test cases pass **only** on `rejected`; an `error` is reported
as `ERROR`, so a broken harness can't pass negative tests.

### 4.2 `POST /v1/jwt/validate`

Validates a JWT-SVID with the SDK, using JWT bundles from the Workload API.

Request:
```json
{ "token": "<compact JWS>", "audience": "conformance" }
```
`audience` is the single audience the validator identifies with (JWT-SVID §3.2).

Response (`200`):
```json
{ "status": "ok", "spiffe_id": "spiffe://example.org/workload", "claims": { "...": "..." } }
```

If the SDK validates by calling the Workload API's `ValidateJWTSVID` RPC, that is
allowed (Workload API §6.3). The suite detects it and marks the JWT validation
results as *delegated*, because they then exercise the mock server rather than the
SDK.

### 4.3 `POST /v1/jwt/fetch`

Fetches JWT-SVIDs through the SDK (Workload API `FetchJWTSVID`).

Request:
```json
{ "audience": ["conformance"], "spiffe_id": "" }
```
`spiffe_id` is optional; when it is non-empty the SDK MUST request that specific
identity.

Response (`200`):
```json
{ "status": "ok", "svids": [ { "spiffe_id": "spiffe://...", "token": "<jws>", "hint": "" } ] }
```
If the SDK API returns only the default SVID, return a one-element list.

### 4.4 `POST /v1/x509/dial`

Makes the SDK act as an mTLS **client**. The harness connects to `address`,
presents the SDK's current default X.509-SVID, and authenticates the server
certificate as an X.509-SVID (X509-SVID §5), authorizing any SPIFFE ID.

Request:
```json
{ "address": "127.0.0.1:34567" }
```

Response (`200`):
```json
{ "status": "ok", "spiffe_id": "<server SPIFFE ID>" }
```
Return `422 rejected` if the SDK refuses the server certificate.

### 4.5 `GET /v1/info` (optional)

Report metadata only; it never affects results.
```json
{ "sdk": "go-spiffe", "sdk_version": "v2.6.0", "language": "go" }
```

## 5. Feature groups

A harness MAY implement a subset of the control endpoints. The suite groups test
cases by the endpoints they need and reports each group separately:

| Feature | Requires |
| --- | --- |
| `x509-server` | X.509 port (mandatory for every harness) |
| `x509-client` | `/v1/x509/dial` |
| `jwt-validate` | `/v1/jwt/validate` |
| `jwt-fetch` | `/v1/jwt/fetch` |

## 6. Changes from v0

| v0 | v1 |
| --- | --- |
| `SPIFFE_JWT_PORT`, `GET/POST /jwt` with `Authorization: Bearer` and a fixed `conformance` audience | `SPIFFE_CONTROL_PORT`, `POST /v1/jwt/validate` with the audience in the body |
| X.509 port held the connection open, client certs optional | X.509 port MUST require and authenticate client certificates and write the peer ID |
| no way to exercise `FetchJWTSVID` or the SDK as TLS client | `/v1/jwt/fetch`, `/v1/x509/dial` |
| no version line | `SPIFFE_HARNESS_VERSION=1` |
| JWT rejection as `401` | `422 rejected`; `500 error` is distinct from rejection |
