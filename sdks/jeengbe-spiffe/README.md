# jeengbe-spiffe

Conformance harness (contract v1, see `docs/HARNESS_CONTRACT.md`) for
[`@jeengbe/spiffe`](https://www.npmjs.com/package/@jeengbe/spiffe) **2.1.0**
(pinned in `package.json` / `package-lock.json`).

## What the SDK covers

`@jeengbe/spiffe` is a Workload API client whose high-level API is JWT-only.
For X.509 its README points users at the raw gRPC client (`SpiffeClient.api`).

| Harness surface | How it is implemented |
| --- | --- |
| Endpoint discovery | `new SpiffeClient()`, which reads `SPIFFE_ENDPOINT_SOCKET` |
| X.509 port, served SVID | `client.api.fetchX509SVID({})` stream (raw RPC), first SVID of each response installed with `tls.Server#setSecureContext`. The SDK does not validate or parse X.509-SVIDs and does not reconnect the stream; per contract rule 3 the harness adds neither and keeps serving the last SVID. |
| X.509 port, client authentication | **None.** The SDK cannot authenticate peer X.509-SVIDs, so the port runs in the contract's `-` mode (`docs/HARNESS_CONTRACT.md` §3, "SDKs without peer authentication"): no client certificate is requested, no substitute verification (Node/OpenSSL `ca`) is done, and the harness writes `-\n` after every handshake, then closes. The suite reports the peer-authentication tests (X10–X13) as `SKIP`. |
| `POST /v1/x509/dial` | `501 unsupported` (no X.509-SVID peer authentication in the SDK) |
| `POST /v1/jwt/validate` | `client.validateJwt(audience, token)`, which delegates to the Workload API's `ValidateJWTSVID` RPC. Results are cached by the SDK. |
| `POST /v1/jwt/fetch` | `client.getJwtSvid(audience, { spiffeId })`, which returns only the first SVID |
| `GET /v1/info` | static metadata |

## Prerequisites

- Node.js 22+ and npm

## Build

From the repository root:

```bash
cd sdks/jeengbe-spiffe
npm ci
npm run build
```

This produces `sdks/jeengbe-spiffe/dist/index.js`.

## Run the conformance suite

From the repository root:

```bash
go run ./cmd/suite run --cmd node --args sdks/jeengbe-spiffe/dist/index.js
```

Or with a prebuilt suite binary: `suite run --cmd node --args sdks/jeengbe-spiffe/dist/index.js`.
