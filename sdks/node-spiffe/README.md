# node-spiffe

Conformance harness (contract v1, see `docs/HARNESS_CONTRACT.md`) for the
[`spiffe`](https://www.npmjs.com/package/spiffe) npm package by Depot
(github.com/depot/node-spiffe), pinned to **0.5.1** via `package-lock.json`.

## Prerequisites

- Node.js 22 and npm

## Build

From the repository root:

```bash
npm ci --prefix sdks/node-spiffe
npm run build --prefix sdks/node-spiffe
```

This produces `sdks/node-spiffe/dist/index.js`.

## Run conformance tests

From the repository root:

```bash
go run ./cmd/suite run --cmd node --args sdks/node-spiffe/dist/index.js
```

## What the SDK provides and how the harness uses it

`spiffe` 0.5.1 is a thin, generated gRPC client for the Workload API. It provides
`createClient()` (reads `SPIFFE_ENDPOINT_SOCKET` and sends the
`workload.spiffe.io: true` header), the raw RPCs, and `parseCertificate` /
`parseCertificateBundle` for DER data. It provides no X.509-SVID or JWT-SVID
validation, no bundle selection by trust domain, and no stream retry or
reconnect. The harness does not add any of those.

| Contract item | Implementation |
| --- | --- |
| Endpoint discovery | `createClient()` with no argument (uses `SPIFFE_ENDPOINT_SOCKET`) |
| X.509-SVID source | one `fetchX509SVID` stream; each response is applied as delivered (first SVID = default identity). If the stream ends, it is not reopened. |
| X.509 port, presenting the SVID | Node TLS server; `setSecureContext` on every response (PEM via `parseCertificateBundle`) |
| X.509 port, peer authentication | **None ("-" mode, contract §3 "SDKs without peer authentication").** The SDK has no API to authenticate peer X.509-SVIDs, and the harness substitutes no other mechanism: it requests no client certificate, configures no CA, and writes `-\n` after every handshake, then closes. The suite reports the peer-authentication tests (X10–X13) as `SKIP`; tests of the presented SVID still run. |
| `POST /v1/x509/dial` | `501 unsupported`: the SDK cannot authenticate a peer X.509-SVID |
| `POST /v1/jwt/validate` | `validateJWTSVID` RPC (delegated to the Workload API; the suite marks these results as delegated); gRPC `InvalidArgument` → `422 rejected`, other errors → `500` |
| `POST /v1/jwt/fetch` | `fetchJWTSVID` RPC with `audience` and optional `spiffe_id` |
| `GET /v1/info` | SDK name, version and language |
