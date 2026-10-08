# defakto-spiffe-ts

Conformance harness for [`@defakto/spiffe`](https://www.npmjs.com/package/@defakto/spiffe)
(TypeScript), pinned to **0.7.0**. It implements harness contract v1
([`docs/HARNESS_CONTRACT.md`](../../docs/HARNESS_CONTRACT.md)).

| Contract feature | SDK API used |
| --- | --- |
| Endpoint discovery | `new WorkloadAPIClient()` (reads `SPIFFE_ENDPOINT_SOCKET`) |
| X.509 port: presented SVID + rotation | `client.x509.watchSVID()` + `marshalX509SVID()` |
| X.509 port: client authentication | `verifyX509SVID(peerChain, client.x509)` |
| `POST /v1/x509/dial` | `verifyX509SVID(peerChain, client.x509)` |
| `POST /v1/jwt/validate` | `parseAndValidateJwtSVID(token, client.jwt, [audience])` |
| `POST /v1/jwt/fetch` | `client.jwt.fetchSVID(audience)` |

Node's TLS stack is only the transport: it runs with `rejectUnauthorized: false`
and no `ca`, and every peer chain goes to the SDK's `verifyX509SVID`.

Limitations of the SDK API:

- `/v1/jwt/fetch` with a non-empty `spiffe_id` answers `501 unsupported`:
  `fetchSVID(audiences)` cannot request a specific identity.
- `/v1/jwt/fetch` returns one SVID (the SDK returns only the default one) with an
  empty `hint`, because the SDK does not expose hints.

## Prerequisites

- Node.js 22 (the SDK requires >= 18) and npm
- Go, to build the suite

## Build

From the repository root:

```bash
npm ci --prefix sdks/defakto-spiffe-ts
npm run build --prefix sdks/defakto-spiffe-ts
```

This produces `sdks/defakto-spiffe-ts/dist/index.js`.

## Run the conformance tests

From the repository root:

```bash
go build -o bin/suite ./cmd/suite
./bin/suite run --cmd node --args sdks/defakto-spiffe-ts/dist/index.js
```

Add `-v` to stream the harness output to stderr, or `--output json` for
machine-readable results.
