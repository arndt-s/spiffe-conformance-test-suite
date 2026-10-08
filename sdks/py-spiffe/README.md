# py-spiffe

Conformance harness (contract v1, see `docs/HARNESS_CONTRACT.md`) for
[py-spiffe](https://github.com/HewlettPackard/py-spiffe): PyPI `spiffe` 0.3.2 and
`spiffe-tls` 0.4.0.

It uses only py-spiffe's public APIs:

| Contract part | py-spiffe API |
| --- | --- |
| Endpoint discovery | `WorkloadApiClient()` (reads `SPIFFE_ENDPOINT_SOCKET`) |
| X.509 SVID/bundles | `X509Source` |
| X.509 port (mTLS server) | `spiffetls.listen` with `ServerTlsMode.MTLS` and `authorize_any()` |
| `POST /v1/x509/dial` | `spiffetls.dial` with `ClientTlsMode.TLS` and `authorize_any()` |
| `POST /v1/jwt/validate` | `JwtSource` (created lazily) + `JwtSvid.parse_and_validate`, with the bundle picked by the token's trust domain as that method's docstring says |
| `POST /v1/jwt/fetch` | `WorkloadApiClient.fetch_jwt_svids` |

Limitations of the SDK API that show up in responses:

- `JwtSvid` has no public claims accessor, so `/v1/jwt/validate` returns only `spiffe_id`.
- `JwtSvid` does not expose the Workload API `hint`, so `/v1/jwt/fetch` returns `"hint": ""`.
- py-spiffe has no public "SPIFFE ID from certificate" helper. After spiffe-tls has
  authenticated the peer, the harness reads the URI SAN and parses it with `SpiffeId`.

## Prerequisites

- Python 3.13 (3.10 or later should work) with `venv` and `pip`
- Access to PyPI

## Setup

From the repository root:

```bash
python3 -m venv sdks/py-spiffe/.venv
sdks/py-spiffe/.venv/bin/pip install -r sdks/py-spiffe/requirements.txt
```

## Run the conformance tests

From the repository root:

```bash
go run ./cmd/suite run --cmd sdks/py-spiffe/.venv/bin/python --args sdks/py-spiffe/harness.py
```

Add `-v` to stream the harness's stderr, or `--tests X1,J1` to select tests.
