# spiffe-defakto (Python)

Conformance harness (contract v1, see `docs/HARNESS_CONTRACT.md`) for
[`spiffe-defakto`](https://pypi.org/project/spiffe-defakto/) 1.1.0, Defakto's
Python SDK. Only the SDK's standard SPIFFE Workload API features are used:

| Harness duty | SDK API |
| --- | --- |
| Endpoint discovery | `WorkloadAPIClient()` (reads `SPIFFE_ENDPOINT_SOCKET`) |
| Own SVID + rotation | `client.watch_x509_context()` → `X509Context.default_svid()` |
| Peer authentication (X.509 port, `/v1/x509/dial`) | `verify_x509_svid(peer_chain, client.x509)` |
| `/v1/jwt/validate` | `parse_and_validate_jwt_svid(token, client.jwt, [audience])` |
| `/v1/jwt/fetch` | `client.jwt.fetch_svid(audience)` |

The SDK has no TLS integration, and Python's `ssl` module cannot request a
client certificate without verifying it against a CA store itself. TLS is
therefore carried by pyOpenSSL with an accept-all verify callback; the peer
chain is then passed to the SDK's `verify_x509_svid`, which makes the trust
decision. Rejected peers are disconnected without the ID line.

Notes:

- `/v1/jwt/fetch` with a non-empty `spiffe_id` answers `501`: `fetch_svid()`
  cannot request a specific identity, and returns only the first JWT-SVID.
- `watch_x509_context()` raises on any RPC or parse error and does not retry;
  the harness does not retry for it, and keeps serving the last SVID it got.

## Prerequisites

- Python 3.10+ (tested with 3.13) with `venv` and `pip`
- Network access to PyPI for the setup step

## Setup

From the repository root:

```bash
python3 -m venv sdks/spiffe-defakto-py/.venv
sdks/spiffe-defakto-py/.venv/bin/pip install -r sdks/spiffe-defakto-py/requirements.txt
```

## Run conformance tests

From the repository root:

```bash
go run ./cmd/suite run --cmd sdks/spiffe-defakto-py/.venv/bin/python --args sdks/spiffe-defakto-py/harness.py
```
