# rust-spiffe harness

Conformance harness (contract v1, see `docs/HARNESS_CONTRACT.md`) for
[rust-spiffe](https://github.com/maxlambrecht/rust-spiffe):
`spiffe` 0.18.0 and `spiffe-rustls` 0.10.0.

It uses only the SDK's public APIs:

| Contract part | SDK API |
| --- | --- |
| Workload API discovery | `X509Source::new()`, `JwtSource::new()`, `WorkloadApiClient::connect_env()` (all read `SPIFFE_ENDPOINT_SOCKET`) |
| X.509 port | `spiffe_rustls::mtls_server(source).authorize(authorizer::any())` + `tokio-rustls`; peer ID via `spiffe::cert::spiffe_id_from_der` |
| `POST /v1/x509/dial` | `spiffe_rustls::mtls_client(source).authorize(authorizer::any())` |
| `POST /v1/jwt/validate` | `JwtSvid::parse_and_validate(token, &jwt_source, &[audience])` (offline, `jwt-verify-rust-crypto` backend) |
| `POST /v1/jwt/fetch` | `WorkloadApiClient::fetch_all_jwt_svids(audience, spiffe_id)` |

`/v1/jwt/validate` returns only the claims the SDK exposes (`sub`, `aud`, `exp`).

## Prerequisites

- Rust toolchain (stable, edition 2021; tested with cargo 1.97)
- A C compiler (for `ring`)
- Go (to build the suite)

## Build

From the repository root:

```bash
cargo build --release --locked --manifest-path sdks/rust-spiffe/Cargo.toml
```

The binary is `sdks/rust-spiffe/target/release/rust-spiffe-harness`.

## Run the conformance tests

From the repository root:

```bash
go build -o suite ./cmd/suite
./suite run --cmd sdks/rust-spiffe/target/release/rust-spiffe-harness
```

Logs go to stderr (`RUST_LOG` controls the level, default `info`); add `-v` to
`suite run` to see them.
