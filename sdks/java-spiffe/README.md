# java-spiffe

Conformance harness (contract v1, see `docs/HARNESS_CONTRACT.md`) for
[java-spiffe](https://github.com/spiffe/java-spiffe) `0.8.17`
(`io.spiffe:java-spiffe-core`, `io.spiffe:java-spiffe-provider`).

It uses only java-spiffe's public APIs:

| Contract part | java-spiffe API |
| --- | --- |
| Endpoint discovery | `DefaultWorkloadApiClient.newClient()` / `DefaultJwtSource.newSource()` (read `SPIFFE_ENDPOINT_SOCKET`) |
| X.509 port (mTLS server) | `DefaultX509Source` + `SpiffeSslContextFactory` (`SpiffeKeyManager`, `SpiffeTrustManager`, `acceptAnySpiffeId()`) |
| `/v1/x509/dial` | same `SSLContext`, client mode |
| `/v1/jwt/validate` | `JwtSvid.parseAndValidate(token, DefaultJwtSource, {audience})` |
| `/v1/jwt/fetch` | `WorkloadApiClient.fetchJwtSvids(...)` |

## Prerequisites

- JDK 17 or newer
- Maven 3.8+
- Linux (x86_64 or aarch64): the Workload API client uses netty epoll for Unix
  domain sockets (`io.spiffe:grpc-netty-linux`).

## Build

From the repository root:

```bash
mvn -B -f sdks/java-spiffe/pom.xml package
```

This produces the shaded jar `sdks/java-spiffe/target/harness.jar`.

## Run the conformance tests

From the repository root:

```bash
go run ./cmd/suite run --cmd java --args "-jar,sdks/java-spiffe/target/harness.jar"
```
