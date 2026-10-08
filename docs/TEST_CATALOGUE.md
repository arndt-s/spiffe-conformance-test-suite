# Test Catalogue

> This catalogue is the source of truth for which test cases exist, what each
> one asserts, and why. Test IDs are stable once released. Sub-results carry a
> `/<variant>` suffix (e.g. `XV-8/server`, `JV-2/RS256`). The
> [mapping table](#9-mapping-from-earlier-tests) shows how the earlier X1–X13 /
> J1–J13 tests map onto it.

Every test case comes from a requirement on a **Workload API client / SDK** in the
SPIFFE specifications. Requirements on servers, issuers or control planes are out
of scope, except where the client must cope with a server misbehaving.

## 1. Conventions

### 1.1 Levels and profiles

| Level | Source | Profile | Effect on a conformance claim |
| --- | --- | --- | --- |
| **MUST** | spec MUST / MUST NOT, or functionality without which the profile is meaningless | `core` | Any failure → not conformant |
| **SHOULD** | spec SHOULD / SHOULD NOT | `recommended` | Reported, does not block the claim |
| **OPT** | spec MAY, or hardening that no spec requires | `optional` | Informational only |

Levels follow the specification text only. A test is never downgraded, skipped
or tolerated because a widely used SDK fails it; an SDK that does not conform
fails. In particular:

- **Accepting a valid SVID is MUST.** If the specs make an input a valid SVID
  (e.g. an allowed `alg`, an optional header left out), rejecting it is
  non-conformance.
- **Rejecting an invalid SVID is MUST.** If the specs make an input invalid
  (a MUST or MUST NOT in the SVID format, or in RFC processing the spec
  incorporates), accepting it is non-conformance.
- **SHOULD is reserved for client behaviour the spec itself words as SHOULD**
  (retries, reconnects, discarding malformed responses). A failing SHOULD
  test is still reported as `FAIL`, but it does not block the claim.

### 1.2 Results and run status

Each test case has exactly one result:

| Result | Meaning |
| --- | --- |
| `PASS` | The SDK behaved as the requirement demands. |
| `FAIL` | The SDK did not. This is a finding about the SDK, not a problem with the run. |
| `SKIP` | The harness reported the operation as `unsupported`. |
| `ERROR` | The test could not be executed (harness did not start, fixture setup failed, the test panicked). Nothing was learned about the SDK. |

Results are never rewritten: there is no way to turn a `FAIL` into a `SKIP`.
A run fails (non-zero exit) only if a test case ended in `ERROR`.

An SDK is **conformant for a feature group** (see
[harness contract §5](HARNESS_CONTRACT.md#5-feature-groups)) when every `core` test
in that group passes. Tests that the harness answers with `unsupported` are reported
as `SKIP`, and they exclude that feature group from the claim.

### 1.3 Spec references

| Abbrev. | Document |
| --- | --- |
| ID | The SPIFFE Identity and Verifiable Identity Document (`SPIFFE-ID.md`) |
| WE | The SPIFFE Workload Endpoint (`SPIFFE_Workload_Endpoint.md`) |
| WA | The SPIFFE Workload API (`SPIFFE_Workload_API.md`) |
| XS | The X.509 SPIFFE Verifiable Identity Document (`X509-SVID.md`) |
| JS | The JWT SPIFFE Verifiable Identity Document (`JWT-SVID.md`) |
| TB | The SPIFFE Trust Domain and Bundle (`SPIFFE_Trust_Domain_and_Bundle.md`) |
| FD | SPIFFE Federation (`SPIFFE_Federation.md`) |

### 1.4 Roles (X.509 peer validation)

`XV` and `XF` tests run in up to two roles, reported as separate results
(`XV-7/server`, `XV-7/client`):

- **server**: the suite connects to the harness's X.509 port with the test
  certificate as the *client* certificate (feature `x509-server`).
- **client**: the suite runs a TLS server with the test certificate and asks the
  harness to dial it with `/v1/x509/dial` (feature `x509-client`).

## 2. Methodology

These rules apply to every test and close the loopholes in the current suite.

1. **Positive control before every negative assertion.** Each negative test first
   shows that the same harness, with the same bundles, *accepts* a valid
   counterpart (a valid token or a valid peer certificate). A harness that rejects
   everything therefore fails instead of passing.
2. **No sleeps to prove that nothing happened.** To show the SDK ignored an update,
   the test pushes the bad update, then a *barrier* update (a new valid SVID or
   bundle), and waits for the barrier to take effect. Because the stream is
   ordered, the SDK has processed the bad update by then. The assertion is that the
   bad state was never observed.
3. **Workload API calls are recorded.** The mock server records every RPC: method,
   metadata, request, and the status it returned. Tests assert on this record (for
   example "every call carried the security header", "no retry after
   InvalidArgument").
4. **Delegated validation is flagged.** If the harness ever calls `ValidateJWTSVID`,
   the `JV`/`JB`/`ID` results are marked *delegated*. Those results then test the
   mock server, not the SDK.
5. **Rejection detection is protocol-level.** X.509 acceptance is the peer-ID line
   from the [harness contract](HARNESS_CONTRACT.md#3-x509-port), never a successful
   `tls.Dial` (see §3 of the contract for why).

## 3. Workload Endpoint — `EP` (feature `x509-server`)

| ID | Requirement | Level | Ref | Method |
| --- | --- | --- | --- | --- |
| EP-1 | Discovers the endpoint from `SPIFFE_ENDPOINT_SOCKET` when not explicitly configured | MUST | WE §4 | Implicit in every test; explicit here: the harness gets no other configuration and reaches `READY`. |
| EP-2 | Sends metadata `workload.spiffe.io: true` on every RPC | MUST | WE §3 | Exercise X.509, JWT bundle and JWT fetch paths; every recorded call must carry the header. |
| EP-3 | Supports a `tcp://127.0.0.1:<port>` endpoint | SHOULD | WE §3, §4 | Mock listens on TCP only; expect `READY`. |
| EP-4 | Rejects an endpoint URI with an authority (`unix://host/abs/path`) or a path on `tcp://` | OPT | WE §4 | The path points at a working socket; a lenient client connects and prints `READY`. Expect no `READY` and zero recorded calls. |
| EP-5 | Retries with backoff after `Unavailable` | SHOULD | WE §6, App. A | First 3 `FetchX509SVID` calls return `Unavailable`; expect `READY` and no tight retry loop (< 20 calls/s). |
| EP-6 | Retries with backoff after `PermissionDenied` | SHOULD | WE §6, App. A | As EP-5 with `PermissionDenied`. |
| EP-7 | Does not retry after `InvalidArgument` | SHOULD | WE §6, App. A | Every call returns `InvalidArgument` for 5 s; expect ≤ 2 calls per RPC method. |
| EP-8 | Retries when the endpoint is not reachable yet | OPT | WE §6 | The socket is created 2 s after the harness starts; expect `READY`. |

## 4. Workload API client behaviour — `WA` (feature `x509-server`)

| ID | Requirement | Level | Ref | Method |
| --- | --- | --- | --- | --- |
| WA-1 | Re-establishes the stream after the server closes it | SHOULD | WA §4.2 | Close all streams with `Unavailable`; push SVID B on the new stream; expect B on the X.509 port. |
| WA-2 | Discards a response in which a mandatory field has its default value | SHOULD | WA §4.5 | After SVID A, push one variant (empty `svids`, empty `spiffe_id`, empty `x509_svid`, empty `x509_svid_key`, empty `bundle`), then barrier SVID B. A is served until B; the SDK never stops serving. One sub-result per variant. |
| WA-3 | Uses the first SVID in the response as the default identity | MUST | WA §8 | Push [A, B] → A is presented; push [B, A] → B is presented. |
| WA-4 | Stops using SVIDs after the stream returns `PermissionDenied` | SHOULD | WA §5.2.1 | After A is served, the stream ends with `PermissionDenied`; expect the X.509 port to stop presenting A within 5 s. |

## 5. X.509-SVID — `XS`, `XV`, `XF`

### 5.1 SVID source — `XS` (feature `x509-server`)

| ID | Requirement | Level | Ref | Method |
| --- | --- | --- | --- | --- |
| XS-1 | Presents the X.509-SVID received from `FetchX509SVID` | MUST | WA §5.2.1 | Probe the X.509 port; expect the leaf to carry the issued SPIFFE ID. |
| XS-2 | Presents the full chain, leaf first, including intermediates | MUST | WA §5.1 (`x509_svid`) | Issue from an intermediate CA; the suite verifies against the root only. |
| XS-3 | Uses a rotated SVID for new connections | MUST | WA §4.3 | Push A, then B; expect B. |
| XS-4 | Accepts a trust bundle with several concatenated CA certificates and trusts each | MUST | WA §5.1 (`bundle`) | Bundle = CA1‖CA2; peers from both are accepted. |
| XS-5 | Stops trusting a CA once it is removed from the bundle | MUST | WA §4.3, §4.4 | Replace the bundle with CA2 only; peers from CA1 are rejected. |

### 5.2 Peer validation — `XV` (roles: server, client)

| ID | Requirement | Level | Ref | Method |
| --- | --- | --- | --- | --- |
| XV-1 | Accepts a valid peer SVID (positive control) | MUST | XS §5.1 | Plain leaf from the trust domain CA. |
| XV-2 | Accepts a peer SVID chained through an intermediate | MUST | XS §5.1 | Peer presents leaf + intermediate. |
| XV-3 | Accepts a peer SVID that also carries DNS SANs | MUST | XS §2 | Other SAN types are permitted. |
| XV-4 | Accepts a peer SVID with an empty Subject and a critical URI SAN | MUST | XS §3.1 | |
| XV-5 | Rejects a peer chaining to an untrusted CA | MUST | XS §5.1 | Same trust domain name, different CA. |
| XV-6 | Rejects an expired peer certificate | MUST | XS §5.1 (RFC 5280) | |
| XV-7 | Rejects a not-yet-valid peer certificate | MUST | XS §5.1 (RFC 5280) | |
| XV-8 | Rejects a peer leaf with `cA=true` | MUST | XS §5.2 | |
| XV-9 | Rejects a peer leaf with `keyCertSign` | MUST | XS §5.2 | |
| XV-10 | Rejects a peer leaf with `cRLSign` | MUST | XS §5.2 | |
| XV-11 | Rejects a peer with more than one URI SAN | MUST | XS §2, §5.2 | |
| XV-12 | Rejects a peer without a URI SAN | MUST | XS §2 | |
| XV-13 | Rejects a peer URI SAN that is not `spiffe://` | MUST | XS §5.2 | |
| XV-14 | Rejects a peer SPIFFE ID without a path (`spiffe://td`) | MUST | XS §3.1, §5.2 | |
| XV-15 | Rejects a peer whose trust domain has no bundle, even if its chain verifies against another trust domain's CA | MUST | WA §4.6, FD §7.3 | Leaf `spiffe://other.test/x` signed by the local CA. |

### 5.3 Federation — `XF` (roles: server, client)

| ID | Requirement | Level | Ref | Method |
| --- | --- | --- | --- | --- |
| XF-1 | Accepts a peer from a federated trust domain using `federated_bundles` | MUST | WA §4.6 | Bundle for `spiffe://fed.test`; peer from `fed.test`. |
| XF-2 | Rejects a peer claiming trust domain B whose chain only verifies against trust domain A's bundle (no bundle merging) | MUST | WA §4.6, FD §4.2, §7.3 | Both bundles present. |
| XF-3 | Stops trusting a federated trust domain when a later response omits it | MUST | WA §4.4 | Push without `federated_bundles` (barrier), then peer from `fed.test` is rejected. |

## 6. JWT-SVID — `JV`, `JB`, `JF`

Unless stated otherwise, tokens are ES256 with `aud=["conformance"]`, a 5-minute
`exp`, and a `kid` present in the bundle. Validation runs with audience
`conformance`.

### 6.1 Validation — `JV` (feature `jwt-validate`)

| ID | Requirement | Level | Ref | Method |
| --- | --- | --- | --- | --- |
| JV-1 | Accepts a valid token and returns `sub` as the SPIFFE ID (positive control) | MUST | JS §4, WA §6.3 | |
| JV-2 | Accepts every supported `alg` | MUST | JS §2.1 | One sub-result each for RS256/384/512, ES256/384/512, PS256/384/512; the bundle carries matching keys. |
| JV-3 | Rejects `alg: none` | MUST | JS §2.1 | |
| JV-4 | Rejects HS256/HS384/HS512 | MUST | JS §2.1 | Including HMAC keyed with the public key bytes (algorithm confusion). |
| JV-5 | Rejects asymmetric algorithms outside the list, even if the key is in the bundle | MUST | JS §2.1 | EdDSA with an Ed25519 key that *is* in the bundle. |
| JV-6 | Rejects an `alg` that does not match the key type | MUST | JS §4 | `RS256` header with an EC key `kid`; `ES384` header with a P-256 key. |
| JV-7 | Rejects a token without `aud` | MUST | JS §3.2 | |
| JV-8 | Rejects a token whose `aud` does not contain the validator's audience | MUST | JS §3.2 | |
| JV-9 | Accepts an `aud` array that contains the validator's audience among others | MUST | JS §3.2 | `["other","conformance"]` |
| JV-10 | Accepts `aud` as a single string | MUST | JS §4 (RFC 7519 §4.1.3) | |
| JV-11 | Rejects a token without `exp` | MUST | JS §3.3 | |
| JV-12 | Rejects an expired token | MUST | JS §3.3, App. A | `exp` = now − 5 min (beyond reasonable leeway). |
| JV-13 | Rejects a token whose `nbf` is in the future | MUST | JS §4 (RFC 7519 §4.1.5) | `nbf` = now + 5 min. |
| JV-14 | Rejects a token with a tampered signature | MUST | JS §4 | One bit flipped in the signature. |
| JV-15 | Rejects a token with a tampered payload | MUST | JS §4 | `sub` changed, original signature. |
| JV-16 | Rejects a token signed by a key that is not in the bundle | MUST | JS §4, WA §6.3 | Unknown `kid`. |
| JV-17 | Rejects a token whose `sub` is in trust domain B but which is signed by trust domain A's key | MUST | WA §6.3 | Both bundles present; the `kid` exists only in A's bundle. |
| JV-18 | Rejects a token whose `sub` trust domain has no bundle | MUST | WA §6.3 | |
| JV-19 | Rejects a token whose `sub` is not a SPIFFE ID | MUST | JS §3.1 | See also `ID`. |
| JV-20 | Accepts `typ` of `JWT`, `JOSE`, or no `typ` | MUST | JS §2.3 | Three sub-results. |
| JV-21 | Rejects any other `typ` value | MUST | JS §2.3 | |
| JV-22 | Accepts a token without `kid` | MUST | JS §2.2 | `kid` is optional, so such a token is valid. go-spiffe and SPIRE are expected to fail this test (WIT-SVID App. C). |
| JV-23 | Rejects a token with an unknown `crit` header | MUST | JS §4 (RFC 7515 §4.1.11) | |
| JV-24 | Rejects JWS JSON serialization | MUST | JS §1, §5.1 | |
| JV-25 | Rejects a malformed compact token | MUST | JS §5.1 | Wrong part count, invalid base64url, invalid JSON. |

### 6.2 JWT bundles — `JB` (feature `jwt-validate`)

| ID | Requirement | Level | Ref | Method |
| --- | --- | --- | --- | --- |
| JB-1 | Picks up a key added by a streamed bundle update | MUST | WA §4.3 | |
| JB-2 | Stops accepting a key removed by a streamed bundle update | MUST | WA §4.4 | |
| JB-3 | Stops accepting tokens from a trust domain whose bundle was removed | SHOULD | WA §4.4 | |
| JB-4 | Selects the verification key by `kid` among several keys | MUST | JS §6.2 (RFC 7515 §4.1.4) | Three keys; the token uses the second. |
| JB-5 | Ignores JWKs whose `use` is missing or is not `jwt-svid` | MUST | TB §4.2.2, JS §6.2 | A token signed by such a key is rejected; other keys keep working. go-spiffe does not check `use` and is expected to fail. |
| JB-6 | Ignores JWKs with an unknown `kty` without discarding the rest of the bundle | MUST | TB §4.2.1, §4.1.3 | |
| JB-7 | Treats a bundle with empty `keys` as "trust nothing" for that trust domain | MUST | TB §4.1.3 | |
| JB-8 | Accepts a token from a federated trust domain using that trust domain's bundle | MUST | WA §6.2.2, §6.3 | |

### 6.3 Fetching JWT-SVIDs — `JF` (feature `jwt-fetch`)

| ID | Requirement | Level | Ref | Method |
| --- | --- | --- | --- | --- |
| JF-1 | Calls `FetchJWTSVID` with the requested audience and returns the server's token | MUST | WA §6.2.1 | Recorded request audience must equal the requested one. |
| JF-2 | Passes several audiences through unchanged | MUST | WA §6.2.1 | |
| JF-3 | Passes `spiffe_id` through when one is requested | OPT | WA §6.2.1 | |
| JF-4 | Reports `PermissionDenied` as an error instead of returning a stale token | OPT | WA §6.2.1 | |

## 7. SPIFFE ID parsing — `ID` (feature `jwt-validate`, sampled in `x509-server`)

Each case is a validly signed JWT-SVID with the given `sub`. Representative cases
are also run as X.509 URI SANs (XV role `server`).

| ID | Requirement | Level | Ref | Cases (one sub-result each) |
| --- | --- | --- | --- | --- |
| ID-1 | Rejects invalid SPIFFE IDs | MUST | ID §2, §2.1, §2.2 | empty trust domain `spiffe:///a`; port `spiffe://td:8080/a`; userinfo `spiffe://u@td/a`; query `?x=1`; fragment `#f`; percent-encoded path `%41`; empty segment `/a//b`; dot segments `/a/./b`, `/a/../b`; trailing slash `/a/`; invalid path character `/a!b`; invalid trust domain character `spiffe://t$d/a` |
| ID-2 | Accepts valid edge-case SPIFFE IDs | MUST | ID §2.1, §2.2, §2.3 | path characters `.-_` and mixed case; trust domain with `_` and digits; IPv4-like trust domain; a 2048-byte ID |

## 8. Hardening — `HX` (optional, feature `x509-server`)

No specification requires a client to validate the SVIDs it receives from the
Workload API, because the Workload API is a trusted source. These tests record
defensive behaviour only and never affect a conformance claim. All of them use the
barrier pattern.

| ID | The SDK ignores a Workload API X.509-SVID … | Level |
| --- | --- | --- |
| HX-1 | … with an invalid signature | OPT |
| HX-2 | … that does not chain to the bundle in the same response | OPT |
| HX-3 | … that is expired | OPT |
| HX-4 | … whose leaf has `cA=true` | OPT |
| HX-5 | … whose leaf has `keyCertSign` | OPT |
| HX-6 | … with more than one URI SAN | OPT |
| HX-7 | … with a non-`spiffe://` URI SAN | OPT |
| HX-8 | … whose private key does not match the certificate | OPT |
| HX-9 | … whose `spiffe_id` field differs from the certificate's URI SAN | OPT |

## 9. Mapping from earlier tests

| Earlier | New | Notes |
| --- | --- | --- |
| X1 | XS-1 | |
| X2 | XS-3 | |
| X3 | HX-1 | Not a spec requirement; uses sleep → barrier |
| X4 | HX-2 | Not a spec requirement |
| X5 | HX-3 | Not a spec requirement |
| X6–X9 | HX-4 … HX-7 | Not a spec requirement (XS §5.2 binds *peer* validators) |
| X10 | XV-8/server | Was undetectable under TLS 1.3 |
| X11 | XV-9/server | |
| X12 | XV-11/server | |
| X13 | XV-13/server | |
| J1 | JV-1 | |
| J2 | JV-16 | |
| J3 | JV-8 | |
| J4 | JV-25 | |
| J5 | JV-14 | Was "append garbage", now a bit flip |
| J6 | JV-12 | |
| J7 | JV-19 | |
| J8 | JV-18 | |
| J9 | JV-3, JV-4 | |
| J10 | JV-11 | |
| J11 | JV-7 | |
| J12 | JV-21 | |
| J13 | JB-1, JB-2 | |

## 10. Not covered (yet)

- **Hint-based SVID selection** (WA §5.2.1 duplicate hints, §8). Needs a contract
  endpoint for selecting by hint.
- **`FetchX509Bundles`-only validators.** The harness contract uses
  `FetchX509SVID`. The mock server serves `FetchX509Bundles` correctly, so SDKs that
  use it are not penalised.
- **CRLs.** No client behaviour is specified.
- **WIT-SVID profile** (incubating, optional). A future `WT` group.
- **Broker API.** Not a Workload API client concern.
