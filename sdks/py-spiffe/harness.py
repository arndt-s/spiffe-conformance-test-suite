"""Conformance harness for py-spiffe (PyPI `spiffe` + `spiffe-tls`).

Implements harness contract v1 (docs/HARNESS_CONTRACT.md) using only
py-spiffe's public APIs:

* `spiffe.WorkloadApiClient` / `spiffe.X509Source` / `spiffe.JwtSource`
  (endpoint discovered from SPIFFE_ENDPOINT_SOCKET),
* `spiffetls.listen` / `spiffetls.dial` with `authorize_any()` for mTLS,
* `spiffe.JwtSvid.parse_and_validate` for JWT-SVID validation.
"""

from __future__ import annotations

import json
import logging
import os
import signal
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.metadata import PackageNotFoundError, version
from typing import Any, Optional

from cryptography import x509
from OpenSSL import SSL, crypto

from spiffe import JwtSource, JwtSvid, SpiffeId, WorkloadApiClient, X509Source
from spiffetls import ListenOptions, ServerTlsMode, dial, listen
from spiffetls.errors import TLSConnectionError
from spiffetls.mode import ClientTlsMode
from spiffetls.tlsconfig.authorize import authorize_any

log = logging.getLogger("harness")

JWT_SOURCE_WAIT_SECONDS = 10.0
X509_CONN_TIMEOUT_SECONDS = 10.0


def _exit_now(signum: int, _frame: Any) -> None:
    # Exit promptly; the SDK's gRPC threads would otherwise delay interpreter
    # shutdown.
    log.info("signal %d received, exiting", signum)
    try:
        sys.stdout.flush()
        sys.stderr.flush()
    finally:
        os._exit(0)


def peer_spiffe_id(cert: crypto.X509) -> str:
    """Returns the SPIFFE ID of an already-authenticated peer certificate.

    py-spiffe has no public "ID from certificate" helper; the peer has already
    been authenticated by spiffe-tls (chain + authorize_any(), which requires
    exactly one spiffe:// URI SAN), so this only reads the URI SAN for
    reporting and parses it with the SDK's SpiffeId.
    """
    san = cert.to_cryptography().extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    ).value
    uris = san.get_values_for_type(x509.UniformResourceIdentifier)
    return str(SpiffeId(uris[0]))


class LazyJwtSource:
    """Creates a JwtSource on first use so a missing JWT bundle does not keep
    the X.509 tests from running."""

    def __init__(self, client: WorkloadApiClient) -> None:
        self._client = client
        self._lock = threading.Lock()
        self._started = False
        self._ready = threading.Event()
        self._source: Optional[JwtSource] = None
        self._err: Optional[Exception] = None

    def _create(self) -> None:
        try:
            self._source = JwtSource(workload_api_client=self._client)
        except Exception as err:  # noqa: BLE001
            self._err = err
        finally:
            self._ready.set()

    def get(self) -> JwtSource:
        with self._lock:
            if not self._started:
                self._started = True
                threading.Thread(target=self._create, daemon=True).start()
        if not self._ready.wait(JWT_SOURCE_WAIT_SECONDS):
            raise TimeoutError("timed out waiting for the first JWT bundle")
        if self._err is not None:
            raise self._err
        assert self._source is not None
        return self._source


def serve_x509(listener: SSL.Connection) -> None:
    """Accepts mTLS connections (authenticated by spiffe-tls), writes the
    client's SPIFFE ID and closes."""
    while True:
        try:
            conn, _ = listener.accept()
        except OSError as err:
            log.info("X.509 listener stopped: %s", err)
            return
        threading.Thread(target=_handle_x509_conn, args=(conn,), daemon=True).start()


def _handle_x509_conn(conn: SSL.Connection) -> None:
    # pyOpenSSL needs a blocking socket; guard against stuck peers with a timer.
    timer = threading.Timer(X509_CONN_TIMEOUT_SECONDS, _force_close, args=(conn,))
    timer.daemon = True
    timer.start()
    try:
        conn.do_handshake()
        cert = conn.get_peer_certificate()
        if cert is None:
            log.info("X.509 handshake: no peer certificate")
            return
        conn.sendall((peer_spiffe_id(cert) + "\n").encode())
        try:
            conn.shutdown()
        except SSL.Error:
            pass
    except Exception as err:  # noqa: BLE001
        log.info("X.509 handshake rejected: %r", err)
    finally:
        timer.cancel()
        _force_close(conn)


def _force_close(conn: SSL.Connection) -> None:
    try:
        conn.close()
    except Exception:  # noqa: BLE001
        pass


class ControlHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server: "ControlServer"

    def log_message(self, fmt: str, *args: Any) -> None:  # stderr, not stdout
        log.info("control: " + fmt, *args)

    def _reply(self, code: int, status: str, message: str = "", **fields: Any) -> None:
        body: dict[str, Any] = {"status": status}
        if message:
            body["message"] = message
        body.update(fields)
        data = json.dumps(body, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        req = json.loads(self.rfile.read(length) or b"{}")
        if not isinstance(req, dict):
            raise ValueError("request body must be a JSON object")
        return req

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/v1/info":
            try:
                sdk_version = f"spiffe {version('spiffe')}, spiffe-tls {version('spiffe-tls')}"
            except PackageNotFoundError:
                sdk_version = "unknown"
            self._reply(200, "ok", sdk="py-spiffe", sdk_version=sdk_version, language="python")
        else:
            self._reply(404, "error", "not found")

    def do_POST(self) -> None:  # noqa: N802
        routes = {
            "/v1/jwt/validate": self._validate,
            "/v1/jwt/fetch": self._fetch,
            "/v1/x509/dial": self._dial,
        }
        route = routes.get(self.path)
        if route is None:
            self._reply(404, "error", "not found")
            return
        try:
            req = self._body()
        except Exception as err:  # noqa: BLE001
            self._reply(500, "error", f"bad request: {err}")
            return
        try:
            route(req)
        except Exception as err:  # noqa: BLE001
            log.exception("handler %s failed", self.path)
            self._reply(500, "error", f"harness error: {err!r}")

    def _validate(self, req: dict[str, Any]) -> None:
        token = req.get("token", "")
        audience = req.get("audience", "")
        try:
            source = self.server.jwt_sources.get()
        except Exception as err:  # noqa: BLE001
            self._reply(500, "error", f"JWT source: {err}")
            return
        try:
            # Select the bundle for the token's trust domain, as
            # JwtSvid.parse_and_validate's documentation prescribes.
            subject = JwtSvid.parse_insecure(token, {audience}).spiffe_id
            bundle = source.get_bundle_for_trust_domain(subject.trust_domain)
            if bundle is None:
                self._reply(422, "rejected", f"no JWT bundle for trust domain {subject.trust_domain}")
                return
            svid = JwtSvid.parse_and_validate(token, bundle, {audience})
        except Exception as err:  # noqa: BLE001
            self._reply(422, "rejected", f"{type(err).__name__}: {err}")
            return
        # py-spiffe's JwtSvid exposes no public claims accessor; report the ID.
        self._reply(200, "ok", spiffe_id=str(svid.spiffe_id))

    def _fetch(self, req: dict[str, Any]) -> None:
        audience = req.get("audience") or []
        if not isinstance(audience, list) or not audience:
            self._reply(500, "error", "bad request: audience required")
            return
        subject = None
        if req.get("spiffe_id"):
            try:
                subject = SpiffeId(req["spiffe_id"])
            except Exception as err:  # noqa: BLE001
                self._reply(500, "error", f"bad spiffe_id: {err}")
                return
        try:
            svids = self.server.client.fetch_jwt_svids(set(audience), subject)
        except Exception as err:  # noqa: BLE001
            self._reply(500, "error", f"{type(err).__name__}: {err}")
            return
        # py-spiffe's JwtSvid does not expose the Workload API hint.
        out = [{"spiffe_id": str(s.spiffe_id), "token": s.token, "hint": ""} for s in svids]
        self._reply(200, "ok", svids=out)

    def _dial(self, req: dict[str, Any]) -> None:
        address = req.get("address", "")
        try:
            conn = dial(address, self.server.x509_source, ClientTlsMode.TLS, authorize_any())
        except TLSConnectionError as err:
            self._reply(422, "rejected", str(err))
            return
        except (ConnectionError, OSError, ValueError) as err:
            self._reply(500, "error", f"{type(err).__name__}: {err}")
            return
        try:
            cert = conn.get_peer_certificate()
            if cert is None:
                self._reply(422, "rejected", "server presented no certificate")
                return
            self._reply(200, "ok", spiffe_id=peer_spiffe_id(cert))
        finally:
            try:
                conn.shutdown()
            except Exception:  # noqa: BLE001
                pass
            _force_close(conn)


class ControlServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, client: WorkloadApiClient, x509_source: X509Source) -> None:
        super().__init__(("127.0.0.1", 0), ControlHandler)
        self.client = client
        self.x509_source = x509_source
        self.jwt_sources = LazyJwtSource(client)


def main() -> None:
    logging.basicConfig(
        stream=sys.stderr,
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    signal.signal(signal.SIGTERM, _exit_now)
    signal.signal(signal.SIGINT, _exit_now)

    # The client discovers the endpoint from SPIFFE_ENDPOINT_SOCKET.
    client = WorkloadApiClient()
    # Blocks until the first X.509-SVID has been received.
    x509_source = X509Source(workload_api_client=client)

    listener = listen(
        "127.0.0.1:0",
        x509_source,
        ListenOptions(tls_mode=ServerTlsMode.MTLS, authorize_fn=authorize_any(), backlog=128),
    )
    x509_port = listener.getsockname()[1]
    threading.Thread(target=serve_x509, args=(listener,), daemon=True).start()

    control = ControlServer(client, x509_source)
    control_port = control.server_address[1]
    threading.Thread(target=control.serve_forever, daemon=True).start()

    print("SPIFFE_HARNESS_VERSION=1")
    print(f"SPIFFE_X509_PORT={x509_port}")
    print(f"SPIFFE_CONTROL_PORT={control_port}")
    print("READY", flush=True)

    threading.Event().wait()


if __name__ == "__main__":
    try:
        main()
    except Exception:  # noqa: BLE001
        log.exception("harness failed")
        sys.stderr.flush()
        os._exit(1)
