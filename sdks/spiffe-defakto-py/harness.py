"""Conformance harness for spiffe-defakto (Defakto's Python SDK).

Implements harness contract v1 (docs/HARNESS_CONTRACT.md). Every SPIFFE
decision is delegated to the SDK:

- endpoint discovery: ``WorkloadAPIClient()`` reads ``SPIFFE_ENDPOINT_SOCKET``
- own X.509-SVID and rotation: ``client.watch_x509_context()`` /
  ``X509Context.default_svid()``
- peer authentication: ``verify_x509_svid(chain, client.x509)``
- JWT validation: ``parse_and_validate_jwt_svid(token, client.jwt, [aud])``
- JWT fetch: ``client.jwt.fetch_svid(audiences)``

The SDK ships no TLS integration of its own, and Python's ``ssl`` module cannot
request a client certificate without having OpenSSL verify it against a CA
store. TLS plumbing therefore uses pyOpenSSL with a verify callback that defers
the decision: OpenSSL only carries the handshake, and the peer chain it
received is handed to the SDK's ``verify_x509_svid`` (the integration the SDK
README documents). Peers the SDK rejects are disconnected without the ID line.

Only standard SPIFFE Workload API features are used; none of the SDK's
Defakto-specific attestation features are touched.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import socket
import struct
import sys
import threading
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import metadata

from OpenSSL import SSL, crypto
from cryptography.hazmat.primitives.serialization import Encoding

from spiffe_defakto import (
    SpiffeError,
    SpiffeErrorCode,
    WorkloadAPIClient,
    parse_and_validate_jwt_svid,
    verify_x509_svid,
)

log = logging.getLogger("harness")

IO_TIMEOUT = 10.0
DIAL_TIMEOUT = 5.0
RPC_TIMEOUT = 15.0

# Errors that mean the SDK could not reach or use the Workload API, as opposed
# to the SDK rejecting its input.
_INFRA_ERRORS = {
    SpiffeErrorCode.WORKLOAD_API_UNAVAILABLE,
    SpiffeErrorCode.WORKLOAD_API_ERROR,
    SpiffeErrorCode.SOCKET_PATH_NOT_CONFIGURED,
}


def emit(line: str) -> None:
    sys.stdout.write(line + "\n")
    sys.stdout.flush()


# --------------------------------------------------------------------- TLS


def _accept_any_at_openssl_layer(_conn, _cert, _errno, _depth, _ok) -> bool:
    # The SDK authenticates the chain after the handshake (verify_x509_svid);
    # OpenSSL must not make a trust decision of its own.
    return True


def _tls_context(svid, *, server: bool) -> SSL.Context:
    ctx = SSL.Context(SSL.TLS_METHOD)
    ctx.set_min_proto_version(SSL.TLS1_2_VERSION)
    leaf, *intermediates = svid.certificates
    ctx.use_certificate(crypto.X509.from_cryptography(leaf))
    for cert in intermediates:
        ctx.add_extra_chain_cert(crypto.X509.from_cryptography(cert))
    ctx.use_privatekey(crypto.PKey.from_cryptography_key(svid.private_key))
    ctx.check_privatekey()
    mode = SSL.VERIFY_PEER
    if server:
        mode |= SSL.VERIFY_FAIL_IF_NO_PEER_CERT
    ctx.set_verify(mode, _accept_any_at_openssl_layer)
    return ctx


def _peer_chain_der(conn: SSL.Connection) -> list[bytes]:
    """The certificates the peer sent, leaf first, as DER."""
    leaf = conn.get_peer_certificate(as_cryptography=True)
    if leaf is None:
        return []
    rest = conn.get_peer_cert_chain(as_cryptography=True) or []
    leaf_der = leaf.public_bytes(Encoding.DER)
    ders = [c.public_bytes(Encoding.DER) for c in rest]
    # OpenSSL includes the leaf in the chain on the client side only.
    if ders and ders[0] == leaf_der:
        ders = ders[1:]
    return [leaf_der, *ders]


def _set_io_timeouts(sock: socket.socket, seconds: float) -> None:
    # pyOpenSSL needs a blocking socket; bound reads/writes at the OS level.
    tv = struct.pack("ll", int(seconds), int((seconds % 1) * 1_000_000))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, tv)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDTIMEO, tv)


def _close(conn: SSL.Connection) -> None:
    try:
        conn.shutdown()
    except Exception:
        pass
    try:
        conn.sock_shutdown(socket.SHUT_RDWR)
    except Exception:
        pass
    conn.close()


# ----------------------------------------------------------------- harness


class Harness:
    def __init__(self, loop: asyncio.AbstractEventLoop, client: WorkloadAPIClient) -> None:
        self.loop = loop
        self.client = client
        self.svid = None  # current default X.509-SVID, from the SDK's watch
        self.server_ctx: SSL.Context | None = None
        self.first_svid = asyncio.Event()

    def run_sdk(self, coro):
        """Run an SDK coroutine on the event loop from a worker thread."""
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(RPC_TIMEOUT)

    # -- X.509 context watch ------------------------------------------------

    async def watch(self) -> None:
        # The SDK reconnects on a clean end of stream; RPC errors are raised to
        # the caller. The harness does not retry on the SDK's behalf.
        try:
            async for ctx in self.client.watch_x509_context():
                svid = ctx.default_svid()
                server_ctx = _tls_context(svid, server=True)
                self.svid, self.server_ctx = svid, server_ctx
                log.info("X.509 context update: default SVID %s", svid.id)
                self.first_svid.set()
            log.warning("X.509 context watch ended")
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.error("X.509 context watch failed: %r", exc)

    # -- X.509 port ---------------------------------------------------------

    def serve_x509(self, ln: socket.socket) -> None:
        while True:
            try:
                sock, _ = ln.accept()
            except OSError:
                return
            threading.Thread(target=self._handle_x509, args=(sock,), daemon=True).start()

    def _handle_x509(self, sock: socket.socket) -> None:
        _set_io_timeouts(sock, IO_TIMEOUT)
        conn = SSL.Connection(self.server_ctx, sock)
        conn.set_accept_state()
        try:
            conn.do_handshake()
            peer_id = self.run_sdk(verify_x509_svid(_peer_chain_der(conn), self.client.x509))
            conn.sendall(f"{peer_id}\n".encode())
        except SpiffeError as exc:
            log.info("X.509 peer rejected by SDK: %s: %s", exc.code, exc)
        except Exception as exc:
            log.info("X.509 connection failed: %r", exc)
        finally:
            _close(conn)

    # -- control endpoints --------------------------------------------------

    def jwt_validate(self, req: dict) -> tuple[int, dict]:
        token, audience = req.get("token"), req.get("audience")
        if not isinstance(token, str) or not isinstance(audience, str):
            return 500, {"status": "error", "message": "bad request: token and audience required"}
        try:
            svid = self.run_sdk(parse_and_validate_jwt_svid(token, self.client.jwt, [audience]))
        except SpiffeError as exc:
            if exc.code in _INFRA_ERRORS:
                return 500, {"status": "error", "message": f"{exc.code.name}: {exc}"}
            return 422, {"status": "rejected", "message": f"{exc.code.name}: {exc}"}
        except Exception as exc:  # noqa: BLE001 - the SDK refused the token, but not with its own error type
            return 422, {"status": "rejected", "message": f"SDK raised unexpected {type(exc).__name__}: {exc}"}
        return 200, {"status": "ok", "spiffe_id": str(svid.id), "claims": dict(svid.claims)}

    def jwt_fetch(self, req: dict) -> tuple[int, dict]:
        audience = req.get("audience")
        if not isinstance(audience, list) or not audience:
            return 500, {"status": "error", "message": "bad request: audience required"}
        if req.get("spiffe_id"):
            return 501, {
                "status": "unsupported",
                "message": "spiffe-defakto's jwt.fetch_svid() cannot request a specific SPIFFE ID",
            }
        try:
            svid = self.run_sdk(self.client.jwt.fetch_svid(list(audience)))
        except SpiffeError as exc:
            return 500, {"status": "error", "message": f"{exc.code.name}: {exc}"}
        # The SDK returns only the first (default) JWT-SVID and exposes no hint.
        return 200, {"status": "ok", "svids": [{"spiffe_id": str(svid.id), "token": svid.token, "hint": ""}]}

    def x509_dial(self, req: dict) -> tuple[int, dict]:
        address = req.get("address")
        if not isinstance(address, str) or ":" not in address:
            return 500, {"status": "error", "message": "bad request: address required"}
        host, _, port = address.rpartition(":")
        try:
            sock = socket.create_connection((host.strip("[]"), int(port)), timeout=DIAL_TIMEOUT)
        except OSError as exc:
            return 500, {"status": "error", "message": f"connect: {exc}"}
        sock.settimeout(None)
        _set_io_timeouts(sock, DIAL_TIMEOUT)
        conn = SSL.Connection(_tls_context(self.svid, server=False), sock)
        conn.set_connect_state()
        try:
            try:
                conn.do_handshake()
            except (SSL.Error, OSError) as exc:
                return 422, {"status": "rejected", "message": f"TLS handshake: {exc!r}"}
            try:
                peer_id = self.run_sdk(verify_x509_svid(_peer_chain_der(conn), self.client.x509))
            except SpiffeError as exc:
                if exc.code in _INFRA_ERRORS:
                    return 500, {"status": "error", "message": f"{exc.code.name}: {exc}"}
                return 422, {"status": "rejected", "message": f"{exc.code.name}: {exc}"}
            return 200, {"status": "ok", "spiffe_id": str(peer_id)}
        finally:
            _close(conn)

    def info(self) -> tuple[int, dict]:
        try:
            version = metadata.version("spiffe-defakto")
        except metadata.PackageNotFoundError:
            version = "unknown"
        return 200, {"status": "ok", "sdk": "spiffe-defakto", "sdk_version": version, "language": "python"}


def make_handler(h: Harness):
    routes = {
        ("POST", "/v1/jwt/validate"): h.jwt_validate,
        ("POST", "/v1/jwt/fetch"): h.jwt_fetch,
        ("POST", "/v1/x509/dial"): h.x509_dial,
    }

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _reply(self, code: int, body: dict) -> None:
            data = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self) -> None:
            if self.path == "/v1/info":
                self._reply(*h.info())
            else:
                self._reply(404, {"status": "error", "message": "not found"})

        def do_POST(self) -> None:
            route = routes.get(("POST", self.path))
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b""
            if route is None:
                self._reply(404, {"status": "error", "message": "not found"})
                return
            try:
                req = json.loads(raw or b"{}")
                if not isinstance(req, dict):
                    raise ValueError("body is not a JSON object")
            except ValueError as exc:
                self._reply(500, {"status": "error", "message": f"bad request: {exc}"})
                return
            try:
                self._reply(*route(req))
            except Exception as exc:
                # Not a SpiffeError: the SDK (or harness) failed unexpectedly.
                log.error("%s failed:\n%s", self.path, traceback.format_exc())
                self._reply(500, {"status": "error", "message": f"unexpected exception: {exc!r}"})

        def log_message(self, fmt, *args) -> None:
            log.info("control: " + fmt, *args)

    return Handler


async def main() -> int:
    loop = asyncio.get_running_loop()
    stop = asyncio.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)

    # Discovers the endpoint from SPIFFE_ENDPOINT_SOCKET.
    client = WorkloadAPIClient()
    h = Harness(loop, client)
    watch = asyncio.create_task(h.watch())

    first = asyncio.create_task(h.first_svid.wait())
    stopping = asyncio.create_task(stop.wait())
    await asyncio.wait({first, watch, stopping}, return_when=asyncio.FIRST_COMPLETED)
    if not h.first_svid.is_set():
        log.error("no X.509-SVID received; exiting without READY")
        return 1

    x509_ln = socket.create_server(("127.0.0.1", 0))
    threading.Thread(target=h.serve_x509, args=(x509_ln,), daemon=True).start()
    control = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(h))
    control.daemon_threads = True
    threading.Thread(target=control.serve_forever, daemon=True).start()

    emit("SPIFFE_HARNESS_VERSION=1")
    emit(f"SPIFFE_X509_PORT={x509_ln.getsockname()[1]}")
    emit(f"SPIFFE_CONTROL_PORT={control.server_address[1]}")
    emit("READY")

    await stop.wait()
    log.info("shutting down")
    x509_ln.close()
    watch.cancel()
    try:
        await asyncio.wait_for(client.close(), 2)
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    code = asyncio.run(main())
    sys.stderr.flush()
    # Worker threads may be blocked in socket I/O; don't wait for them.
    os._exit(code)
