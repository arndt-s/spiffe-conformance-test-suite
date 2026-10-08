// Conformance harness for @defakto/spiffe (TypeScript). Implements harness
// contract v1 (docs/HARNESS_CONTRACT.md) using only the SDK's public APIs:
// WorkloadAPIClient (endpoint discovery, X.509 watch, bundle sources),
// marshalX509SVID, verifyX509SVID and parseAndValidateJwtSVID.
//
// Node's TLS stack is used only as transport: it never decides whether a peer
// is trusted (rejectUnauthorized: false, no `ca`). Every peer chain is handed
// to the SDK's verifyX509SVID, which selects the bundle for the peer's trust
// domain from the Workload API.
import * as fs from 'fs';
import * as http from 'http';
import * as net from 'net';
import * as path from 'path';
import * as tls from 'tls';
import {
  SpiffeError,
  SpiffeErrorCode,
  WorkloadAPIClient,
  X509SVID,
  marshalX509SVID,
  parseAndValidateJwtSVID,
  verifyX509SVID,
} from '@defakto/spiffe';

const log = (...args: unknown[]) => console.error('[harness]', ...args);

// SDK errors that mean "could not perform the operation" rather than "rejected".
const OPERATIONAL_ERRORS = new Set<string>([
  SpiffeErrorCode.WorkloadAPIUnavailable,
  SpiffeErrorCode.WorkloadAPIError,
  SpiffeErrorCode.SocketPathNotConfigured,
]);

function isOperationalError(err: unknown): boolean {
  return err instanceof SpiffeError && OPERATIONAL_ERRORS.has(err.code);
}

function errMessage(err: unknown): string {
  if (err instanceof SpiffeError) {
    const cause = err.cause instanceof Error ? `: ${err.cause.message}` : '';
    return `${err.code}: ${err.message}${cause}`;
  }
  return err instanceof Error ? err.message : String(err);
}

// Raw DER chain the peer sent, leaf first. Node only exposes it as the linked
// list returned by getPeerCertificate(true); it ends at a self-issued cert.
function peerChain(socket: tls.TLSSocket): Uint8Array[] {
  const chain: Uint8Array[] = [];
  let cert = socket.getPeerCertificate(true) as tls.DetailedPeerCertificate | undefined;
  const seen = new Set<string>();
  while (cert && cert.raw && !seen.has(cert.fingerprint256)) {
    seen.add(cert.fingerprint256);
    chain.push(new Uint8Array(cert.raw));
    cert = cert.issuerCertificate;
  }
  return chain;
}

function listen(server: net.Server): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve((server.address() as net.AddressInfo).port));
  });
}

function reply(res: http.ServerResponse, code: number, status: string, message?: string, fields?: Record<string, unknown>) {
  const body: Record<string, unknown> = { status };
  if (message) body.message = message;
  Object.assign(body, fields ?? {});
  res.writeHead(code, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(body) + '\n');
}

function readJSON(req: http.IncomingMessage): Promise<any> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch (e) {
        reject(e);
      }
    });
    req.on('error', reject);
  });
}

function sdkVersion(): string {
  try {
    const entry = require.resolve('@defakto/spiffe');
    const pkg = path.join(path.dirname(entry), '..', 'package.json');
    return JSON.parse(fs.readFileSync(pkg, 'utf8')).version;
  } catch {
    return 'unknown';
  }
}

async function main() {
  // The SDK discovers the endpoint from SPIFFE_ENDPOINT_SOCKET.
  const client = new WorkloadAPIClient();

  const shutdown = () => {
    void client.close();
    process.exit(0);
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);

  // Current default X.509-SVID, kept up to date by the SDK's watch stream.
  let current: { svid: X509SVID; cert: string; key: string } | undefined;
  let resolveFirst: () => void = () => {};
  const firstSVID = new Promise<void>((r) => (resolveFirst = r));

  // --- X.509 port -----------------------------------------------------------
  const x509Server = tls.createServer({
    requestCert: true,
    // Node must not judge the client chain; the SDK does it below.
    rejectUnauthorized: false,
    minVersion: 'TLSv1.2',
  });
  x509Server.on('secureConnection', (socket: tls.TLSSocket) => {
    socket.setTimeout(10_000, () => socket.destroy());
    socket.on('error', () => socket.destroy());
    verifyX509SVID(peerChain(socket), client.x509, { side: 'client' })
      .then((id) => socket.end(id.toString() + '\n'))
      .catch((err) => {
        log(`X.509 client rejected: ${errMessage(err)}`);
        socket.destroy();
      });
  });
  x509Server.on('tlsClientError', (err) => log(`X.509 handshake failed: ${err.message}`));

  (async () => {
    try {
      for await (const svid of client.x509.watchSVID()) {
        const { certChainPem, privateKeyPem } = await marshalX509SVID(svid);
        current = { svid, cert: certChainPem, key: privateKeyPem };
        x509Server.setSecureContext({ cert: certChainPem, key: privateKeyPem });
        log(`X.509-SVID received: ${svid.id.toString()}`);
        resolveFirst();
      }
      log('X.509 watch ended');
    } catch (err) {
      log(`X.509 watch failed: ${errMessage(err)}`);
      if (!current) process.exit(1);
    }
  })();

  // --- Control port ---------------------------------------------------------
  const handlers: Record<string, (req: http.IncomingMessage, res: http.ServerResponse) => Promise<void>> = {
    'POST /v1/jwt/validate': async (req, res) => {
      let body: { token?: unknown; audience?: unknown };
      try {
        body = await readJSON(req);
      } catch (e) {
        return reply(res, 500, 'error', `bad request: ${errMessage(e)}`);
      }
      if (typeof body.token !== 'string' || typeof body.audience !== 'string') {
        return reply(res, 500, 'error', 'bad request: token and audience required');
      }
      try {
        const svid = await parseAndValidateJwtSVID(body.token, client.jwt, [body.audience]);
        reply(res, 200, 'ok', undefined, { spiffe_id: svid.id.toString(), claims: svid.claims });
      } catch (err) {
        if (isOperationalError(err)) return reply(res, 500, 'error', errMessage(err));
        reply(res, 422, 'rejected', errMessage(err));
      }
    },

    'POST /v1/jwt/fetch': async (req, res) => {
      let body: { audience?: unknown; spiffe_id?: unknown };
      try {
        body = await readJSON(req);
      } catch (e) {
        return reply(res, 500, 'error', `bad request: ${errMessage(e)}`);
      }
      const audience = body.audience;
      if (!Array.isArray(audience) || audience.length === 0 || !audience.every((a) => typeof a === 'string')) {
        return reply(res, 500, 'error', 'bad request: audience required');
      }
      if (typeof body.spiffe_id === 'string' && body.spiffe_id !== '') {
        // JwtSVIDSource.fetchSVID(audiences) has no way to request a specific identity.
        return reply(res, 501, 'unsupported', '@defakto/spiffe fetchSVID cannot request a specific SPIFFE ID');
      }
      try {
        const svid = await client.jwt.fetchSVID(audience);
        // The SDK returns only the default JWT-SVID and does not expose its hint.
        reply(res, 200, 'ok', undefined, { svids: [{ spiffe_id: svid.id.toString(), token: svid.token, hint: '' }] });
      } catch (err) {
        reply(res, 500, 'error', errMessage(err));
      }
    },

    'POST /v1/x509/dial': async (req, res) => {
      let body: { address?: unknown };
      try {
        body = await readJSON(req);
      } catch (e) {
        return reply(res, 500, 'error', `bad request: ${errMessage(e)}`);
      }
      if (typeof body.address !== 'string') return reply(res, 500, 'error', 'bad request: address required');
      const m = /^(.*):(\d+)$/.exec(body.address);
      if (!m) return reply(res, 500, 'error', `bad address ${body.address}`);
      const host = m[1].replace(/^\[(.*)\]$/, '$1');
      const port = Number(m[2]);
      if (!current) return reply(res, 500, 'error', 'no X.509-SVID yet');

      let raw: net.Socket;
      try {
        raw = await new Promise<net.Socket>((resolve, reject) => {
          const s = net.connect({ host, port, timeout: 5000 });
          s.once('connect', () => resolve(s));
          s.once('timeout', () => {
            s.destroy();
            reject(new Error('connect timeout'));
          });
          s.once('error', reject);
        });
      } catch (err) {
        return reply(res, 500, 'error', errMessage(err));
      }

      let socket: tls.TLSSocket;
      try {
        socket = await new Promise<tls.TLSSocket>((resolve, reject) => {
          const s = tls.connect({
            socket: raw,
            cert: current!.cert,
            key: current!.key,
            // Node must not judge the server chain; the SDK does it below.
            rejectUnauthorized: false,
            minVersion: 'TLSv1.2',
          });
          s.setTimeout(5000, () => {
            s.destroy();
            reject(new Error('handshake timeout'));
          });
          s.once('secureConnect', () => resolve(s));
          s.once('error', reject);
        });
      } catch (err) {
        raw.destroy();
        return reply(res, 422, 'rejected', `TLS handshake: ${errMessage(err)}`);
      }
      try {
        const id = await verifyX509SVID(peerChain(socket), client.x509, { side: 'server' });
        reply(res, 200, 'ok', undefined, { spiffe_id: id.toString() });
      } catch (err) {
        if (isOperationalError(err)) reply(res, 500, 'error', errMessage(err));
        else reply(res, 422, 'rejected', errMessage(err));
      } finally {
        socket.destroy();
      }
    },

    'GET /v1/info': async (_req, res) => {
      reply(res, 200, 'ok', undefined, { sdk: '@defakto/spiffe', sdk_version: sdkVersion(), language: 'typescript' });
    },
  };

  const controlServer = http.createServer((req, res) => {
    const handler = handlers[`${req.method} ${(req.url ?? '').split('?')[0]}`];
    if (!handler) return reply(res, 404, 'error', 'not found');
    handler(req, res).catch((err) => {
      log(`control handler failed: ${errMessage(err)}`);
      if (!res.headersSent) reply(res, 500, 'error', errMessage(err));
    });
  });

  const [x509Port, controlPort] = await Promise.all([listen(x509Server), listen(controlServer)]);
  console.log('SPIFFE_HARNESS_VERSION=1');
  console.log(`SPIFFE_X509_PORT=${x509Port}`);
  console.log(`SPIFFE_CONTROL_PORT=${controlPort}`);

  // READY only after the SDK has delivered the first X.509-SVID.
  await firstSVID;
  console.log('READY');
}

main().catch((err) => {
  log(`fatal: ${errMessage(err)}`);
  process.exit(1);
});
