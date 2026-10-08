// Conformance harness for @jeengbe/spiffe, implementing harness contract v1
// (docs/HARNESS_CONTRACT.md).
//
// @jeengbe/spiffe is a JWT-first Workload API client. Its high-level API
// (SpiffeClient.getJwtSvid / validateJwt) covers JWT-SVIDs only. For X.509 the
// SDK's README says to use the raw gRPC client exposed as `SpiffeClient.api`;
// the SDK offers no X.509-SVID parsing, no X.509 peer authentication and no
// stream reconnect for X.509. Consequently:
//
//   - X.509 port: the SVID comes from `client.api.fetchX509SVID()` (endpoint
//     discovery, transport and the security header are the SDK's). The first
//     SVID of every response is installed as-is; the SDK does not validate it
//     and neither does this harness. Because the SDK cannot authenticate
//     peer X.509-SVIDs, the port runs in the contract's "-" mode (§3, "SDKs
//     without peer authentication"): no client certificate is requested and
//     `-\n` is written after every handshake. No substitute verification
//     (Node/OpenSSL `ca`) is used.
//   - /v1/x509/dial: 501 (the SDK cannot authenticate an X.509-SVID peer).
//   - /v1/jwt/validate: SpiffeClient.validateJwt (delegates to the Workload
//     API's ValidateJWTSVID RPC).
//   - /v1/jwt/fetch: SpiffeClient.getJwtSvid (returns only the first SVID).
import { readFileSync } from 'node:fs';
import * as http from 'node:http';
import type { AddressInfo } from 'node:net';
import * as tls from 'node:tls';
import { X509Certificate, createPrivateKey } from 'node:crypto';
import { SpiffeClient } from '@jeengbe/spiffe';

const log = (...args: unknown[]): void => console.error('[jeengbe-spiffe]', ...args);

process.on('SIGTERM', () => process.exit(0));
process.on('SIGINT', () => process.exit(0));

// No `connection` option: the SDK resolves SPIFFE_ENDPOINT_SOCKET itself.
const client = new SpiffeClient();

// ---------------------------------------------------------------------------
// DER -> PEM plumbing for Node's TLS API. The Workload API delivers
// concatenated DER certificates; Node's X509Certificate parses the first one
// and reports its length, so the concatenation is walked with Node's parser.
// This is format conversion only; no SPIFFE checks are done here.
function derChainToPem(der: Uint8Array): string[] {
  const buf = Buffer.from(der);
  const out: string[] = [];
  let off = 0;
  while (off < buf.length) {
    const cert = new X509Certificate(buf.subarray(off));
    out.push(cert.toString());
    off += cert.raw.length;
  }
  return out;
}

function pkcs8ToPem(der: Uint8Array): string {
  return createPrivateKey({ key: Buffer.from(der), format: 'der', type: 'pkcs8' })
    .export({ type: 'pkcs8', format: 'pem' })
    .toString();
}

// ---------------------------------------------------------------------------
// X.509: raw FetchX509SVID stream via the SDK's `api` client.
let current: tls.SecureContextOptions | undefined;
let resolveFirst: () => void;
const firstSvid = new Promise<void>((r) => (resolveFirst = r));

async function watchX509(): Promise<void> {
  try {
    for await (const resp of client.api.fetchX509SVID({})) {
      const svid = resp.svids[0];
      if (!svid) {
        log('X509SVIDResponse without SVIDs');
        continue;
      }
      try {
        const next: tls.SecureContextOptions = {
          cert: derChainToPem(svid.x509Svid).join(''),
          key: pkcs8ToPem(svid.x509SvidKey),
        };
        // Applies to new connections only.
        x509Server.setSecureContext(next);
        current = next;
        log(`X.509-SVID received: ${svid.spiffeId}`);
        resolveFirst();
      } catch (err) {
        log(`could not load X.509-SVID ${svid.spiffeId}: ${String(err)}`);
      }
    }
    log('FetchX509SVID stream ended');
  } catch (err) {
    log(`FetchX509SVID stream failed: ${String(err)}`);
  }
  if (!current) process.exit(1);
}

// The secure context is replaced via setSecureContext on every SVID update,
// so rotations take effect for new connections without a restart.
// No client certificate is requested: the SDK has no peer authentication, so
// per contract §3 the harness writes "-" instead of a peer SPIFFE ID.
const x509Server = tls.createServer({ requestCert: false, minVersion: 'TLSv1.2' }, (socket) => {
  socket.setTimeout(10_000, () => socket.destroy());
  socket.end('-\n');
});
x509Server.on('tlsClientError', (err) => log(`X.509 handshake failed: ${err.message}`));

// ---------------------------------------------------------------------------
// Control port.
type Body = Record<string, unknown>;

function reply(res: http.ServerResponse, code: number, status: string, message?: string, fields: Body = {}): void {
  const body: Body = { status, ...(message ? { message } : {}), ...fields };
  res.writeHead(code, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(body));
}

async function readJSON(req: http.IncomingMessage): Promise<Body> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  const v: unknown = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  if (typeof v !== 'object' || v === null) throw new Error('body is not a JSON object');
  return v as Body;
}

async function handleValidate(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
  let body: Body;
  try {
    body = await readJSON(req);
  } catch (err) {
    return reply(res, 500, 'error', `bad request: ${String(err)}`);
  }
  const { token, audience } = body;
  if (typeof token !== 'string' || typeof audience !== 'string') {
    return reply(res, 500, 'error', 'bad request: token and audience must be strings');
  }
  try {
    const v = await client.validateJwt(audience, token);
    if (!v) return reply(res, 422, 'rejected', 'validateJwt returned null');
    return reply(res, 200, 'ok', undefined, { spiffe_id: v.spiffeId, claims: v.claims });
  } catch (err) {
    return reply(res, 500, 'error', String(err));
  }
}

async function handleFetch(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
  let body: Body;
  try {
    body = await readJSON(req);
  } catch (err) {
    return reply(res, 500, 'error', `bad request: ${String(err)}`);
  }
  const { audience, spiffe_id: spiffeId } = body;
  if (!Array.isArray(audience) || audience.length === 0 || !audience.every((a) => typeof a === 'string')) {
    return reply(res, 500, 'error', 'bad request: audience required');
  }
  try {
    const svid = await client.getJwtSvid(
      audience as string[],
      typeof spiffeId === 'string' && spiffeId !== '' ? { spiffeId } : undefined,
    );
    if (!svid) return reply(res, 500, 'error', 'SDK returned no JWT-SVID');
    return reply(res, 200, 'ok', undefined, {
      svids: [{ spiffe_id: svid.spiffeId, token: svid.token, hint: svid.hint ?? '' }],
    });
  } catch (err) {
    return reply(res, 500, 'error', String(err));
  }
}

function sdkVersion(): string {
  try {
    const p = new URL('../node_modules/@jeengbe/spiffe/package.json', import.meta.url);
    return (JSON.parse(readFileSync(p, 'utf8')) as { version: string }).version;
  } catch {
    return 'unknown';
  }
}

const controlServer = http.createServer((req, res) => {
  const route = `${req.method} ${req.url}`;
  switch (route) {
    case 'POST /v1/jwt/validate':
      void handleValidate(req, res);
      return;
    case 'POST /v1/jwt/fetch':
      void handleFetch(req, res);
      return;
    case 'POST /v1/x509/dial':
      req.resume();
      return reply(
        res,
        501,
        'unsupported',
        '@jeengbe/spiffe has no X.509-SVID peer authentication (it only exposes the raw FetchX509SVID RPC)',
      );
    case 'GET /v1/info':
      return reply(res, 200, 'ok', undefined, {
        sdk: '@jeengbe/spiffe',
        sdk_version: sdkVersion(),
        language: 'typescript',
      });
    default:
      req.resume();
      return reply(res, 404, 'error', `no route ${route}`);
  }
});

function listen(server: tls.Server | http.Server): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve((server.address() as AddressInfo).port));
  });
}

async function main(): Promise<void> {
  void watchX509();
  const [x509Port, controlPort] = await Promise.all([listen(x509Server), listen(controlServer)]);
  await firstSvid;
  process.stdout.write(
    `SPIFFE_HARNESS_VERSION=1\nSPIFFE_X509_PORT=${x509Port}\nSPIFFE_CONTROL_PORT=${controlPort}\nREADY\n`,
  );
}

main().catch((err) => {
  log(`fatal: ${String(err)}`);
  process.exit(1);
});
