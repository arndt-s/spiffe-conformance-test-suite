// Conformance harness (contract v1, docs/HARNESS_CONTRACT.md) for the `spiffe`
// npm package (github.com/depot/node-spiffe).
//
// That package is a thin, generated gRPC client for the Workload API plus two
// DER parsing helpers. It offers:
//   - createClient(): endpoint discovery from SPIFFE_ENDPOINT_SOCKET and the
//     `workload.spiffe.io: true` security header,
//   - the raw RPCs (FetchX509SVID stream, FetchJWTSVID, ValidateJWTSVID, ...),
//   - parseCertificate / parseCertificateBundle (DER -> @peculiar/x509).
// It does NOT offer: X.509-SVID peer authentication, bundle selection by trust
// domain, local JWT-SVID validation, or stream retry/reconnect. This harness
// therefore does not add any of those; see README.md for what that means for
// each feature group.
import {once} from 'node:events'
import http from 'node:http'
import net from 'node:net'
import tls from 'node:tls'
import {createRequire} from 'node:module'
import {createClient, parseCertificateBundle, Struct, type X509SVIDResponse} from 'spiffe'

const log = (...args: unknown[]) => console.error('[node-spiffe]', ...args)

// The SDK discovers the endpoint from SPIFFE_ENDPOINT_SOCKET.
const client = createClient()

// ---------------------------------------------------------------------------
// X.509: consume the FetchX509SVID stream exactly as the SDK delivers it.
// ---------------------------------------------------------------------------

let serving = false
let firstSVID = true
let markReady: () => void
const svidReceived = new Promise<void>((resolve) => (markReady = resolve))

const toPEM = (der: Uint8Array): string[] => parseCertificateBundle(der).map((c) => c.toString('pem'))

// applyX509Response turns the latest X509SVIDResponse into the TLS context the
// X.509 port serves. The first SVID is the default identity. The response is
// used as delivered: the SDK neither validates nor discards responses, so an
// unusable response leaves the X.509 port without an identity.
function applyX509Response(resp: X509SVIDResponse) {
  const svid = resp.svids[0]
  if (!svid) {
    log('X509SVIDResponse without SVIDs; X.509 port has no identity')
    serving = false
    return
  }
  try {
    // setSecureContext applies to new connections (rotation without restart).
    // No CA/bundle is configured: peers are not authenticated (see below).
    x509Server.setSecureContext({cert: toPEM(svid.x509Svid).join(''), key: derKeyToPEM(svid.x509SvidKey)})
  } catch (err) {
    log('cannot use X509SVIDResponse; X.509 port has no identity:', errMessage(err))
    serving = false
    return
  }
  serving = true
  log(`X.509-SVID received: ${svid.spiffeId}`)
  if (firstSVID) {
    firstSVID = false
    markReady()
  }
}

function derKeyToPEM(der: Uint8Array): string {
  const b64 = Buffer.from(der).toString('base64').replace(/(.{64})/g, '$1\n')
  return `-----BEGIN PRIVATE KEY-----\n${b64}\n-----END PRIVATE KEY-----\n`
}

async function watchX509() {
  const call = client.fetchX509SVID({})
  // Avoid unhandled rejections from the call's auxiliary promises.
  for (const p of [call.headers, call.status, call.trailers]) Promise.resolve(p).catch(() => {})
  try {
    for await (const resp of call.responses) applyX509Response(resp)
    log('FetchX509SVID stream ended')
  } catch (err) {
    log('FetchX509SVID stream failed:', errMessage(err))
  }
  // The SDK has no retry/reconnect logic; neither does this shim.
}

// ---------------------------------------------------------------------------
// X.509 port. The SDK provides no X.509-SVID peer authentication, so per the
// contract (§3, "SDKs without peer authentication") the port presents the
// SDK's SVID, requests no client certificate, and writes "-\n" after every
// handshake. No other verification mechanism is substituted.
// ---------------------------------------------------------------------------

const x509Server = tls.createServer({requestCert: false, minVersion: 'TLSv1.2'})
x509Server.prependListener('connection', (sock: net.Socket) => {
  if (!serving) sock.destroy()
})
x509Server.on('secureConnection', (sock: tls.TLSSocket) => sock.end('-\n'))
x509Server.on('tlsClientError', (err) => log('X.509 handshake failed:', err.message))

// ---------------------------------------------------------------------------
// Control port.
// ---------------------------------------------------------------------------

type Body = Record<string, unknown>

function reply(res: http.ServerResponse, code: number, status: string, message?: string, fields?: Body) {
  const body: Body = {status}
  if (message) body.message = message
  Object.assign(body, fields)
  res.writeHead(code, {'Content-Type': 'application/json'})
  res.end(JSON.stringify(body))
}

async function readJSON(req: http.IncomingMessage): Promise<Body> {
  const chunks: Buffer[] = []
  for await (const c of req) chunks.push(c as Buffer)
  const v = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')
  if (typeof v !== 'object' || v === null) throw new Error('body must be a JSON object')
  return v as Body
}

const errMessage = (err: unknown) => (err instanceof Error ? err.message : String(err))
const rpcCode = (err: unknown) => (err as {code?: string})?.code

// /v1/jwt/validate: the SDK can only validate via the Workload API's
// ValidateJWTSVID RPC (the suite marks these results as delegated).
async function handleValidate(req: http.IncomingMessage, res: http.ServerResponse) {
  let token: string, audience: string
  try {
    const b = await readJSON(req)
    token = String(b.token ?? '')
    audience = String(b.audience ?? '')
  } catch (err) {
    return reply(res, 500, 'error', `bad request: ${errMessage(err)}`)
  }
  try {
    const {response} = await client.validateJWTSVID({svid: token, audience})
    const claims = response.claims ? Struct.toJson(response.claims) : {}
    reply(res, 200, 'ok', undefined, {spiffe_id: response.spiffeId, claims})
  } catch (err) {
    // The Workload API answers InvalidArgument for an invalid token.
    if (rpcCode(err) === 'INVALID_ARGUMENT') return reply(res, 422, 'rejected', errMessage(err))
    reply(res, 500, 'error', `ValidateJWTSVID: ${rpcCode(err) ?? ''} ${errMessage(err)}`)
  }
}

async function handleFetch(req: http.IncomingMessage, res: http.ServerResponse) {
  let audience: string[], spiffeId: string
  try {
    const b = await readJSON(req)
    audience = Array.isArray(b.audience) ? b.audience.map(String) : []
    spiffeId = typeof b.spiffe_id === 'string' ? b.spiffe_id : ''
    if (audience.length === 0) throw new Error('audience required')
  } catch (err) {
    return reply(res, 500, 'error', `bad request: ${errMessage(err)}`)
  }
  try {
    const {response} = await client.fetchJWTSVID({audience, spiffeId})
    const svids = response.svids.map((s) => ({spiffe_id: s.spiffeId, token: s.svid, hint: s.hint}))
    reply(res, 200, 'ok', undefined, {svids})
  } catch (err) {
    reply(res, 500, 'error', `FetchJWTSVID: ${rpcCode(err) ?? ''} ${errMessage(err)}`)
  }
}

function sdkVersion(): string {
  try {
    const require = createRequire(import.meta.url)
    return (require('spiffe/package.json') as {version: string}).version
  } catch {
    return 'unknown'
  }
}

const controlServer = http.createServer((req, res) => {
  const route = `${req.method} ${req.url}`
  const run = async () => {
    switch (route) {
      case 'POST /v1/jwt/validate':
        return handleValidate(req, res)
      case 'POST /v1/jwt/fetch':
        return handleFetch(req, res)
      case 'POST /v1/x509/dial':
        req.resume()
        return reply(
          res,
          501,
          'unsupported',
          'the spiffe npm package provides no X.509-SVID peer authentication (no TLS/SVID verification API)',
        )
      case 'GET /v1/info':
        return reply(res, 200, 'ok', undefined, {sdk: 'node-spiffe', sdk_version: sdkVersion(), language: 'typescript'})
      default:
        req.resume()
        return reply(res, 404, 'error', `no route ${route}`)
    }
  }
  run().catch((err) => {
    if (!res.headersSent) reply(res, 500, 'error', errMessage(err))
  })
})

// ---------------------------------------------------------------------------
// Startup and shutdown.
// ---------------------------------------------------------------------------

function shutdown() {
  log('terminating')
  process.exit(0)
}
process.on('SIGTERM', shutdown)
process.on('SIGINT', shutdown)

async function main() {
  void watchX509()

  x509Server.listen(0, '127.0.0.1')
  controlServer.listen(0, '127.0.0.1')
  await Promise.all([once(x509Server, 'listening'), once(controlServer, 'listening')])

  await svidReceived

  const port = (s: net.Server) => (s.address() as net.AddressInfo).port
  process.stdout.write(
    `SPIFFE_HARNESS_VERSION=1\nSPIFFE_X509_PORT=${port(x509Server)}\nSPIFFE_CONTROL_PORT=${port(controlServer)}\nREADY\n`,
  )
}

main().catch((err) => {
  log('fatal:', err)
  process.exit(1)
})
