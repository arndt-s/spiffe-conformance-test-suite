import * as tls from 'tls';
import * as http from 'http';
import * as net from 'net';
import { webcrypto } from 'crypto';
import { WorkloadAPIClient, parseAndValidateJwtSVID } from '@defakto/spiffe';

async function exportPrivateKeyToPEM(privateKey: webcrypto.CryptoKey): Promise<string> {
  const exported = await webcrypto.subtle.exportKey('pkcs8', privateKey);
  const exportedAsBase64 = Buffer.from(exported).toString('base64');
  const pemExported = `-----BEGIN PRIVATE KEY-----\n${exportedAsBase64.match(/.{1,64}/g)?.join('\n')}\n-----END PRIVATE KEY-----\n`;
  return pemExported;
}

async function main() {
  const audience = 'conformance';

  // Create Workload API client (ready after construction)
  const client = new WorkloadAPIClient();

  // Wait for initial X.509 SVID before creating TLS server
  const initialSVID = await client.x509.getSVID();
  const initialCert = initialSVID.certificates.map(c => c.toString()).join('');
  const initialKey = await exportPrivateKeyToPEM(initialSVID.privateKey);

  // Cache current credentials (updated on rotation)
  let cachedCert = initialCert;
  let cachedKey = initialKey;

  // X.509 TLS server with initial credentials
  const tlsServer = tls.createServer({
    cert: initialCert,
    key: initialKey,
  }, (socket) => {
    // Hold the connection open until client closes
    socket.on('data', () => {});
    socket.on('error', () => socket.destroy());
  });

  // Watch for SVID updates to support rotation (run in background)
  (async () => {
    try {
      for await (const svid of client.x509.watchSVID()) {
        console.log('Received updated SVID, rotating credentials');
        console.log(`New SPIFFE ID: ${svid.id}`);
        cachedCert = svid.certificates.map(c => c.toString()).join('');
        cachedKey = await exportPrivateKeyToPEM(svid.privateKey);
        
        // Update the server's secure context with new credentials
        tlsServer.setSecureContext({
          cert: cachedCert,
          key: cachedKey,
        });
      }
    } catch (err) {
      console.error(`SVID watch error: ${err}`);
    }
  })();

  tlsServer.listen(0, () => {
    const address = tlsServer.address() as net.AddressInfo;
    const x509Port = address.port;
    console.log(`SPIFFE_X509_PORT=${x509Port}`);
  });

  // JWT HTTP server
  const httpServer = http.createServer(async (req, res) => {
    if (req.url !== '/jwt') {
      res.writeHead(404);
      res.end();
      return;
    }

    // Extract JWT from Authorization header
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        status: 'invalid',
        spiffe_id: '',
        message: 'missing Authorization header'
      }));
      return;
    }

    // Expect "Bearer <token>" format
    const prefix = 'Bearer ';
    if (!authHeader.startsWith(prefix)) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        status: 'invalid',
        spiffe_id: '',
        message: 'invalid Authorization header format'
      }));
      return;
    }

    const token = authHeader.slice(prefix.length);
    if (!token) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        status: 'invalid',
        spiffe_id: '',
        message: 'empty token'
      }));
      return;
    }

    try {
      // Parse and validate the JWT using client.jwt as bundle source
      const svid = await parseAndValidateJwtSVID(token, client.jwt, [audience]);
      
      console.log(`Validated JWT for SPIFFE ID: ${svid.id}`);

      // Return validation success with SPIFFE ID
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        status: 'valid',
        spiffe_id: svid.id.toString(),
        message: 'JWT validation successful'
      }));
    } catch (err) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        status: 'invalid',
        spiffe_id: '',
        message: `invalid JWT: ${err}`
      }));
    }
  });

  httpServer.listen(0, () => {
    const address = httpServer.address() as net.AddressInfo;
    const jwtPort = address.port;
    console.log(`SPIFFE_JWT_PORT=${jwtPort}`);
    console.log('READY');
  });

  // Handle graceful shutdown
  const shutdown = async () => {
    console.log('Shutting down...');
    httpServer.close();
    tlsServer.close();
    await client.close();
    process.exit(0);
  };

  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

main().catch((err) => {
  console.error(`Fatal error: ${err}`);
  process.exit(1);
});
