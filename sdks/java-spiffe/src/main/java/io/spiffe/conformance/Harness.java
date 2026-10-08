package io.spiffe.conformance;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import io.spiffe.exception.AuthorityNotFoundException;
import io.spiffe.exception.BundleNotFoundException;
import io.spiffe.exception.JwtSvidException;
import io.spiffe.provider.SpiffeSslContextFactory;
import io.spiffe.provider.SpiffeSslContextFactory.SslContextOptions;
import io.spiffe.spiffeid.SpiffeId;
import io.spiffe.svid.jwtsvid.JwtSvid;
import io.spiffe.workloadapi.DefaultJwtSource;
import io.spiffe.workloadapi.DefaultWorkloadApiClient;
import io.spiffe.workloadapi.DefaultX509Source;
import io.spiffe.workloadapi.JwtSource;
import io.spiffe.workloadapi.WorkloadApiClient;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Conformance harness for java-spiffe. Implements harness contract v1
 * (docs/HARNESS_CONTRACT.md) using only java-spiffe's public APIs:
 * {@link DefaultX509Source}, {@link DefaultJwtSource}, {@link DefaultWorkloadApiClient},
 * {@link SpiffeSslContextFactory} (SpiffeKeyManager + SpiffeTrustManager) and
 * {@link JwtSvid#parseAndValidate}.
 */
public final class Harness {
    private static final Logger log = Logger.getLogger(Harness.class.getName());
    private static final Gson GSON = new GsonBuilder().disableHtmlEscaping().serializeNulls().create();
    private static final InetAddress LOOPBACK = InetAddress.getLoopbackAddress();

    private Harness() {
    }

    public static void main(String[] args) throws Exception {
        // Everything not part of the stdout protocol goes to stderr.
        PrintStream stdout = System.out;
        System.setOut(System.err);

        // The client discovers the endpoint from SPIFFE_ENDPOINT_SOCKET.
        final WorkloadApiClient client;
        final DefaultX509Source x509Source;
        try {
            client = DefaultWorkloadApiClient.newClient();
            // Blocks until the first X509Context update (no timeout: the suite owns the deadline).
            x509Source = DefaultX509Source.newSource(DefaultX509Source.X509SourceOptions.builder()
                    .workloadApiClient(client)
                    .initTimeout(Duration.ZERO)
                    .build());
        } catch (Exception e) {
            log.log(Level.SEVERE, "create X.509 source", e);
            System.exit(1);
            return;
        }
        // DefaultX509Source.newSource also returns when the watcher failed terminally
        // (e.g. InvalidArgument). Only report READY once the SDK actually holds an SVID.
        try {
            x509Source.getX509Svid();
        } catch (IllegalStateException e) {
            log.log(Level.SEVERE, "X.509 source has no SVID: " + e.getMessage());
            System.exit(1);
            return;
        }

        SSLContext sslContext = SpiffeSslContextFactory.getSslContext(SslContextOptions.builder()
                .x509Source(x509Source)
                .acceptAnySpiffeId()
                .sslProtocol("TLSv1.3")
                .build());

        // The JWT source is created lazily so that a missing JWT bundle does not
        // prevent X.509 tests from running. It uses its own Workload API client
        // (from SPIFFE_ENDPOINT_SOCKET), because a failed DefaultJwtSource closes
        // the client it was given.
        LazyJwtSource jwtSource = new LazyJwtSource();

        SSLServerSocket x509Ln = (SSLServerSocket) sslContext.getServerSocketFactory()
                .createServerSocket(0, 128, LOOPBACK);
        x509Ln.setNeedClientAuth(true);

        HttpServer control = HttpServer.create(new InetSocketAddress(LOOPBACK, 0), 128);
        control.createContext("/v1/jwt/validate", post(ex -> handleValidate(ex, jwtSource)));
        control.createContext("/v1/jwt/fetch", post(ex -> handleFetch(ex, client)));
        control.createContext("/v1/x509/dial", post(ex -> handleDial(ex, sslContext)));
        control.createContext("/v1/info", Harness::handleInfo);
        control.setExecutor(Executors.newCachedThreadPool(daemonThreads("control")));
        control.start();

        Thread acceptor = new Thread(() -> serveX509(x509Ln), "x509-accept");
        acceptor.setDaemon(true);
        acceptor.start();

        stdout.print("SPIFFE_HARNESS_VERSION=1\n");
        stdout.print("SPIFFE_X509_PORT=" + x509Ln.getLocalPort() + "\n");
        stdout.print("SPIFFE_CONTROL_PORT=" + control.getAddress().getPort() + "\n");
        stdout.print("READY\n");
        stdout.flush();

        // The JVM exits on SIGTERM (shutdown hooks run, then halt). Nothing to clean up:
        // no state lives outside the process. Block forever until then.
        new java.util.concurrent.CountDownLatch(1).await();
    }

    // --- X.509 port ---------------------------------------------------------------------------

    /**
     * Completes the mTLS handshake (SpiffeTrustManager authenticates the client against the
     * bundle for its trust domain), writes the client's SPIFFE ID and closes the connection.
     */
    private static void serveX509(SSLServerSocket ln) {
        while (true) {
            final SSLSocket conn;
            try {
                conn = (SSLSocket) ln.accept();
            } catch (IOException e) {
                log.log(Level.WARNING, "X.509 accept", e);
                return;
            }
            Thread t = new Thread(() -> {
                try (SSLSocket c = conn) {
                    c.setSoTimeout(10_000);
                    try {
                        c.startHandshake();
                    } catch (IOException e) {
                        log.info("X.509 handshake rejected: " + e);
                        return;
                    }
                    String id = peerId(c);
                    OutputStream out = c.getOutputStream();
                    out.write((id + "\n").getBytes(StandardCharsets.UTF_8));
                    out.flush();
                } catch (Exception e) {
                    log.info("X.509 connection: " + e);
                }
            }, "x509-conn");
            t.setDaemon(true);
            t.start();
        }
    }

    /**
     * Returns the SPIFFE ID of the authenticated peer. By the time this runs, SpiffeTrustManager has
     * already validated the chain and extracted (exactly one) SPIFFE ID from the leaf's URI SAN;
     * java-spiffe has no public helper to read it back, so it is read from the leaf here and parsed
     * with {@link SpiffeId#parse}.
     */
    private static String peerId(SSLSocket socket) throws IOException, CertificateParsingException {
        Certificate[] peer = socket.getSession().getPeerCertificates();
        X509Certificate leaf = (X509Certificate) peer[0];
        Collection<List<?>> sans = leaf.getSubjectAlternativeNames();
        if (sans != null) {
            for (List<?> san : sans) {
                if (Integer.valueOf(6).equals(san.get(0)) && san.get(1) instanceof String
                        && ((String) san.get(1)).startsWith("spiffe://")) {
                    return SpiffeId.parse((String) san.get(1)).toString();
                }
            }
        }
        throw new IOException("peer certificate has no SPIFFE ID");
    }

    // --- control port -------------------------------------------------------------------------

    private static void handleValidate(HttpExchange ex, LazyJwtSource sources) throws IOException {
        JsonObject req;
        String token;
        String audience;
        try {
            req = readJson(ex);
            token = req.get("token").getAsString();
            audience = req.get("audience").getAsString();
        } catch (Exception e) {
            reply(ex, 500, "error", "bad request: " + e, null);
            return;
        }
        JwtSource source;
        try {
            source = sources.get(8, TimeUnit.SECONDS);
        } catch (TimeoutException e) {
            reply(ex, 500, "error", "timed out waiting for the first JWT bundle", null);
            return;
        } catch (Exception e) {
            reply(ex, 500, "error", "JWT source: " + rootMessage(e), null);
            return;
        }
        JwtSvid svid;
        try {
            svid = JwtSvid.parseAndValidate(token, source, Set.of(audience));
        } catch (JwtSvidException | BundleNotFoundException | AuthorityNotFoundException
                 | IllegalArgumentException e) {
            // IllegalArgumentException is java-spiffe's documented signal for a token that
            // cannot be parsed (and InvalidSpiffeIdException extends it).
            reply(ex, 422, "rejected", e.getClass().getSimpleName() + ": " + e.getMessage(), null);
            return;
        } catch (RuntimeException e) {
            log.log(Level.WARNING, "parseAndValidate threw unexpectedly", e);
            reply(ex, 500, "error", "SDK threw " + e, null);
            return;
        }
        Map<String, Object> fields = new LinkedHashMap<>();
        fields.put("spiffe_id", svid.getSpiffeId().toString());
        fields.put("claims", jsonClaims(svid.getClaims()));
        reply(ex, 200, "ok", null, fields);
    }

    private static void handleFetch(HttpExchange ex, WorkloadApiClient client) throws IOException {
        List<String> audience = new ArrayList<>();
        String spiffeId = "";
        try {
            JsonObject req = readJson(ex);
            JsonElement aud = req.get("audience");
            if (aud != null && aud.isJsonArray()) {
                for (JsonElement a : aud.getAsJsonArray()) {
                    audience.add(a.getAsString());
                }
            }
            JsonElement id = req.get("spiffe_id");
            if (id != null && !id.isJsonNull()) {
                spiffeId = id.getAsString();
            }
        } catch (Exception e) {
            reply(ex, 500, "error", "bad request: " + e, null);
            return;
        }
        if (audience.isEmpty()) {
            reply(ex, 500, "error", "bad request: audience required", null);
            return;
        }
        String first = audience.get(0);
        String[] extra = audience.subList(1, audience.size()).toArray(new String[0]);
        List<JwtSvid> svids;
        try {
            if (spiffeId.isEmpty()) {
                svids = client.fetchJwtSvids(first, extra);
            } else {
                SpiffeId subject;
                try {
                    subject = SpiffeId.parse(spiffeId);
                } catch (IllegalArgumentException e) {
                    reply(ex, 500, "error", "bad spiffe_id: " + e.getMessage(), null);
                    return;
                }
                svids = client.fetchJwtSvids(subject, first, extra);
            }
        } catch (Exception e) {
            reply(ex, 500, "error", rootMessage(e), null);
            return;
        }
        JsonArray out = new JsonArray();
        for (JwtSvid s : svids) {
            JsonObject o = new JsonObject();
            o.addProperty("spiffe_id", s.getSpiffeId().toString());
            o.addProperty("token", s.marshal());
            o.addProperty("hint", s.getHint() == null ? "" : s.getHint());
            out.add(o);
        }
        Map<String, Object> fields = new LinkedHashMap<>();
        fields.put("svids", out);
        reply(ex, 200, "ok", null, fields);
    }

    private static void handleDial(HttpExchange ex, SSLContext sslContext) throws IOException {
        String address;
        String host;
        int port;
        try {
            address = readJson(ex).get("address").getAsString();
            int i = address.lastIndexOf(':');
            host = address.substring(0, i);
            port = Integer.parseInt(address.substring(i + 1));
        } catch (Exception e) {
            reply(ex, 500, "error", "bad request: " + e, null);
            return;
        }
        Socket raw = new Socket();
        try {
            raw.connect(new InetSocketAddress(host, port), 5_000);
        } catch (IOException e) {
            raw.close();
            reply(ex, 500, "error", "connect: " + e.getMessage(), null);
            return;
        }
        try (SSLSocket conn = (SSLSocket) sslContext.getSocketFactory().createSocket(raw, host, port, true)) {
            conn.setSoTimeout(5_000);
            try {
                conn.startHandshake();
            } catch (IOException e) {
                reply(ex, 422, "rejected", rootMessage(e), null);
                return;
            }
            String id;
            try {
                id = peerId(conn);
            } catch (Exception e) {
                reply(ex, 422, "rejected", e.getMessage(), null);
                return;
            }
            Map<String, Object> fields = new LinkedHashMap<>();
            fields.put("spiffe_id", id);
            reply(ex, 200, "ok", null, fields);
        }
    }

    private static void handleInfo(HttpExchange ex) throws IOException {
        if (!"GET".equals(ex.getRequestMethod())) {
            plain(ex, 405, "method not allowed");
            return;
        }
        String version = "unknown";
        try (InputStream in = Harness.class.getResourceAsStream("/harness.properties")) {
            if (in != null) {
                Properties p = new Properties();
                p.load(in);
                version = p.getProperty("sdk.version", version);
            }
        } catch (IOException ignored) {
            // report "unknown"
        }
        Map<String, Object> fields = new LinkedHashMap<>();
        fields.put("sdk", "java-spiffe");
        fields.put("sdk_version", version);
        fields.put("language", "java");
        reply(ex, 200, "ok", null, fields);
    }

    // --- helpers ------------------------------------------------------------------------------

    private interface Handler {
        void handle(HttpExchange ex) throws IOException;
    }

    private static HttpHandler post(Handler h) {
        return ex -> {
            try {
                if (!"POST".equals(ex.getRequestMethod())) {
                    plain(ex, 405, "method not allowed");
                    return;
                }
                h.handle(ex);
            } catch (Exception e) {
                log.log(Level.WARNING, "handler failed", e);
                try {
                    reply(ex, 500, "error", "harness: " + e, null);
                } catch (Exception ignored) {
                    // response already started
                }
            } finally {
                ex.close();
            }
        };
    }

    private static JsonObject readJson(HttpExchange ex) throws IOException {
        String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        return JsonParser.parseString(body).getAsJsonObject();
    }

    private static void reply(HttpExchange ex, int code, String status, String message,
                              Map<String, Object> fields) throws IOException {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", status);
        if (message != null && !message.isEmpty()) {
            body.put("message", message);
        }
        if (fields != null) {
            body.putAll(fields);
        }
        byte[] bytes = GSON.toJson(body).getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json");
        ex.sendResponseHeaders(code, bytes.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(bytes);
        }
    }

    private static void plain(HttpExchange ex, int code, String text) throws IOException {
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "text/plain");
        ex.sendResponseHeaders(code, bytes.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(bytes);
        }
    }

    /** Converts the SDK's claim map to JSON-friendly values (NumericDate claims come back as Date). */
    private static Object jsonClaims(Object v) {
        if (v instanceof Date) {
            return ((Date) v).getTime() / 1000;
        }
        if (v instanceof Map) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<?, ?> e : ((Map<?, ?>) v).entrySet()) {
                out.put(String.valueOf(e.getKey()), jsonClaims(e.getValue()));
            }
            return out;
        }
        if (v instanceof Collection) {
            List<Object> out = new ArrayList<>();
            for (Object o : (Collection<?>) v) {
                out.add(jsonClaims(o));
            }
            return out;
        }
        return v;
    }

    private static String rootMessage(Throwable e) {
        StringBuilder sb = new StringBuilder(String.valueOf(e));
        for (Throwable c = e.getCause(); c != null && c != c.getCause(); c = c.getCause()) {
            sb.append(": ").append(c);
        }
        return sb.toString();
    }

    private static java.util.concurrent.ThreadFactory daemonThreads(String name) {
        return r -> {
            Thread t = new Thread(r, name);
            t.setDaemon(true);
            return t;
        };
    }

    /** Creates a DefaultJwtSource on first use and reuses it (including a failed result). */
    private static final class LazyJwtSource {
        private CompletableFuture<JwtSource> future;

        synchronized CompletableFuture<JwtSource> start() {
            if (future == null) {
                future = CompletableFuture.supplyAsync(() -> {
                    try {
                        return DefaultJwtSource.newSource(io.spiffe.workloadapi.JwtSourceOptions.builder()
                                .initTimeout(Duration.ZERO)
                                .build());
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }, Executors.newSingleThreadExecutor(daemonThreads("jwt-source")));
            }
            return future;
        }

        JwtSource get(long timeout, TimeUnit unit) throws InterruptedException, ExecutionException, TimeoutException {
            return start().get(timeout, unit);
        }
    }
}
