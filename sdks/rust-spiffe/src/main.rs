//! Conformance harness for rust-spiffe (`spiffe` + `spiffe-rustls`).
//!
//! Implements harness contract v1 (docs/HARNESS_CONTRACT.md) using only the
//! SDK's idiomatic public APIs:
//!
//! * `spiffe::X509Source` / `spiffe::JwtSource` / `spiffe::WorkloadApiClient`,
//!   all discovering the Workload API from `SPIFFE_ENDPOINT_SOCKET`;
//! * `spiffe_rustls::{mtls_server, mtls_client}` with `authorizer::any()` for the
//!   X.509 port and `/v1/x509/dial`;
//! * `spiffe::JwtSvid::parse_and_validate` (offline validation against the
//!   `JwtSource` bundle set) for `/v1/jwt/validate`.
//!
//! The protocol lines go to stdout; all logging goes to stderr.

use std::io::Write as _;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use spiffe::{JwtSource, JwtSvid, SpiffeId, WorkloadApiClient, X509Source};
use spiffe_rustls::{authorizer, mtls_client, mtls_server};
use tokio::io::AsyncWriteExt as _;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, OnceCell};
use tokio_rustls::{TlsAcceptor, TlsConnector};

const SDK_NAME: &str = "rust-spiffe";
const SDK_VERSION: &str = "spiffe 0.18.0, spiffe-rustls 0.10.0";

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .target(env_logger::Target::Stderr)
        .init();

    let mut sigterm = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    {
        Ok(s) => s,
        Err(e) => {
            log::error!("install SIGTERM handler: {e}");
            std::process::exit(1);
        }
    };

    // Exit promptly on SIGTERM/SIGINT, also while still waiting for the first SVID.
    tokio::select! {
        res = run() => {
            if let Err(e) = res {
                log::error!("{e}");
                std::process::exit(1);
            }
        }
        _ = sigterm.recv() => log::info!("SIGTERM received, exiting"),
        _ = tokio::signal::ctrl_c() => log::info!("SIGINT received, exiting"),
    }
    std::process::exit(0);
}

struct AppState {
    dial: TlsConnector,
    jwt: Arc<LazyJwtSource>,
    client: OnceCell<WorkloadApiClient>,
}

async fn run() -> Result<(), String> {
    // Endpoint discovered from SPIFFE_ENDPOINT_SOCKET. Resolves once the first
    // X.509-SVID has been received.
    let x509 = X509Source::new()
        .await
        .map_err(|e| format!("create X509Source: {e}"))?;
    log::info!("X509Source ready");

    let server_cfg = mtls_server(x509.clone())
        .authorize(authorizer::any())
        .build()
        .map_err(|e| format!("build mTLS server config: {e}"))?;
    let client_cfg = mtls_client(x509.clone())
        .authorize(authorizer::any())
        .build()
        .map_err(|e| format!("build mTLS client config: {e}"))?;

    let x509_ln = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("listen X.509: {e}"))?;
    let control_ln = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("listen control: {e}"))?;
    let x509_port = x509_ln.local_addr().map_err(|e| e.to_string())?.port();
    let control_port = control_ln.local_addr().map_err(|e| e.to_string())?.port();

    tokio::spawn(serve_x509(x509_ln, TlsAcceptor::from(Arc::new(server_cfg))));

    let state = Arc::new(AppState {
        dial: TlsConnector::from(Arc::new(client_cfg)),
        jwt: LazyJwtSource::new(),
        client: OnceCell::new(),
    });
    let app = Router::new()
        .route("/v1/jwt/validate", post(handle_validate))
        .route("/v1/jwt/fetch", post(handle_fetch))
        .route("/v1/x509/dial", post(handle_dial))
        .route("/v1/info", get(handle_info))
        .with_state(Arc::clone(&state));
    tokio::spawn(async move {
        if let Err(e) = axum::serve(control_ln, app).await {
            log::error!("control server: {e}");
        }
    });

    {
        let mut out = std::io::stdout().lock();
        let _ = writeln!(out, "SPIFFE_HARNESS_VERSION=1");
        let _ = writeln!(out, "SPIFFE_X509_PORT={x509_port}");
        let _ = writeln!(out, "SPIFFE_CONTROL_PORT={control_port}");
        let _ = writeln!(out, "READY");
        let _ = out.flush();
    }

    std::future::pending::<()>().await;
    Ok(())
}

// ---------------------------------------------------------------------------
// X.509 port
// ---------------------------------------------------------------------------

/// Completes the mTLS handshake (spiffe-rustls authenticates the client against
/// the bundle for its trust domain), writes the client's SPIFFE ID and closes.
async fn serve_x509(listener: TcpListener, acceptor: TlsAcceptor) {
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(c) => c,
            Err(e) => {
                log::warn!("X.509 accept: {e}");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let fut = handle_x509_conn(acceptor, tcp, peer);
            if tokio::time::timeout(Duration::from_secs(10), fut).await.is_err() {
                log::warn!("X.509 connection from {peer} timed out");
            }
        });
    }
}

async fn handle_x509_conn(acceptor: TlsAcceptor, tcp: TcpStream, peer: SocketAddr) {
    let mut tls = match acceptor.accept(tcp).await {
        Ok(t) => t,
        Err(e) => {
            log::info!("X.509 handshake from {peer} rejected: {e}");
            return;
        }
    };
    let id = match peer_spiffe_id(tls.get_ref().1.peer_certificates()) {
        Ok(id) => id,
        Err(e) => {
            log::warn!("X.509 peer ID from {peer}: {e}");
            return;
        }
    };
    let _ = tls.write_all(format!("{id}\n").as_bytes()).await;
    let _ = tls.shutdown().await;
}

/// Reads the SPIFFE ID of an already authenticated peer with the SDK's helper.
fn peer_spiffe_id(
    certs: Option<&[rustls::pki_types::CertificateDer<'static>]>,
) -> Result<SpiffeId, String> {
    let leaf = certs
        .and_then(<[_]>::first)
        .ok_or_else(|| "peer presented no certificate".to_owned())?;
    spiffe::cert::spiffe_id_from_der(leaf.as_ref()).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Control port
// ---------------------------------------------------------------------------

fn reply(code: StatusCode, status: &str, message: Option<String>, fields: Value) -> Response {
    let mut body = Map::new();
    body.insert("status".into(), Value::from(status));
    if let Some(m) = message.filter(|m| !m.is_empty()) {
        body.insert("message".into(), Value::from(m));
    }
    if let Value::Object(extra) = fields {
        body.extend(extra);
    }
    (code, axum::Json(Value::Object(body))).into_response()
}

fn ok(fields: Value) -> Response {
    reply(StatusCode::OK, "ok", None, fields)
}

fn rejected(message: String) -> Response {
    reply(StatusCode::UNPROCESSABLE_ENTITY, "rejected", Some(message), Value::Null)
}

fn error(message: String) -> Response {
    reply(StatusCode::INTERNAL_SERVER_ERROR, "error", Some(message), Value::Null)
}

fn parse<T: for<'de> Deserialize<'de>>(body: &Bytes) -> Result<T, Response> {
    serde_json::from_slice(body).map_err(|e| error(format!("bad request: {e}")))
}

#[derive(Deserialize)]
struct ValidateRequest {
    token: String,
    audience: String,
}

async fn handle_validate(State(state): State<Arc<AppState>>, body: Bytes) -> Response {
    let req: ValidateRequest = match parse(&body) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let source = match state.jwt.get().await {
        Ok(s) => s,
        Err(e) => return error(format!("JWT source: {e}")),
    };
    // Offline validation by the SDK against the JWT bundles from the Workload API.
    match JwtSvid::parse_and_validate(&req.token, &source, &[req.audience.as_str()]) {
        Ok(svid) => {
            // The SDK exposes only the required claims (sub, aud, exp).
            let claims = svid.claims();
            ok(json!({
                "spiffe_id": svid.spiffe_id().to_string(),
                "claims": { "sub": claims.sub(), "aud": claims.aud(), "exp": claims.exp() },
            }))
        }
        Err(e) => rejected(e.to_string()),
    }
}

#[derive(Deserialize)]
struct FetchRequest {
    #[serde(default)]
    audience: Vec<String>,
    #[serde(default)]
    spiffe_id: String,
}

async fn handle_fetch(State(state): State<Arc<AppState>>, body: Bytes) -> Response {
    let req: FetchRequest = match parse(&body) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    if req.audience.is_empty() {
        return error("bad request: audience required".into());
    }
    let id = if req.spiffe_id.is_empty() {
        None
    } else {
        match SpiffeId::new(&req.spiffe_id) {
            Ok(id) => Some(id),
            Err(e) => return error(format!("bad spiffe_id: {e}")),
        }
    };
    let client = match state
        .client
        .get_or_try_init(WorkloadApiClient::connect_env)
        .await
    {
        Ok(c) => c,
        Err(e) => return error(format!("connect Workload API: {e}")),
    };
    match client.fetch_all_jwt_svids(&req.audience, id.as_ref()).await {
        Ok(svids) => {
            let out: Vec<Value> = svids
                .iter()
                .map(|s| {
                    json!({
                        "spiffe_id": s.spiffe_id().to_string(),
                        "token": s.token(),
                        "hint": s.hint().unwrap_or(""),
                    })
                })
                .collect();
            ok(json!({ "svids": out }))
        }
        Err(e) => error(e.to_string()),
    }
}

#[derive(Deserialize)]
struct DialRequest {
    address: String,
}

async fn handle_dial(State(state): State<Arc<AppState>>, body: Bytes) -> Response {
    let req: DialRequest = match parse(&body) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    // rustls needs a ServerName; spiffe-rustls authenticates the URI SAN, not the name.
    let host = req
        .address
        .rsplit_once(':')
        .map_or(req.address.as_str(), |(h, _)| h)
        .trim_start_matches('[')
        .trim_end_matches(']');
    let server_name = match rustls::pki_types::ServerName::try_from(host.to_owned()) {
        Ok(n) => n,
        Err(e) => return error(format!("bad address: {e}")),
    };
    let tcp = match tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&req.address)).await {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => return error(format!("dial {}: {e}", req.address)),
        Err(_) => return error(format!("dial {}: timeout", req.address)),
    };
    let tls = match tokio::time::timeout(Duration::from_secs(5), state.dial.connect(server_name, tcp)).await {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => return rejected(e.to_string()),
        Err(_) => return error("TLS handshake timeout".into()),
    };
    let result = peer_spiffe_id(tls.get_ref().1.peer_certificates());
    let mut tls = tls;
    let _ = tls.shutdown().await;
    match result {
        Ok(id) => ok(json!({ "spiffe_id": id.to_string() })),
        Err(e) => rejected(e),
    }
}

async fn handle_info() -> Response {
    ok(json!({ "sdk": SDK_NAME, "sdk_version": SDK_VERSION, "language": "rust" }))
}

// ---------------------------------------------------------------------------
// Lazy JWT source
// ---------------------------------------------------------------------------

/// Creates a `JwtSource` on first use and reuses it, so that a missing JWT
/// bundle does not prevent the X.509 tests from running (mirrors go-spiffe's
/// reference harness).
struct LazyJwtSource {
    started: AtomicBool,
    tx: watch::Sender<Option<Result<JwtSource, String>>>,
}

impl LazyJwtSource {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            started: AtomicBool::new(false),
            tx: watch::Sender::new(None),
        })
    }

    async fn get(self: &Arc<Self>) -> Result<JwtSource, String> {
        if !self.started.swap(true, Ordering::SeqCst) {
            let this = Arc::clone(self);
            tokio::spawn(async move {
                let res = JwtSource::new().await.map_err(|e| e.to_string());
                if let Err(e) = &res {
                    log::warn!("create JwtSource: {e}");
                }
                this.tx.send_replace(Some(res));
            });
        }
        let mut rx = self.tx.subscribe();
        let res = match tokio::time::timeout(Duration::from_secs(8), rx.wait_for(Option::is_some))
            .await
        {
            Ok(Ok(v)) => v.clone().unwrap_or_else(|| Err("JWT source not ready".into())),
            Ok(Err(_)) => Err("JWT source initialisation aborted".into()),
            Err(_) => Err("timed out waiting for the first JWT bundle".into()),
        };
        res
    }
}
