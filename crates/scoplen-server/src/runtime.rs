// SPDX-License-Identifier: AGPL-3.0-only
//! First-run material and role supervision.

use std::{path::Path, sync::Arc, time::Duration};

use axum::{Router, http::StatusCode, routing::get};
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
use rustls::{ServerConfig, pki_types::PrivateKeyDer};
use scoplen_store::SqliteStore;
use tokio::{io::AsyncWriteExt, net::TcpListener, time::sleep};
use tokio_rustls::{TlsAcceptor, server::TlsStream};
use tracing::{error, info, warn};

use crate::{Config, Role, ServerError, TlsMode};

/// Result of first-run material generation.
#[derive(Debug, Default)]
pub struct BootstrapResult {
    /// One-time setup link when this invocation created it.
    pub setup_link: Option<String>,
}

/// Create the data directory, deployment key, internal CA, and one-time setup link as needed.
///
/// # Errors
///
/// Returns an error when the data directory, generated key material, or setup-link file cannot
/// be created.
pub fn bootstrap(config: &Config) -> Result<BootstrapResult, ServerError> {
    std::fs::create_dir_all(&config.server.data_dir).map_err(|source| {
        ServerError::DataDirectory { path: config.server.data_dir.clone(), source }
    })?;

    let deployment_key = config.server.data_dir.join("deployment.key");
    if !deployment_key.exists() {
        let mut bytes = [0_u8; 32];
        getrandom::fill(&mut bytes).map_err(|source| ServerError::Material {
            path: deployment_key.clone(),
            source: std::io::Error::other(source.to_string()),
        })?;
        write_private(&deployment_key, &hex_bytes(&bytes))?;
    }

    let ca_certificate = config.server.data_dir.join("internal-ca.pem");
    let ca_key = config.server.data_dir.join("internal-ca-key.pem");
    if !ca_certificate.exists() || !ca_key.exists() {
        let mut params = CertificateParams::new(vec![config.server.public_host.clone()])
            .map_err(|error| ServerError::Tls(error.to_string()))?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let key_pair = KeyPair::generate().map_err(|error| ServerError::Tls(error.to_string()))?;
        let certificate =
            params.self_signed(&key_pair).map_err(|error| ServerError::Tls(error.to_string()))?;
        write_private(&ca_certificate, &certificate.pem())?;
        write_private(&ca_key, &key_pair.serialize_pem())?;
    }

    let setup_file = config.server.data_dir.join("setup-link.txt");
    if setup_file.exists() {
        return Ok(BootstrapResult::default());
    }
    let token = uuid::Uuid::new_v4();
    let link = format!("https://{}/setup/{}", config.server.public_host, token);
    write_private(&setup_file, &link)?;
    Ok(BootstrapResult { setup_link: Some(link) })
}

fn write_private(path: &Path, contents: &str) -> Result<(), ServerError> {
    std::fs::write(path, format!("{contents}\n"))
        .map_err(|source| ServerError::Material { path: path.to_path_buf(), source })
}

fn hex_bytes(bytes: &[u8]) -> String {
    use std::fmt::Write;

    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut value, "{byte:02x}").expect("writing to a String cannot fail");
    }
    value
}

/// Open and migrate the deployment database before first-run material is generated.
///
/// # Errors
///
/// Returns an error when configuration is invalid or storage cannot be initialized.
pub async fn initialize_store(config: &Config) -> Result<SqliteStore, ServerError> {
    config.validate()?;
    Ok(SqliteStore::open(&config.server.data_dir.join("scoplen.sqlite")).await?)
}

/// Run the requested roles until Ctrl-C using initialized storage.
///
/// # Errors
///
/// Returns an error when signal handling, listener startup, or a role task fails.
pub async fn run_roles(
    config: Config,
    roles: Vec<Role>,
    store: SqliteStore,
) -> Result<(), ServerError> {
    let store = Arc::new(store);
    let mut tasks = Vec::new();
    if roles.contains(&Role::Api) || roles.contains(&Role::Edge) {
        tasks.push(tokio::spawn(run_public_listener(config.clone(), roles.clone(), store.clone())));
    }
    if roles.contains(&Role::Worker) {
        tasks.push(tokio::spawn(run_periodic_role("worker")));
    }
    if roles.contains(&Role::Ca) {
        tasks.push(tokio::spawn(run_periodic_role("ca")));
    }
    if roles.contains(&Role::Gateway) {
        tasks.push(tokio::spawn(run_periodic_role("gateway")));
    }
    info!(roles = ?roles, "server roles started");
    tokio::signal::ctrl_c().await.map_err(ServerError::Runtime)?;
    for task in tasks {
        task.abort();
    }
    info!("server shutdown requested");
    Ok(())
}

async fn run_periodic_role(name: &'static str) -> Result<(), ServerError> {
    loop {
        info!(role = name, "role heartbeat");
        sleep(Duration::from_secs(30)).await;
    }
}

fn api_router(store: Arc<SqliteStore>) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route(
            "/readyz",
            get(move || {
                let store = store.clone();
                async move {
                    match store.ping().await {
                        Ok(()) => (StatusCode::OK, "ready"),
                        Err(error) => {
                            error!(%error, "readiness database query failed");
                            (StatusCode::SERVICE_UNAVAILABLE, "database unavailable")
                        }
                    }
                }
            }),
        )
        .route("/metrics", get(|| async {
            format!(
                "# HELP scoplen_server_info Server build information.\n# TYPE scoplen_server_info gauge\nscoplen_server_info{{version=\"{}\"}} 1\n",
                crate::VERSION
            )
        }))
        .route("/", get(|| async { "Scoplen server" }))
}

async fn run_public_listener(
    config: Config,
    roles: Vec<Role>,
    store: Arc<SqliteStore>,
) -> Result<(), ServerError> {
    let address = config.listen_address();
    let listener = TcpListener::bind(&address).await?;
    info!(%address, tls_mode = ?config.tls.mode, "public listener started");
    match config.tls.mode {
        TlsMode::Plain => {
            if roles.contains(&Role::Edge) {
                warn!(
                    "edge role is configured behind plain HTTP; gateway ALPN requires direct TLS"
                );
            }
            axum::serve(listener, api_router(store))
                .await
                .map_err(|error| ServerError::Task(error.to_string()))?;
        }
        TlsMode::Files => {
            let acceptor = TlsAcceptor::from(Arc::new(tls_config(&config)?));
            loop {
                let (stream, peer) = listener.accept().await?;
                let acceptor = acceptor.clone();
                let router = api_router(store.clone());
                tokio::spawn(async move {
                    match acceptor.accept(stream).await {
                        Ok(tls) => {
                            if let Err(error) = serve_tls_connection(tls, router).await {
                                error!(%peer, %error, "TLS connection failed");
                            }
                        }
                        Err(error) => error!(%peer, %error, "TLS handshake failed"),
                    }
                });
            }
        }
        TlsMode::Acme => {
            return Err(ServerError::Tls(
                "ACME TLS-ALPN provisioning is selected but not enabled in this baseline; use files mode or a TLS-terminating proxy while V1 is in progress".into(),
            ));
        }
    }
    Ok(())
}

fn tls_config(config: &Config) -> Result<ServerConfig, ServerError> {
    let cert_path = config
        .tls
        .cert_file
        .as_ref()
        .ok_or_else(|| ServerError::Tls("tls.cert_file is required in files mode".into()))?;
    let key_path = config
        .tls
        .key_file
        .as_ref()
        .ok_or_else(|| ServerError::Tls("tls.key_file is required in files mode".into()))?;
    let mut cert_file = std::io::BufReader::new(
        std::fs::File::open(cert_path).map_err(|error| ServerError::Tls(error.to_string()))?,
    );
    let certificates = rustls_pemfile::certs(&mut cert_file)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| ServerError::Tls(error.to_string()))?;
    if certificates.is_empty() {
        return Err(ServerError::Tls("tls.cert_file contains no certificates".into()));
    }
    let mut key_file = std::io::BufReader::new(
        std::fs::File::open(key_path).map_err(|error| ServerError::Tls(error.to_string()))?,
    );
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_file)
        .map_err(|error| ServerError::Tls(error.to_string()))?
        .ok_or_else(|| ServerError::Tls("tls.key_file contains no private key".into()))?;
    let mut server = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .map_err(|error| ServerError::Tls(error.to_string()))?;
    server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"spl-gw/1".to_vec()];
    Ok(server)
}

async fn serve_tls_connection(
    mut stream: TlsStream<tokio::net::TcpStream>,
    router: Router,
) -> Result<(), ServerError> {
    use hyper_util::{
        rt::{TokioExecutor, TokioIo},
        server::conn::auto::Builder,
        service::TowerToHyperService,
    };

    let protocol =
        stream.get_ref().1.alpn_protocol().map_or_else(|| b"http/1.1".to_vec(), ToOwned::to_owned);
    if protocol.as_slice() == b"spl-gw/1" {
        stream
            .write_all(b"SPL gateway protocol is reserved for the managed data-path gate.\n")
            .await?;
        return Ok(());
    }
    let io = TokioIo::new(stream);
    let service = TowerToHyperService::new(router);
    Builder::new(TokioExecutor::new())
        .serve_connection_with_upgrades(io, service)
        .await
        .map_err(|error| ServerError::Task(error.to_string()))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use scoplen_store::RelationalStore;
    use tokio::io::AsyncReadExt;

    async fn remove_test_directory(path: &Path) {
        for attempt in 0..20 {
            match fs::remove_dir_all(path) {
                Ok(()) => return,
                Err(error) if error.raw_os_error() == Some(32) && attempt < 19 => {
                    sleep(Duration::from_millis(50)).await;
                }
                Err(error) => panic!("remove test directory {}: {error}", path.display()),
            }
        }
    }

    #[test]
    fn bootstrap_creates_private_material_once() {
        let data_dir =
            std::env::temp_dir().join(format!("scoplen-server-{}", uuid::Uuid::new_v4()));
        let mut config = Config::default();
        config.server.data_dir = data_dir.clone();

        let first = bootstrap(&config).expect("first bootstrap succeeds");
        assert!(first.setup_link.is_some());
        for name in ["deployment.key", "internal-ca.pem", "internal-ca-key.pem", "setup-link.txt"] {
            let path = data_dir.join(name);
            assert!(path.is_file(), "expected generated material at {}", path.display());
        }

        let second = bootstrap(&config).expect("second bootstrap is idempotent");
        assert!(second.setup_link.is_none());
        fs::remove_dir_all(data_dir).expect("test material is removable");
    }

    #[tokio::test]
    async fn readiness_follows_database_availability() {
        let data_dir = std::env::temp_dir().join(format!("scoplen-ready-{}", uuid::Uuid::new_v4()));
        let store =
            SqliteStore::open(&data_dir.join("scoplen.sqlite")).await.expect("open database");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind isolated HTTP listener");
        let address = listener.local_addr().expect("read listener address");
        let server_store = store.clone();
        let server = tokio::spawn(async move {
            axum::serve(listener, api_router(Arc::new(server_store)))
                .await
                .expect("serve readiness endpoint");
        });
        assert!(http_readiness(address).await.starts_with("HTTP/1.1 200 OK"));

        store.pool().close().await;
        assert!(http_readiness(address).await.starts_with("HTTP/1.1 503 Service Unavailable"));
        server.abort();
        let _ = server.await;
        drop(store);
        remove_test_directory(&data_dir).await;
    }

    async fn http_readiness(address: std::net::SocketAddr) -> String {
        let mut stream =
            tokio::net::TcpStream::connect(address).await.expect("connect to listener");
        stream
            .write_all(b"GET /readyz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .expect("send HTTP request");
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.expect("read HTTP response");
        String::from_utf8(response).expect("HTTP response is UTF-8")
    }

    #[tokio::test]
    async fn server_refuses_unwritable_database_path() {
        let data_dir = std::env::temp_dir().join(format!("scoplen-path-{}", uuid::Uuid::new_v4()));
        fs::write(&data_dir, "occupied").expect("create file where directory is needed");
        let mut config = Config::default();
        config.server.data_dir = data_dir.clone();
        let result = initialize_store(&config).await;
        assert!(matches!(result, Err(ServerError::Storage(_))));
        fs::remove_file(data_dir).expect("test file is removable");
    }
}
