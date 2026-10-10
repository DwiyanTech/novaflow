use std::{fs::File, io::BufReader, process::ExitCode, sync::Arc};

use anyhow::{anyhow, Result};
use clap::Parser;
use config::{PolicyConfig, ServerConfig};
use engine::Engine;
use hyper::body::Bytes;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto;
use request::{handler::request_handler, RequestData};
use tokio::{net::TcpListener, sync::RwLock};
use tokio_rustls::TlsAcceptor;
use tracing_subscriber::{
    layer::{Layer as _, SubscriberExt as _},
    util::SubscriberInitExt as _,
};

mod admin;
mod config;
mod domain;
mod engine;
mod geoip;
mod logging;
mod proxy;
mod ratelimit;
mod request;
mod response;
mod telemetry;
mod virtualserver;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(short = 'c', long)]
    config: String,
    #[arg(short = 'p', long)]
    policy: String,
}

#[tokio::main]
async fn main() -> ExitCode {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");
    match run(Cli::parse()).await {
        std::result::Result::Ok(_) => ExitCode::SUCCESS,
        std::result::Result::Err(e) => {
            eprintln!("novaflow failed: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: Cli) -> Result<()> {
    let server_config = ServerConfig::load_server_config(&args.config).await?;
    let logging_config = server_config.clone().logging;
    let server_config = Arc::new(RwLock::new(server_config));

    // Structured JSON logging for all events, including the per-request
    // access log emitted by src/request/handler.rs.
    // Blocking stdout is used by default so logs appear immediately even when
    // stdout is redirected to a file. File mode uses the non-blocking rolling
    // appender; its WorkerGuard must outlive the subscriber. Syslog mode sends
    // JSON lines to the local syslog daemon via /dev/log.
    let mut _guard: Option<tracing_appender::non_blocking::WorkerGuard> = None;
    let fmt_layer: Box<dyn tracing_subscriber::layer::Layer<_> + Send + Sync> =
        match logging_config.mode.as_str() {
            "file" => {
                let (writer, guard) = logging_config.output_tofile();
                _guard = Some(guard);
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_current_span(false)
                    .with_target(false)
                    .with_writer(writer)
                    .boxed()
            }
            "syslog" => {
                let writer = logging::SyslogWriter::new("novaflow")
                    .map_err(|e| anyhow::anyhow!("failed to open syslog: {e}"))?;
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_current_span(false)
                    .with_target(false)
                    .with_writer(move || writer.clone())
                    .boxed()
            }
            _ => tracing_subscriber::fmt::layer()
                .json()
                .with_current_span(false)
                .with_target(false)
                .boxed(),
        };

    // Optional OpenTelemetry layer. The OTLP tracer/meter are built once here
    // from the `otel:` config section; when disabled the subscriber runs with
    // the plain JSON format layer only.
    let otel_config = server_config.read().await.otel.clone();
    let mut _telemetry_guard: Option<telemetry::TelemetryGuard> = None;
    let registry = tracing_subscriber::registry().with(fmt_layer);
    if let Some((guard, tracer)) = telemetry::init_telemetry(&otel_config)? {
        _telemetry_guard = Some(guard);
        registry
            .with(tracing_opentelemetry::layer().with_tracer(tracer))
            .try_init()
            .map_err(|e| anyhow!("failed to init tracing subscriber: {e}"))?;
        tracing::info!(
            endpoint = otel_config.endpoint,
            service_name = otel_config.service_name,
            sample_ratio = otel_config.sample_ratio,
            "OpenTelemetry exporter initialized"
        );
    } else {
        registry
            .try_init()
            .map_err(|e| anyhow!("failed to init tracing subscriber: {e}"))?;
    }

    let policy_config: PolicyConfig = PolicyConfig::load_policy_config(&args.policy).await?;

    // Compile the detection engine ONCE: every regex in the policy is
    // validated and compiled here, not per request.
    let engine = Engine::new(policy_config).map_err(|e| anyhow!("invalid policy: {e}"))?;
    let engine = Arc::new(RwLock::new(engine));

    // Download the GeoIP database first if auto-download is configured, then
    // open the GeoIP service for logs, rate limiting, and the admin API.
    let geoip_cfg = server_config.read().await.geoip.clone();
    geoip::download::ensure_database(&geoip_cfg).await?;
    let geoip = Arc::new(geoip::GeoIpService::new(&geoip_cfg)?);

    // Rate limiter with configurable memory or Redis backend.
    let rate_limiter = Arc::new(
        ratelimit::RateLimiter::new(&server_config.read().await.rate_limit)
            .await
            .map_err(|e| anyhow!("rate limiter failed to initialize: {e}"))?,
    );

    tracing::info!(
        mode = ?engine.read().await.mode(),
        "Novaflow WAF v0.2.0 — semantic anomaly-scoring engine"
    );
    tracing::info!("https://github.com/DwiyanTech/novaflow");

    let (ssl_enabled, admin_enabled, admin_separate) = {
        let cfg = server_config.read().await;
        (
            cfg.ssl.enabled,
            cfg.admin_api.enabled,
            !cfg.admin_api.listen_address.is_empty() && cfg.admin_api.listen_port != 0,
        )
    };

    let server_config_main = server_config.clone();
    let engine_main = engine.clone();
    let geoip_main = geoip.clone();
    let rate_limiter_main = rate_limiter.clone();
    let config_path_main = args.config.clone();
    let policy_path_main = args.policy.clone();

    let main_serve = async move {
        if ssl_enabled {
            serve_tls(
                server_config_main,
                engine_main,
                config_path_main,
                policy_path_main,
                geoip_main,
                rate_limiter_main,
            )
            .await
        } else {
            serve_http(
                server_config_main,
                engine_main,
                config_path_main,
                policy_path_main,
                geoip_main,
                rate_limiter_main,
            )
            .await
        }
    };

    if admin_enabled && admin_separate {
        tokio::select! {
            res = main_serve => res,
            res = serve_admin_api(
                server_config,
                engine,
                args.config,
                args.policy,
                geoip,
                rate_limiter,
            ) => res,
        }
    } else {
        main_serve.await
    }
}

async fn serve_tls(
    server_config: Arc<RwLock<ServerConfig>>,
    engine: Arc<RwLock<Engine>>,
    config_path: String,
    policy_path: String,
    geoip: Arc<geoip::GeoIpService>,
    rate_limiter: Arc<ratelimit::RateLimiter>,
) -> Result<()> {
    let (ca_path, key_path, listen_address, listen_port) = {
        let cfg = server_config.read().await;
        (
            cfg.ssl.ca_path.clone(),
            cfg.ssl.key_path.clone(),
            cfg.listen_address.clone(),
            cfg.listen_port,
        )
    };

    let cert_file = File::open(&ca_path).map_err(|e| anyhow!("cannot open cert file: {e}"))?;
    let key_file = File::open(&key_path).map_err(|e| anyhow!("cannot open key file: {e}"))?;

    let mut cert_byte = BufReader::new(cert_file);
    let mut key_byte = BufReader::new(key_file);
    let cert_chain: Vec<_> = rustls_pemfile::certs(&mut cert_byte)
        .map(|r| r.unwrap())
        .collect();
    let keys = rustls_pemfile::private_key(&mut key_byte).map(|k| k.unwrap())?;

    let mut conf = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, keys)
        .map_err(|e| anyhow!("TLS config error: {e}"))?;
    conf.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"http/1.0".to_vec()];
    let tls = TlsAcceptor::from(Arc::new(conf));

    let addr = format!("{}:{}", listen_address, listen_port);
    tracing::info!("Listening (TLS) on {addr}");
    let listener = TcpListener::bind(&addr).await?;

    loop {
        let serverconf_loop = server_config.clone();
        let engine_loop = engine.clone();
        let config_path_loop = config_path.clone();
        let policy_path_loop = policy_path.clone();
        let geoip_loop = geoip.clone();
        let rate_limiter_loop = rate_limiter.clone();
        let (tcp, _) = listener.accept().await?;
        let remote_addr = tcp.peer_addr().unwrap().ip();
        let tls_acceptor = tls.clone();
        tokio::task::spawn(async move {
            let stream_tls = match tls_acceptor.accept(tcp).await {
                std::result::Result::Ok(stream) => stream,
                std::result::Result::Err(err) => {
                    tracing::error!("TLS handshake failed: {err}");
                    return;
                }
            };
            let tokio_io = TokioIo::new(stream_tls);
            let admin_state = admin::AdminState {
                server_config: serverconf_loop.clone(),
                engine: engine_loop.clone(),
                config_path: config_path_loop.clone(),
                policy_path: policy_path_loop.clone(),
                geoip: geoip_loop.clone(),
                rate_limiter: rate_limiter_loop.clone(),
            };
            // auto-detect HTTP/1.1 vs HTTP/2 per connection (ALPN/preface)
            if let Err(err) = auto::Builder::new(request::TokioExecutor)
                .serve_connection(
                    tokio_io,
                    service_fn(move |req| {
                        request_handler(
                            req,
                            serverconf_loop.clone(),
                            engine_loop.clone(),
                            admin_state.clone(),
                            remote_addr,
                            geoip_loop.clone(),
                            rate_limiter_loop.clone(),
                        )
                    }),
                )
                .await
            {
                tracing::error!("connection error (TLS): {err}");
            }
        });
    }
}

async fn serve_http(
    server_config: Arc<RwLock<ServerConfig>>,
    engine: Arc<RwLock<Engine>>,
    config_path: String,
    policy_path: String,
    geoip: Arc<geoip::GeoIpService>,
    rate_limiter: Arc<ratelimit::RateLimiter>,
) -> Result<()> {
    let (listen_address, listen_port) = {
        let cfg = server_config.read().await;
        (cfg.listen_address.clone(), cfg.listen_port)
    };
    let addr = format!("{}:{}", listen_address, listen_port);
    tracing::info!("Listening on {addr}");
    let listener = TcpListener::bind(&addr).await?;

    loop {
        let serverconf_loop = server_config.clone();
        let engine_loop = engine.clone();
        let config_path_loop = config_path.clone();
        let policy_path_loop = policy_path.clone();
        let geoip_loop = geoip.clone();
        let rate_limiter_loop = rate_limiter.clone();
        let (tcp, _) = listener.accept().await?;
        let remote_addr = tcp.peer_addr().unwrap().ip();
        let io = TokioIo::new(tcp);
        let admin_state = admin::AdminState {
            server_config: serverconf_loop.clone(),
            engine: engine_loop.clone(),
            config_path: config_path_loop.clone(),
            policy_path: policy_path_loop.clone(),
            geoip: geoip_loop.clone(),
            rate_limiter: rate_limiter_loop.clone(),
        };
        tokio::task::spawn(async move {
            if let Err(err) = auto::Builder::new(request::TokioExecutor)
                .serve_connection(
                    io,
                    service_fn(move |req| {
                        request_handler(
                            req,
                            serverconf_loop.clone(),
                            engine_loop.clone(),
                            admin_state.clone(),
                            remote_addr,
                            geoip_loop.clone(),
                            rate_limiter_loop.clone(),
                        )
                    }),
                )
                .await
            {
                tracing::error!("connection error: {err}");
            }
        });
    }
}

async fn serve_admin_api(
    server_config: Arc<RwLock<ServerConfig>>,
    engine: Arc<RwLock<Engine>>,
    config_path: String,
    policy_path: String,
    geoip: Arc<geoip::GeoIpService>,
    rate_limiter: Arc<ratelimit::RateLimiter>,
) -> Result<()> {
    let (listen_address, listen_port) = {
        let cfg = server_config.read().await;
        (
            cfg.admin_api.listen_address.clone(),
            cfg.admin_api.listen_port,
        )
    };
    let addr = format!("{}:{}", listen_address, listen_port);
    tracing::info!("Admin API listening on {addr}");
    let listener = TcpListener::bind(&addr).await?;

    loop {
        let serverconf_loop = server_config.clone();
        let engine_loop = engine.clone();
        let config_path_loop = config_path.clone();
        let policy_path_loop = policy_path.clone();
        let geoip_loop = geoip.clone();
        let rate_limiter_loop = rate_limiter.clone();
        let (tcp, _) = listener.accept().await?;
        let remote_addr = tcp.peer_addr().unwrap().ip();
        let io = TokioIo::new(tcp);
        let admin_state = admin::AdminState {
            server_config: serverconf_loop.clone(),
            engine: engine_loop.clone(),
            config_path: config_path_loop,
            policy_path: policy_path_loop,
            geoip: geoip_loop.clone(),
            rate_limiter: rate_limiter_loop.clone(),
        };
        tokio::task::spawn(async move {
            if let Err(err) = auto::Builder::new(request::TokioExecutor)
                .serve_connection(
                    io,
                    service_fn(move |req| {
                        admin::handle_admin_request(
                            req,
                            RequestData {
                                uri: String::new(),
                                query: None,
                                method: hyper::Method::GET,
                                headers: hyper::HeaderMap::new(),
                                body: Bytes::new(),
                                body_bytes: 0,
                                host: String::new(),
                            },
                            admin_state.clone(),
                            remote_addr,
                        )
                    }),
                )
                .await
            {
                tracing::error!("admin connection error: {err}");
            }
        });
    }
}
