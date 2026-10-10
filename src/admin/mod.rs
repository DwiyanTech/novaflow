//! NovaFlow admin API and dashboard static-file serving.
//!
//! All endpoints live under `/novaflow/` and are intentionally routed
//! **before** the WAF inspection so health checks and management UI remain
//! reachable even when traffic would otherwise be blocked.

pub mod health;

use std::{net::IpAddr, path::Path, sync::Arc};

use anyhow::Result;
use http_body_util::{BodyExt, Full};
use hyper::{
    body::Bytes,
    header::{self, HeaderValue},
    Request, Response, StatusCode,
};
use tokio::sync::RwLock;

use crate::{
    config::{PolicyConfig, ServerConfig},
    engine::Engine,
    geoip::GeoIpService,
    ratelimit::RateLimiter,
    request::RequestData,
};

/// Maximum certificate/key upload size (1 MiB).
const MAX_UPLOAD_SIZE: usize = 1024 * 1024;

/// Audit-log an admin API action.
///
/// Emits a structured `admin_audit` event for every state-mutating operation
/// (config reload, policy reload, backend edits, rule edits).  Read-only
/// health / geoip / block-list endpoints are not audit-logged.
fn audit_log(
    action: &str,
    remote_addr: IpAddr,
    path: &str,
    method: &str,
    status: StatusCode,
    detail: Option<&str>,
) {
    tracing::info!(
        event = "admin_audit",
        action = action,
        remote_addr = %remote_addr,
        path = path,
        method = method,
        status = status.as_u16(),
        detail = detail,
        "admin action"
    );
}

/// Shared admin state handed to every admin request.
#[derive(Clone)]
pub struct AdminState {
    pub server_config: Arc<RwLock<crate::config::ServerConfig>>,
    pub engine: Arc<RwLock<Engine>>,
    pub config_path: String,
    pub policy_path: String,
    pub geoip: Arc<GeoIpService>,
    pub rate_limiter: Arc<RateLimiter>,
}

/// CORS preflight / actual response helpers.
fn cors_headers() -> hyper::HeaderMap {
    let mut h = hyper::HeaderMap::new();
    h.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    h.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET, POST, PUT, DELETE, OPTIONS"),
    );
    h.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("content-type, authorization"),
    );
    h
}

fn json_response<T: serde::Serialize>(
    status: StatusCode,
    body: &T,
) -> Result<Response<Full<Bytes>>> {
    let bytes = serde_json::to_vec(body)?;
    Ok(Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(bytes)))?)
}

fn text_response(status: StatusCode, text: &str) -> Result<Response<Full<Bytes>>> {
    Ok(Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from(text.to_string())))?)
}

fn with_cors(mut resp: Response<Full<Bytes>>) -> Response<Full<Bytes>> {
    for (k, v) in cors_headers().iter() {
        resp.headers_mut().insert(k, v.clone());
    }
    resp
}

/// Check bearer token when one is configured. Returns `None` if the request
/// may proceed, otherwise an unauthorized response.
async fn check_auth(
    req: &Request<hyper::body::Incoming>,
    state: &AdminState,
) -> Option<Result<Response<Full<Bytes>>>> {
    let token = state
        .server_config
        .read()
        .await
        .admin_api_token
        .trim()
        .to_string();
    if token.is_empty() {
        return None;
    }

    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let expected = format!("Bearer {token}");
    if !constant_time_eq::constant_time_eq(auth_header.as_bytes(), expected.as_bytes()) {
        let body = serde_json::json!({ "error": "unauthorized" });
        let resp = match json_response(StatusCode::UNAUTHORIZED, &body) {
            Ok(r) => Ok(with_cors(r)),
            Err(e) => Err(e),
        };
        return Some(resp);
    }

    None
}

/// Entry point for `/novaflow/` requests.
pub async fn handle_admin_request(
    req: Request<hyper::body::Incoming>,
    _request_data: RequestData,
    state: AdminState,
    remote_addr: IpAddr,
) -> Result<Response<Full<Bytes>>> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    // Handle CORS preflight up front.
    if method == hyper::Method::OPTIONS {
        return Ok(with_cors(Response::new(Full::new(Bytes::new()))));
    }

    // Backward-compatible simple health endpoint.
    if path == "/novaflow_healthz" {
        let body = serde_json::json!({ "status": "ok" });
        return Ok(with_cors(json_response(StatusCode::OK, &body)?));
    }

    // All other admin API endpoints require the bearer token when configured.
    if let Some(resp) = check_auth(&req, &state).await {
        return resp;
    }

    match path.as_str() {
        "/novaflow/api/health" => health_handler(state).await,
        "/novaflow/api/config" => match method {
            hyper::Method::GET => config_handler(state).await,
            hyper::Method::POST => config_post_handler(req, state, remote_addr).await,
            _ => Ok(with_cors(text_response(
                StatusCode::METHOD_NOT_ALLOWED,
                "method not allowed",
            )?)),
        },
        "/novaflow/api/ssl-cert" => match method {
            hyper::Method::POST => ssl_cert_upload_handler(req, state, remote_addr).await,
            _ => Ok(with_cors(text_response(
                StatusCode::METHOD_NOT_ALLOWED,
                "method not allowed",
            )?)),
        },
        "/novaflow/api/policy" => match method {
            hyper::Method::GET => policy_get_handler(state).await,
            hyper::Method::POST => policy_post_handler(req, state, remote_addr).await,
            _ => Ok(with_cors(text_response(
                StatusCode::METHOD_NOT_ALLOWED,
                "method not allowed",
            )?)),
        },
        path if path.starts_with("/novaflow/api/geoip/") => {
            geoip_handler(
                path.strip_prefix("/novaflow/api/geoip/").unwrap_or(""),
                state,
            )
            .await
        }
        "/novaflow/api/ratelimit/blocks" => ratelimit_blocks_handler(state).await,
        _ => Ok(with_cors(text_response(
            StatusCode::NOT_FOUND,
            "novaflow admin endpoint not found",
        )?)),
    }
}

async fn geoip_handler(ip_str: &str, state: AdminState) -> Result<Response<Full<Bytes>>> {
    let ip: IpAddr = match ip_str.parse() {
        Ok(ip) => ip,
        Err(_) => {
            let body = serde_json::json!({ "error": "invalid IP address" });
            return Ok(with_cors(json_response(StatusCode::BAD_REQUEST, &body)?));
        }
    };

    let info = state.geoip.lookup(ip).await;
    Ok(with_cors(json_response(StatusCode::OK, &info)?))
}

async fn ratelimit_blocks_handler(state: AdminState) -> Result<Response<Full<Bytes>>> {
    match state.rate_limiter.blocked_entries().await {
        Ok(entries) => {
            let body = serde_json::json!({ "blocks": entries });
            Ok(with_cors(json_response(StatusCode::OK, &body)?))
        }
        Err(e) => {
            let body = serde_json::json!({ "error": format!("failed to list blocks: {e}") });
            Ok(with_cors(json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &body,
            )?))
        }
    }
}

async fn health_handler(state: AdminState) -> Result<Response<Full<Bytes>>> {
    let engine = state.engine.read().await;
    let server_config = state.server_config.read().await;
    let (vs_results, ds_results) = health::probe_all(
        &server_config.virtual_server.config,
        &server_config.domain_server.config,
    )
    .await;

    let any_error = vs_results
        .iter()
        .chain(ds_results.iter())
        .any(|r| r.status != "ok");
    let overall = if any_error { "degraded" } else { "healthy" };

    let body = serde_json::json!({
        "status": overall,
        "timestamp": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        "engine": {
            "status": "ok",
            "mode": format!("{:?}", engine.mode()).to_lowercase(),
            "anomaly_threshold": engine.policy().detection.anomaly_threshold,
            "max_body_bytes": engine.max_body_bytes(),
        },
        "virtual_servers": vs_results,
        "domain_servers": ds_results,
    });

    Ok(with_cors(json_response(StatusCode::OK, &body)?))
}

async fn config_handler(state: AdminState) -> Result<Response<Full<Bytes>>> {
    let server_config = state.server_config.read().await;
    Ok(with_cors(json_response(StatusCode::OK, &*server_config)?))
}

async fn config_post_handler(
    req: Request<hyper::body::Incoming>,
    state: AdminState,
    remote_addr: IpAddr,
) -> Result<Response<Full<Bytes>>> {
    let path = req.uri().path().to_string();
    let method = req.method().to_string();
    let collected = req.collect().await?;
    let bytes = collected.to_bytes();
    let yaml = String::from_utf8_lossy(&bytes);

    // 1. Parse YAML as a generic value so we can manipulate sections, then
    //    validate it as a ServerConfig.
    let mut value: serde_yaml::Value = match serde_yaml::from_str(&yaml) {
        Ok(v) => v,
        Err(e) => {
            let body = serde_json::json!({ "error": format!("invalid config yaml: {e}") });
            let resp = with_cors(json_response(StatusCode::BAD_REQUEST, &body)?);
            audit_log(
                "config_update_failed",
                remote_addr,
                &path,
                &method,
                resp.status(),
                Some(&format!("invalid config yaml: {e}")),
            );
            return Ok(resp);
        }
    };

    let config: ServerConfig = match serde_yaml::from_value(value.clone()) {
        Ok(c) => c,
        Err(e) => {
            let body = serde_json::json!({ "error": format!("invalid config yaml: {e}") });
            let resp = with_cors(json_response(StatusCode::BAD_REQUEST, &body)?);
            audit_log(
                "config_update_failed",
                remote_addr,
                &path,
                &method,
                resp.status(),
                Some(&format!("invalid config yaml: {e}")),
            );
            return Ok(resp);
        }
    };

    // 2. If split config paths are configured, write geoip / rate_limit to
    //    their own files and remove them from the main config value.
    let config_dir = Path::new(&state.config_path)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| Path::new(".").to_path_buf());

    if let Some(geoip_path) = config.geoip_config_path.as_deref() {
        if let Some(geoip_value) = value.get_mut("geoip").and_then(|v| v.as_mapping_mut()) {
            let geoip_yaml = match serde_yaml::to_string(&serde_yaml::Value::Mapping(
                geoip_value.clone(),
            )) {
                Ok(y) => y,
                Err(e) => {
                    let body =
                        serde_json::json!({ "error": format!("failed to serialize geoip: {e}") });
                    return Ok(with_cors(json_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &body,
                    )?));
                }
            };
            let resolved = config_dir.join(geoip_path);
            if let Some(parent) = resolved.parent() {
                if let Err(e) = tokio::fs::create_dir_all(parent).await {
                    let body =
                        serde_json::json!({ "error": format!("failed to create geoip dir: {e}") });
                    return Ok(with_cors(json_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &body,
                    )?));
                }
            }
            if let Err(e) = tokio::fs::write(&resolved, geoip_yaml).await {
                let body =
                    serde_json::json!({ "error": format!("failed to write geoip config: {e}") });
                return Ok(with_cors(json_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &body,
                )?));
            }
        }
        if let Some(map) = value.as_mapping_mut() {
            map.remove(&serde_yaml::Value::String("geoip".to_string()));
        }
    }

    if let Some(rate_limit_path) = config.rate_limit_config_path.as_deref() {
        if let Some(rl_value) = value.get_mut("rate_limit").and_then(|v| v.as_mapping_mut()) {
            let rl_yaml = match serde_yaml::to_string(&serde_yaml::Value::Mapping(rl_value.clone()))
            {
                Ok(y) => y,
                Err(e) => {
                    let body = serde_json::json!({ "error": format!("failed to serialize rate_limit: {e}") });
                    return Ok(with_cors(json_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &body,
                    )?));
                }
            };
            let resolved = config_dir.join(rate_limit_path);
            if let Some(parent) = resolved.parent() {
                if let Err(e) = tokio::fs::create_dir_all(parent).await {
                    let body = serde_json::json!({ "error": format!("failed to create rate_limit dir: {e}") });
                    return Ok(with_cors(json_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &body,
                    )?));
                }
            }
            if let Err(e) = tokio::fs::write(&resolved, rl_yaml).await {
                let body = serde_json::json!({ "error": format!("failed to write rate_limit config: {e}") });
                return Ok(with_cors(json_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &body,
                )?));
            }
        }
        if let Some(map) = value.as_mapping_mut() {
            map.remove(&serde_yaml::Value::String("rate_limit".to_string()));
        }
    }

    // 3. Persist the main config (without split sections) to disk.
    let main_yaml = match serde_yaml::to_string(&value) {
        Ok(y) => y,
        Err(e) => {
            let body = serde_json::json!({ "error": format!("failed to serialize config: {e}") });
            return Ok(with_cors(json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &body,
            )?));
        }
    };

    if let Err(e) = tokio::fs::write(&state.config_path, main_yaml).await {
        let body = serde_json::json!({ "error": format!("failed to write config: {e}") });
        let resp = with_cors(json_response(StatusCode::INTERNAL_SERVER_ERROR, &body)?);
        audit_log(
            "config_update_failed",
            remote_addr,
            &path,
            &method,
            resp.status(),
            Some(&format!("failed to write config: {e}")),
        );
        return Ok(resp);
    }

    // 4. Hot-reload the in-memory config so proxy changes take effect immediately.
    {
        let mut server_config = state.server_config.write().await;
        *server_config = config.clone();
    }

    // Listener address/port changes still require a process restart.
    let restart_required = false;

    let body = serde_json::json!({
        "status": "saved",
        "restart_required": restart_required,
        "config": config,
    });
    let resp = with_cors(json_response(StatusCode::OK, &body)?);
    audit_log(
        "config_updated",
        remote_addr,
        &path,
        &method,
        resp.status(),
        Some(&format!(
            "virtual_servers={}, domain_servers={}",
            config.virtual_server.config.len(),
            config.domain_server.config.len()
        )),
    );
    Ok(resp)
}

async fn ssl_cert_upload_handler(
    req: Request<hyper::body::Incoming>,
    state: AdminState,
    remote_addr: IpAddr,
) -> Result<Response<Full<Bytes>>> {
    let path = req.uri().path().to_string();
    let method = req.method().to_string();

    let content_type = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let boundary = match multer::parse_boundary(content_type) {
        Ok(b) => b,
        Err(e) => {
            let body = serde_json::json!({ "error": format!("invalid content type: {e}") });
            return Ok(with_cors(json_response(StatusCode::BAD_REQUEST, &body)?));
        }
    };

    let collected = req.collect().await?;
    let bytes = collected.to_bytes();
    if bytes.len() > MAX_UPLOAD_SIZE {
        let body = serde_json::json!({ "error": "upload too large" });
        return Ok(with_cors(json_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            &body,
        )?));
    }

    let stream = futures::stream::once(async move { Ok::<_, multer::Error>(bytes) });
    let mut multipart = multer::Multipart::new(stream, boundary);

    let mut cert_bytes: Option<Bytes> = None;
    let mut key_bytes: Option<Bytes> = None;

    while let Some(field) = multipart.next_field().await? {
        let name = field.name().unwrap_or("").to_string();
        let data = field.bytes().await?;
        match name.as_str() {
            "cert" => cert_bytes = Some(data),
            "key" => key_bytes = Some(data),
            _ => {}
        }
    }

    let cert_bytes = match cert_bytes {
        Some(b) => b,
        None => {
            let body = serde_json::json!({ "error": "missing cert field" });
            return Ok(with_cors(json_response(StatusCode::BAD_REQUEST, &body)?));
        }
    };
    let key_bytes = match key_bytes {
        Some(b) => b,
        None => {
            let body = serde_json::json!({ "error": "missing key field" });
            return Ok(with_cors(json_response(StatusCode::BAD_REQUEST, &body)?));
        }
    };

    let cert_text = String::from_utf8_lossy(&cert_bytes);
    let key_text = String::from_utf8_lossy(&key_bytes);

    if !cert_text.contains("-----BEGIN CERTIFICATE-----") {
        let body = serde_json::json!({ "error": "cert does not look like a PEM certificate" });
        return Ok(with_cors(json_response(StatusCode::BAD_REQUEST, &body)?));
    }
    if !key_text.contains("-----BEGIN") && !key_text.contains("-----END") {
        let body = serde_json::json!({ "error": "key does not look like a PEM private key" });
        return Ok(with_cors(json_response(StatusCode::BAD_REQUEST, &body)?));
    }

    let config_dir = Path::new(&state.config_path)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| Path::new(".").to_path_buf());

    let upload_id = format!(
        "{}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        uuid::Uuid::now_v7()
    );
    let cert_dir = config_dir.join("certs").join(&upload_id);
    tokio::fs::create_dir_all(&cert_dir).await?;

    let cert_path = cert_dir.join("cert.pem");
    let key_path = cert_dir.join("key.pem");

    tokio::fs::write(&cert_path, &cert_bytes).await?;
    tokio::fs::write(&key_path, &key_bytes).await?;

    let body = serde_json::json!({
        "ca_path": cert_path.to_string_lossy(),
        "key_path": key_path.to_string_lossy(),
    });
    let resp = with_cors(json_response(StatusCode::OK, &body)?);
    audit_log(
        "ssl_cert_uploaded",
        remote_addr,
        &path,
        &method,
        resp.status(),
        Some(&format!("ca_path={}", cert_path.to_string_lossy())),
    );
    Ok(resp)
}

async fn policy_get_handler(state: AdminState) -> Result<Response<Full<Bytes>>> {
    let engine = state.engine.read().await;
    Ok(with_cors(json_response(StatusCode::OK, engine.policy())?))
}

async fn policy_post_handler(
    req: Request<hyper::body::Incoming>,
    state: AdminState,
    remote_addr: IpAddr,
) -> Result<Response<Full<Bytes>>> {
    let path = req.uri().path().to_string();
    let method = req.method().to_string();
    let collected = req.collect().await?;
    let bytes = collected.to_bytes();
    let yaml = String::from_utf8_lossy(&bytes);

    // 1. Parse YAML.
    let policy: PolicyConfig = match serde_yaml::from_str(&yaml) {
        Ok(p) => p,
        Err(e) => {
            let body = serde_json::json!({ "error": format!("invalid policy yaml: {e}") });
            let resp = with_cors(json_response(StatusCode::BAD_REQUEST, &body)?);
            audit_log(
                "policy_update_failed",
                remote_addr,
                &path,
                &method,
                resp.status(),
                Some(&format!("invalid policy yaml: {e}")),
            );
            return Ok(resp);
        }
    };

    // 2. Validate regexes by building a new engine.
    let new_engine = match Engine::new(policy.clone()) {
        Ok(e) => e,
        Err(e) => {
            let body = serde_json::json!({ "error": e });
            let resp = with_cors(json_response(StatusCode::BAD_REQUEST, &body)?);
            audit_log(
                "policy_update_failed",
                remote_addr,
                &path,
                &method,
                resp.status(),
                Some(&e),
            );
            return Ok(resp);
        }
    };

    // 3. Persist to disk.
    if let Err(e) = tokio::fs::write(&state.policy_path, yaml.as_ref()).await {
        let body = serde_json::json!({ "error": format!("failed to write policy: {e}") });
        let resp = with_cors(json_response(StatusCode::INTERNAL_SERVER_ERROR, &body)?);
        audit_log(
            "policy_update_failed",
            remote_addr,
            &path,
            &method,
            resp.status(),
            Some(&format!("failed to write policy: {e}")),
        );
        return Ok(resp);
    }

    // 4. Swap the active engine.
    {
        let mut engine = state.engine.write().await;
        *engine = new_engine;
    }

    let body = serde_json::json!({
        "status": "reloaded",
        "policy": policy,
    });
    let resp = with_cors(json_response(StatusCode::OK, &body)?);
    audit_log(
        "policy_updated",
        remote_addr,
        &path,
        &method,
        resp.status(),
        Some(&format!(
            "mode={:?}, threshold={}, custom_rules={}",
            policy.detection.mode,
            policy.detection.anomaly_threshold,
            policy.custom_rules.len()
        )),
    );
    Ok(resp)
}
