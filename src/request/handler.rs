use std::{net::IpAddr, sync::Arc, time::Instant};

use anyhow::{Ok, Result};
use http_body_util::{BodyExt, Full};
use hyper::{
    body::Bytes,
    header::{HeaderValue, HOST},
    Request, Response, StatusCode,
};
use tokio::sync::RwLock;
use tracing::Instrument;
use uuid::Uuid;
use valuable::Valuable;

use crate::{
    admin::{self, AdminState},
    config::ServerConfig,
    domain::handler::domain_handler,
    engine::Engine,
    geoip::{GeoIpInfo, GeoIpService, PolicyDecision},
    ratelimit::{Decision, RateLimiter},
    telemetry,
    virtualserver::handler::virtual_server_handler,
};

use super::RequestData;

pub async fn request_handler(
    req: Request<hyper::body::Incoming>,
    server_conf: Arc<RwLock<ServerConfig>>,
    engine: Arc<RwLock<Engine>>,
    admin_state: AdminState,
    remote_addr: IpAddr,
    geoip: Arc<GeoIpService>,
    rate_limiter: Arc<RateLimiter>,
) -> Result<Response<Full<Bytes>>> {
    let method = req.method().clone();
    let uri = req.uri().path().to_string();
    let span = tracing::info_span!(
        "http.request",
        request_id = tracing::field::Empty,
        method = %method,
        uri = %uri
    );
    request_handler_inner(
        req,
        server_conf,
        engine,
        admin_state,
        remote_addr,
        geoip,
        rate_limiter,
    )
    .instrument(span)
    .await
}

async fn request_handler_inner(
    req: Request<hyper::body::Incoming>,
    server_conf: Arc<RwLock<ServerConfig>>,
    engine: Arc<RwLock<Engine>>,
    admin_state: AdminState,
    remote_addr: IpAddr,
    geoip: Arc<GeoIpService>,
    rate_limiter: Arc<RateLimiter>,
) -> Result<Response<Full<Bytes>>> {
    let start = Instant::now();
    let uuid = Uuid::now_v7().to_string();

    // Host comes from the Host header (origin-form requests have no
    // uri.host()); fall back to the absolute-form URI host.
    let host = req
        .headers()
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .map(|h| h.split(':').next().unwrap_or(h).to_string())
        .or_else(|| req.uri().host().map(|h| h.to_string()))
        .unwrap_or_default();

    let uri = req.uri().path().to_string();
    let query = req.uri().query().map(|q| q.to_string());
    let method = req.method().clone();
    let headers = req.headers().clone();

    // ------------------------------------------------ admin / dashboard
    // Admin endpoints are routed before WAF inspection so health checks and
    // management remain reachable even when a request would be blocked.
    // They are only handled here when the admin API is enabled and sharing
    // the main listener; a separate admin listener handles them otherwise.
    let admin_on_main_listener = {
        let cfg = server_conf.read().await;
        cfg.admin_api.enabled
            && (cfg.admin_api.listen_address.is_empty() || cfg.admin_api.listen_port == 0)
    };
    if admin_on_main_listener
        && (uri.starts_with("/novaflow") || uri.starts_with("/novaflow_healthz"))
    {
        let admin_headers = headers.clone();
        let resp = admin::handle_admin_request(
            req,
            RequestData {
                uri,
                query: None,
                method: hyper::Method::GET,
                headers: hyper::HeaderMap::new(),
                body: Bytes::new(),
                body_bytes: 0,
                host: host.clone(),
            },
            admin_state,
            remote_addr,
        )
        .await;
        if let std::result::Result::Ok(ref r) = resp {
            log_access(
                &uuid,
                remote_addr,
                "ADMIN",
                "-",
                Some(String::from("")),
                &host,
                r.status(),
                0,
                false,
                &[],
                &GeoIpInfo::default(),
                None,
                &admin_headers,
                0,
            );
        }
        return resp;
    }

    // Body is only consumed for non-admin traffic.
    let max_body = engine_max_body(&engine).await;
    let (body_bytes, body) = match req.collect().await {
        std::result::Result::Ok(c) => {
            let bytes = c.to_bytes();
            let original_len = bytes.len();
            // Cap what we buffer for inspection.
            (original_len, bytes.slice(0..original_len.min(max_body)))
        }
        std::result::Result::Err(_) => (0, Bytes::new()),
    };
    let request_data = RequestData {
        uri,
        query,
        method,
        headers,
        body,
        body_bytes,
        host,
    };

    // ------------------------------------------------ GeoIP + rate limiting
    let geo = geoip.lookup(remote_addr).await;
    let server_config = server_conf.read().await;

    if server_config.geoip.enabled {
        if let PolicyDecision::Block { ref reason } = geoip.check_policy(remote_addr).await {
            tracing::info!(
                remote_addr = ?remote_addr,
                reason = reason,
                request_id = ?uuid,
                "GeoIP block"
            );
            let forbidden = super::forbidden_page(&*server_config, &uuid);
            let resp = Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Full::new(Bytes::from(forbidden)))
                .unwrap();
            log_access(
                &uuid,
                remote_addr,
                request_data.method.as_str(),
                &request_data.uri,
                request_data.query,
                &request_data.host,
                resp.status(),
                0,
                true,
                &[RuleHit {
                    policy_id: 0,
                    rule_name: reason.as_str(),
                }],
                &geo,
                None,
                &request_data.headers,
                request_data.body_bytes,
            );
            telemetry::record_http_request(
                start.elapsed(),
                request_data.method.as_str(),
                resp.status().as_u16(),
                "blocked",
            );
            return Ok(resp);
        }
    }

    // ------------------------------------------------ WAF inspection
    let waf_start = Instant::now();
    let engine = engine.read().await;
    let verdict = {
        // Synchronous block: no .await while the span guard is alive so the
        // future stays Send.
        let _waf_span = tracing::info_span!("waf.inspect").entered();
        engine.inspect(&request_data)
    };
    drop(engine);
    telemetry::record_waf_inspection(waf_start.elapsed(), verdict.should_block);

    let rules_fired: Vec<RuleHit<'_>> = verdict
        .detections
        .iter()
        .map(|d| RuleHit {
            policy_id: d.policy_id,
            rule_name: d.rule.as_str(),
        })
        .collect();
    let (first_policy_id, first_rule_name) = rules_fired
        .first()
        .map(|r| (r.policy_id, r.rule_name))
        .unwrap_or((0, ""));

    // Rate limiting runs after WAF so the anomaly score is available.
    let rate_limit_decision = if server_config.rate_limit.enabled {
        rate_limiter
            .check(remote_addr, &request_data, verdict.score, &geo)
            .await
    } else {
        Decision::Allow
    };

    if let Decision::Block {
        ref rule,
        ref reason,
    } = rate_limit_decision
    {
        tracing::info!(
            remote_addr = ?remote_addr,
            rate_limit_rule = rule,
            reason = reason,
            request_id = ?uuid,
            "Rate limit block"
        );
        let forbidden = super::forbidden_page(&*server_config, &uuid);
        let resp = Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Full::new(Bytes::from(forbidden)))
            .unwrap();
        log_access(
            &uuid,
            remote_addr,
            request_data.method.as_str(),
            &request_data.uri,
            request_data.query,
            &request_data.host,
            resp.status(),
            verdict.score,
            true,
            &rules_fired,
            &geo,
            Some(rule),
            &request_data.headers,
            request_data.body_bytes,
        );
        telemetry::record_http_request(
            start.elapsed(),
            request_data.method.as_str(),
            resp.status().as_u16(),
            "blocked",
        );
        return Ok(resp);
    }

    if let Decision::Alert {
        ref rule,
        ref reason,
    } = rate_limit_decision
    {
        tracing::info!(
            remote_addr = ?remote_addr,
            rate_limit_rule = rule,
            reason = reason,
            request_id = ?uuid,
            "Rate limit alert"
        );
    }

    if verdict.should_block {
        tracing::info!(
            remote_addr = ?remote_addr,
            anomaly_score = verdict.score,
            policy_id = first_policy_id,
            rule_name = first_rule_name,
            rules = rules_fired.as_value(),
            rule_count = rules_fired.len(),
            uri = ?request_data.uri,
            method = ?request_data.method,
            request_id = ?uuid,
            request_size = request_data.body_bytes,
            "Blocked request"
        );
        let forbidden = super::forbidden_page(&*server_config, &uuid);
        let resp = Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Full::new(Bytes::from(forbidden)))
            .unwrap();
        log_access(
            &uuid,
            remote_addr,
            request_data.method.as_str(),
            &request_data.uri,
            request_data.query,
            &request_data.host,
            resp.status(),
            verdict.score,
            true,
            &rules_fired,
            &geo,
            None,
            &request_data.headers,
            request_data.body_bytes,
        );
        telemetry::record_http_request(
            start.elapsed(),
            request_data.method.as_str(),
            resp.status().as_u16(),
            "blocked",
        );
        return Ok(resp);
    }

    if verdict.score > 0 {
        // detect mode: log-only
        tracing::info!(
            remote_addr = ?remote_addr,
            anomaly_score = verdict.score,
            policy_id = first_policy_id,
            rule_name = first_rule_name,
            rules = rules_fired.as_value(),
            rule_count = rules_fired.len(),
            uri = ?request_data.uri,
            method = ?request_data.method,
            request_id = ?uuid,
            request_size = request_data.body_bytes,
            "Detection (monitor mode, request allowed)"
        );
    }

    // ------------------------------------------------ routing
    // Client IP seen by upstreams: honor nothing — we append the direct
    // peer address to X-Forwarded-For ourselves.
    let response = if server_config.domain_server.enabled {
        if let std::result::Result::Ok(resp) = domain_handler(
            server_config.domain_server.config.clone(),
            &request_data,
            remote_addr,
            &uuid,
            &*server_config,
        )
        .await
        {
            resp
        } else if server_config.virtual_server.enabled {
            virtual_server_handler(
                server_config.virtual_server.config.clone(),
                request_data.clone(),
                remote_addr,
                uuid.clone(),
                &*server_config,
            )
            .await?
        } else {
            not_found_response(&*server_config)
        }
    } else if server_config.virtual_server.enabled {
        virtual_server_handler(
            server_config.virtual_server.config.clone(),
            request_data.clone(),
            remote_addr,
            uuid.clone(),
            &*server_config,
        )
        .await?
    } else {
        not_found_response(&*server_config)
    };

    log_access(
        &uuid,
        remote_addr,
        request_data.method.as_str(),
        &request_data.uri,
        request_data.query,
        &request_data.host,
        response.status(),
        verdict.score,
        false,
        &rules_fired,
        &geo,
        rate_limit_decision.rule_name(),
        &request_data.headers,
        request_data.body_bytes,
    );
    let action = if verdict.score > 0 {
        "detected"
    } else {
        "allowed"
    };
    telemetry::record_http_request(
        start.elapsed(),
        request_data.method.as_str(),
        response.status().as_u16(),
        action,
    );
    Ok(response)
}

fn not_found_response(config: &ServerConfig) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Full::new(Bytes::from(super::not_found_page(config))))
        .unwrap()
}

#[derive(Debug, serde::Serialize, valuable::Valuable)]
struct RuleHit<'a> {
    policy_id: i32,
    rule_name: &'a str,
}

fn log_access(
    request_id: &str,
    remote_addr: IpAddr,
    method: &str,
    uri: &str,
    query: Option<String>,
    host: &str,
    status: StatusCode,
    anomaly_score: u32,
    blocked: bool,
    rules: &[RuleHit<'_>],
    geo: &GeoIpInfo,
    rate_limit_rule: Option<&str>,
    headers: &hyper::HeaderMap,
    request_size: usize,
) {
    let action = if blocked {
        "blocked"
    } else if anomaly_score > 0 {
        "detected"
    } else {
        "allowed"
    };

    let user_agent = header_value(headers, "user-agent");
    let selected_headers = selected_headers_map(headers);
    let rules_value = rules.as_value();

    tracing::info!(
        request_id = request_id,
        remote_addr = %remote_addr,
        method = method,
        uri = uri,
        host = host,
        query = query,
        status = status.as_u16(),
        anomaly_score = anomaly_score,
        action = action,
        rules = rules_value,
        rule_count = rules.len(),
        request_size = request_size,
        user_agent = user_agent.as_deref(),
        headers = ?selected_headers,
        country_code = geo.country_code.as_deref(),
        country_name = geo.country_name.as_deref(),
        city = geo.city.as_deref(),
        asn = geo.asn,
        asn_organization = geo.asn_organization.as_deref(),
        rate_limit_rule = rate_limit_rule,
        "access"
    );
}

fn header_value(headers: &hyper::HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

/// Return a small, non-sensitive subset of request headers for logging.
/// Cookies and Authorization are intentionally omitted.
fn selected_headers_map(headers: &hyper::HeaderMap) -> std::collections::HashMap<String, String> {
    const LOGGED: &[&str] = &[
        "user-agent",
        "accept",
        "accept-language",
        "accept-encoding",
        "referer",
        "content-type",
        "x-forwarded-for",
        "x-requested-with",
    ];
    let mut map = std::collections::HashMap::new();
    for name in LOGGED {
        if let Some(value) = header_value(headers, name) {
            map.insert(name.to_string(), value);
        }
    }
    map
}

async fn engine_max_body(engine: &Arc<RwLock<Engine>>) -> usize {
    engine.read().await.max_body_bytes()
}

/// Append the direct peer to X-Forwarded-For (or create it).
pub fn forwarded_headers(headers: &hyper::HeaderMap, remote_addr: IpAddr) -> hyper::HeaderMap {
    let mut out = headers.clone();
    let prior = out
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let value = match prior {
        Some(p) if !p.is_empty() => format!("{p}, {remote_addr}"),
        _ => remote_addr.to_string(),
    };
    if let std::result::Result::Ok(v) = HeaderValue::from_str(&value) {
        out.insert("x-forwarded-for", v);
    }
    out
}

/// Strip hop-by-hop headers before proxying (RFC 7230 §6.1) — the old
/// code forwarded them blindly, which breaks keep-alive upstreams.
pub fn strip_hop_by_hop(headers: hyper::HeaderMap) -> hyper::HeaderMap {
    const HOP: &[&str] = &[
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "content-length",
        "host",
    ];
    let mut out = hyper::HeaderMap::new();
    for (name, value) in headers.iter() {
        if !HOP.iter().any(|h| name.as_str().eq_ignore_ascii_case(h)) {
            out.append(name.clone(), value.clone());
        }
    }
    out
}
