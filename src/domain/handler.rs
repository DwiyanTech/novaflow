use std::{net::IpAddr, time::Instant};

use anyhow::{anyhow, Result};
use http_body_util::Full;
use hyper::{body::Bytes, Response, StatusCode};
use tracing::Instrument;

use crate::{
    config::{DomainServer, ServerConfig},
    proxy,
    request::handler::{forwarded_headers, strip_hop_by_hop},
    request::{bad_gateway_page, RequestData},
    response::convert::convert_reqwest_to_hyper_response,
    telemetry,
};

/// Route by the request's Host header (domain-based mode).
///
/// Matching is case-insensitive and supports leading-dot wildcard entries
/// (`domain_name: .example.com` matches `www.example.com`). Returns Err
/// when no domain matches so the caller can fall back to virtual servers.
pub async fn domain_handler(
    domain_conf: Vec<DomainServer>,
    request_data: &RequestData,
    source_ip: IpAddr,
    uuid: &str,
    server_config: &ServerConfig,
) -> Result<Response<Full<Bytes>>> {
    let host = request_data.host.to_lowercase();

    let matched = domain_conf.iter().find(|d| {
        let want = d.domain_name.to_lowercase();
        if let Some(suffix) = want.strip_prefix('.') {
            host == suffix || host.ends_with(&format!(".{suffix}")) || host.ends_with(&want)
        } else {
            host == want
        }
    });

    let Some(domain) = matched else {
        return Err(anyhow!("no domain matched"));
    };

    let base = domain.remote_address.trim_end_matches('/');
    let path = if request_data.uri.starts_with('/') {
        request_data.uri.clone()
    } else {
        format!("/{}", request_data.uri)
    };
    let upstream_url = match &request_data.query {
        Some(q) if !q.is_empty() => format!("{base}{path}?{q}"),
        _ => format!("{base}{path}"),
    };

    let headers = forwarded_headers(&strip_hop_by_hop(request_data.headers.clone()), source_ip);

    let upstream_start = Instant::now();
    let resp = async {
        proxy::client()
            .request(request_data.method.clone(), upstream_url)
            .headers(headers)
            .body(request_data.body.clone())
            .send()
            .await
    }
    .instrument(tracing::info_span!("upstream.request", upstream = %domain.name))
    .await;

    match resp {
        std::result::Result::Ok(resp) => {
            let upstream_status = resp.status().as_u16();
            match convert_reqwest_to_hyper_response(resp).await {
                std::result::Result::Ok(hyper_resp) => {
                    telemetry::record_upstream(
                        upstream_start.elapsed(),
                        &domain.name,
                        Some(upstream_status),
                    );
                    let status: StatusCode = hyper_resp.status();
                    tracing::trace!(
                        remote_addr = ?source_ip,
                        uri = ?request_data.uri,
                        method = ?request_data.method,
                        request_id = ?uuid,
                        domain = ?domain.name,
                        response_code = ?status,
                        "Accepted request"
                    );
                    Ok(hyper_resp)
                }
                std::result::Result::Err(err) => {
                    telemetry::record_upstream(
                        upstream_start.elapsed(),
                        &domain.name,
                        Some(upstream_status),
                    );
                    tracing::warn!(
                        remote_addr = ?source_ip,
                        uri = ?request_data.uri,
                        request_id = ?uuid,
                        domain = ?domain.name,
                        error = %err,
                        "upstream response conversion failed"
                    );
                    let bad_gw = bad_gateway_page(server_config, uuid);
                    Ok(Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .body(Full::new(Bytes::from(bad_gw)))
                        .unwrap())
                }
            }
        }
        std::result::Result::Err(err) => {
            telemetry::record_upstream(upstream_start.elapsed(), &domain.name, None);
            tracing::warn!(
                remote_addr = ?source_ip,
                uri = ?request_data.uri,
                request_id = ?uuid,
                domain = ?domain.name,
                error = %err,
                "upstream request failed"
            );
            let bad_gw = bad_gateway_page(server_config, uuid);
            Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from(bad_gw)))
                .unwrap())
        }
    }
}
