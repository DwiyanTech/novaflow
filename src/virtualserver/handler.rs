use std::{net::IpAddr, time::Instant};

use anyhow::Result;
use http_body_util::Full;
use hyper::{body::Bytes, Response, StatusCode};
use tracing::Instrument;

use crate::{
    config::{ServerConfig, VirtualServer},
    proxy,
    request::handler::{forwarded_headers, strip_hop_by_hop},
    request::{bad_gateway_page, not_found_page, RequestData},
    response::convert::convert_reqwest_to_hyper_response,
    telemetry,
};

/// Route by longest path prefix (virtual-server based mode).
///
/// The old implementation used `.find()` on the config order and rebuilt
/// the upstream URL with a regex — now it's an exact longest-prefix match
/// plus plain string slicing.
pub async fn virtual_server_handler(
    vs_conf: Vec<VirtualServer>,
    request_data: RequestData,
    remote_addr: IpAddr,
    uuid: String,
    server_config: &ServerConfig,
) -> Result<Response<Full<Bytes>>> {
    let matched = vs_conf
        .iter()
        .filter(|vs| {
            let prefix = vs.path.trim_end_matches('/');
            request_data.uri == prefix
                || request_data
                    .uri
                    .strip_prefix(prefix)
                    .is_some_and(|rest| rest.starts_with('/'))
        })
        .max_by_key(|vs| vs.path.len());

    let Some(vs) = matched else {
        tracing::trace!(
            remote_addr = ?remote_addr,
            uri = ?request_data.uri,
            method = ?request_data.method,
            request_id = ?uuid,
            response_code = ?StatusCode::NOT_FOUND,
            "Not Found"
        );
        return Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from(not_found_page(server_config))))
            .unwrap());
    };

    let prefix = vs.path.trim_end_matches('/');
    let remainder = request_data.uri.strip_prefix(prefix).unwrap_or("");
    let base = vs.remote_address.trim_end_matches('/');
    let upstream_url = match &request_data.query {
        Some(q) if !q.is_empty() => format!("{base}{remainder}?{q}"),
        _ => format!("{base}{remainder}"),
    };

    let headers = forwarded_headers(&strip_hop_by_hop(request_data.headers.clone()), remote_addr);

    let upstream_start = Instant::now();
    let resp = async {
        proxy::client()
            .request(request_data.method.clone(), upstream_url)
            .headers(headers)
            .body(request_data.body.clone())
            .send()
            .await
    }
    .instrument(tracing::info_span!("upstream.request", upstream = %vs.name))
    .await;

    match resp {
        std::result::Result::Ok(resp) => {
            let upstream_status = resp.status().as_u16();
            match convert_reqwest_to_hyper_response(resp).await {
                std::result::Result::Ok(hyper_resp) => {
                    telemetry::record_upstream(
                        upstream_start.elapsed(),
                        &vs.name,
                        Some(upstream_status),
                    );
                    let status: StatusCode = hyper_resp.status();
                    tracing::trace!(
                        remote_addr = ?remote_addr,
                        uri = ?request_data.uri,
                        method = ?request_data.method,
                        request_id = ?uuid,
                        vs = ?vs.name,
                        response_code = ?status,
                        "Accepted request"
                    );
                    Ok(hyper_resp)
                }
                std::result::Result::Err(err) => {
                    telemetry::record_upstream(
                        upstream_start.elapsed(),
                        &vs.name,
                        Some(upstream_status),
                    );
                    tracing::warn!(
                        remote_addr = ?remote_addr,
                        uri = ?request_data.uri,
                        request_id = ?uuid,
                        error = %err,
                        "upstream response conversion failed"
                    );
                    let bad_gw = bad_gateway_page(server_config, &uuid);
                    Ok(Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .body(Full::new(Bytes::from(bad_gw)))
                        .unwrap())
                }
            }
        }
        std::result::Result::Err(err) => {
            telemetry::record_upstream(upstream_start.elapsed(), &vs.name, None);
            tracing::warn!(
                remote_addr = ?remote_addr,
                uri = ?request_data.uri,
                request_id = ?uuid,
                error = %err,
                "upstream request failed"
            );
            let bad_gw = bad_gateway_page(server_config, &uuid);
            Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from(bad_gw)))
                .unwrap())
        }
    }
}
