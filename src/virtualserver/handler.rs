use std::net::IpAddr;

use http_body_util:: Full;
use hyper::{
    body::Bytes,
    Error,  Response, StatusCode,
};


use anyhow::Result;
use regex::Regex;
use reqwest::Client;
use crate::{config::VirtualServer, request::{RequestData, BAD_GATEWAY, NOT_FOUND}, response::convert::convert_reqwest_to_hyper_response};


pub async fn virtual_server_handler(
    vs_conf: Vec<VirtualServer>,
    request_data: RequestData,
    remote_addr: IpAddr,
    uuid: String,
) -> Result<Response<Full<Bytes>>> {
    if let Some(vs) = vs_conf.iter().find(|vs| request_data.uri.starts_with(&vs.path)) {
        let pattern_uri = format!("^{}", vs.path.as_str());
        let regex_uri_vs = Regex::new(&pattern_uri).unwrap();
        let format_full_uri = format!(
            "{}{}",
            vs.remote_address.clone(),
            regex_uri_vs.replace_all(request_data.uri.as_str(), "")
        );

        let request_to_uri = Client::new();
        let request_data_cloned = request_data.clone();
        let req_to_addr = request_to_uri
            .request(request_data.method, format_full_uri)
            .headers(request_data.headers)
            .body(request_data.body);
        
        match req_to_addr.send().await {
            Ok(resp) => {
                match convert_reqwest_to_hyper_response(resp).await {
                    Ok(hyper_resp) => {
                        let status: StatusCode = hyper_resp.status();
                        tracing::trace!(
                            remote_addr = ?remote_addr,
                            uri = ?request_data_cloned.uri,
                            method = ?request_data_cloned.method,
                            headers = ?request_data_cloned.headers,
                            request_id = ?uuid,
                            vs = ?vs,
                            response_code = ?status,
                            "Accepted request"
                        );
                        return Ok(hyper_resp);
                    }
                    Err(_) => {
                        tracing::trace!(
                            remote_addr = ?remote_addr,
                            uri = ?request_data_cloned.uri,
                            method = ?request_data_cloned.method,
                            headers = ?request_data_cloned.headers,
                            request_id = ?uuid,
                            vs = ?vs,
                            response_code = ?StatusCode::BAD_GATEWAY,
                            "Bad Gateway"
                        );
                        return Ok(Response::builder()
                            .status(StatusCode::BAD_GATEWAY)
                            .body(Full::new(Bytes::from(BAD_GATEWAY)))
                            .unwrap());
                    }
                }
            }
            Err(_) => {
                tracing::trace!(
                    remote_addr = ?remote_addr,
                    uri = ?request_data_cloned.uri,
                    method = ?request_data_cloned.method,
                    headers = ?request_data_cloned.headers,
                    request_id = ?uuid,
                    response_code = ?StatusCode::NOT_FOUND,
                    "Not Found"
                );
                return Ok(Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Full::new(Bytes::from(NOT_FOUND)))
                    .unwrap());
            }
        }
    } else {
        tracing::trace!(
            remote_addr = ?remote_addr,
            uri = ?request_data.uri,
            method = ?request_data.method,
            headers = ?request_data.headers,
            request_id = ?uuid,
            response_code = ?StatusCode::NOT_FOUND,
            "Not Found"
        );

        Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from(NOT_FOUND)))
            .unwrap())
    }
}