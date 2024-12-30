use std::net::IpAddr;

use uuid::Uuid;
use http_body_util::{BodyExt, Full};
use hyper::{
    body::Bytes,
    Error, HeaderMap, Request, Response, StatusCode,
};
use regex::Regex;
use reqwest::Client;
use crate::config::{PolicyConfig, VirtualServer};

use super::{filter::check_rules, RequestData, BAD_GATEWAY, NOT_FOUND};

pub async fn request_handler(
    req: Request<hyper::body::Incoming>,
    vs_conf: Vec<VirtualServer>,
    policy_conf: PolicyConfig,
    remote_addr: IpAddr,
) -> Result<Response<Full<Bytes>>, Error> {
    let request_data = RequestData {
        uri: req.uri().to_string(),
        method: req.method().clone(),
        headers: req.headers().clone(),
        body: req.collect().await.unwrap().to_bytes(),
    };

    let uuid = Uuid::now_v7().to_string();
    let matched_rules = check_rules(policy_conf, request_data.clone()).await?;

    for rule in matched_rules {
        if let Some(_matched) = rule {
            tracing::info!(remote_addr = ?remote_addr, rule_name = ?_matched.name, policy_id = ?_matched.policy_id, uri = ?request_data.uri,method = ?request_data.method, headers = ?request_data.headers, request_id = ?uuid,  "Blocked request");
            return Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Full::new(Bytes::from(super::BLOCKED_REQUEST)))
            .unwrap());

        }
    }

    if request_data.uri == "/healthz" {
        tracing::info!(remote_addr = ?remote_addr, uri = ?request_data.uri,method = ?request_data.method, headers = ?request_data.headers, request_id = ?uuid,  "Health check request");
        return Ok(Response::new(Full::new(Bytes::from("{\"status\": \"ok\"}"))));
    }



   if let Some(vs) = vs_conf.iter().find(|vs| request_data.uri.starts_with(&vs.path)){
    let req_data = request_data.clone();
    let pattern_uri = format!("^{}",vs.path.as_str());
    let regex_uri_vs = Regex::new(&pattern_uri).unwrap();
    let format_full_uri = format!("{}{}",vs.remote_address.clone(),regex_uri_vs.replace_all(req_data.uri.as_str(), ""));
    let request_to_uri = Client::new();
    let req_to_addr = request_to_uri
        .request(req_data.method, format_full_uri)
        .headers(req_data.headers) 
        .body(req_data.body);


    match req_to_addr.send().await {
        Ok(resp) => {
            match convert_reqwest_to_hyper_response(resp).await {
                Ok(hyper_resp) => {
                    let status: StatusCode = hyper_resp.status();
                    tracing::info!(remote_addr = ?remote_addr, uri = ?request_data.uri,method = ?request_data.method, headers = ?request_data.headers, request_id = ?uuid,vs = ?vs,response_code = ?status,  "Accepted request");
                    return Ok(hyper_resp);
                }
                Err(_) => {
                    tracing::info!(remote_addr = ?remote_addr, uri = ?request_data.uri,method = ?request_data.method, headers = ?request_data.headers, request_id = ?uuid, vs = ?vs,response_code = ?StatusCode::BAD_GATEWAY,  "Bad Gateway");
                    return Ok(Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(Full::new(Bytes::from(BAD_GATEWAY)))
                    .unwrap());
                }
            }
        }

        Err(_) => {
            tracing::info!(remote_addr = ?remote_addr, uri = ?request_data.uri,method = ?request_data.method, headers = ?request_data.headers, request_id = ?uuid,response_code = ?StatusCode::NOT_FOUND,  "Not Found");
            return Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from(NOT_FOUND)))
            .unwrap());
    }
   }    
   
} else {
    tracing::info!(remote_addr = ?remote_addr, uri = ?request_data.uri,method = ?request_data.method, headers = ?request_data.headers, request_id = ?uuid,response_code = ?StatusCode::NOT_FOUND,  "Not Found");

    Ok(Response::builder()
    .status(StatusCode::NOT_FOUND)
    .body(Full::new(Bytes::from(NOT_FOUND)))
    .unwrap())

}

}


async fn convert_reqwest_to_hyper_response(
    reqwest_resp: reqwest::Response,
) -> Result<Response<Full<Bytes>>, Box<dyn std::error::Error>> {
    let status = reqwest_resp.status();

    // Convert reqwest headers to hyper headers
    let mut hyper_headers = HeaderMap::new();
    for (key, value) in reqwest_resp.headers().iter() {
        hyper_headers.insert(key.clone(), value.clone());
    }

    let bytes = reqwest_resp.bytes().await?;
    let response_builder = Response::builder().status(status);
    let mut hyper_resp = response_builder.body(Full::new(Bytes::from(bytes)))?;
    *hyper_resp.headers_mut() = hyper_headers; // Set headers in the response

    Ok(hyper_resp)
}