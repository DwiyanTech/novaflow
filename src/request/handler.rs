use std::{collections::HashMap, net::IpAddr};

use http_body_util::{BodyExt, Full};
use hyper::{
    body::Bytes,
    Error, HeaderMap, Request, Response, StatusCode,
};
use regex::Regex;
use reqwest::Client;

use crate::config::{PolicyConfig, VirtualServer};

use super::{filter::check_rules, BAD_GATEWAY, NOT_FOUND};

pub async fn request_handler(
    req: Request<hyper::body::Incoming>,
    vs_conf: Vec<VirtualServer>,
    conf: PolicyConfig,
    remote_addr: IpAddr,
) -> Result<Response<Full<Bytes>>, Error> {
    let mut matched_rules: bool = false;
    let method = req.method().clone();
    let uri = req.uri().clone().to_string();
    let uri_cloned = req.uri().clone().to_string();
    let path = req.uri().path().to_string(); 
    let headers = req.headers().clone();
    let body_bytes = req.collect().await?.to_bytes();
    let string_body = String::from_utf8_lossy(&body_bytes).to_string().clone();

    let matched_string = check_rules(conf, string_body,uri,headers.clone()).await?; 

    for result in matched_string.iter() {
        if let Some(matched) = result {
            matched_rules = true;
            println!(
                "Rules Matched: Rule Name : {}, Policy ID :  {} , Remote IP : {}",
                matched.name, matched.policy_id, remote_addr
            );
        }

    }

    if matched_rules {
        return Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Full::new(Bytes::from(super::BLOCKED_REQUEST)))
            .unwrap());
    }

    let config_map: HashMap<&str, &VirtualServer> = vs_conf.iter().map(|c| (c.path.as_str(), c)).collect();

    if let Some(matched_path) = config_map.keys().find(|k| path.starts_with(*k)) {
        if let Some(vs) = config_map.get(matched_path) {
            let uri_cloned = uri_cloned.to_owned();
            let pattern_uri = format!("^{}",vs.path.as_str());
            let regex_uri_vs = Regex::new(&pattern_uri).unwrap();
            let format_full_uri = format!("{}{}",vs.remote_address.clone(),regex_uri_vs.replace_all(uri_cloned.clone().as_str(), ""));
            let request_to_uri = Client::new();
            let req_to_addr = request_to_uri
                .request(method, format_full_uri) // Use cloned method and remote address
                .headers(headers.clone()) // Use cloned headers
                .body(body_bytes.clone()); // Use cloned body

            match req_to_addr.send().await {
                Ok(resp) => {
                    match convert_reqwest_to_hyper_response(resp).await {
                        Ok(hyper_resp) => Ok(hyper_resp),
                        Err(_) => Ok(Response::builder()
                            .status(StatusCode::BAD_GATEWAY)
                            .body(Full::new(Bytes::from(BAD_GATEWAY)))
                            .unwrap()),
                    }
                }
                Err(_) => Ok(Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(Full::new(Bytes::from(BAD_GATEWAY)))
                    .unwrap()),
            }
        } else {
            return Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from(BAD_GATEWAY)))
                .unwrap());
        }
    } else {
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
