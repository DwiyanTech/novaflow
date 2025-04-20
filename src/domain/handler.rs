use std::net::IpAddr;

use anyhow::{anyhow, Ok, Result};
use http_body_util::Full;
use hyper::{body::Bytes, Response, StatusCode};
use reqwest::Client;

use crate::{config::DomainServer, request::{self, RequestData, BAD_GATEWAY}, response::convert::convert_reqwest_to_hyper_response};



pub async fn domain_handler(
    domain_conf: Vec<DomainServer>,
    request_data: RequestData,
    source_ip: IpAddr,
    uuid: String
) -> Result<Response<Full<Bytes>>> {
        if let Some(domain) = domain_conf.iter().find(|domain_server| request_data.host == domain_server.domain_name) {
            let format_full_uri = format!("{}{}",domain.remote_address,request_data.uri);
            let request_to_uri = Client::new();
            let request_data_cloned = request_data.clone();
            let req_to_addr = request_to_uri
                .request(request_data.method, format_full_uri)
                .headers(request_data.headers)
                .body(request_data.body);

                match req_to_addr.send().await {
                    std::result::Result::Ok(resp) => {
                        match convert_reqwest_to_hyper_response(resp).await {
                            std::result::Result::Ok(hyper_resp) => {
                                let status: StatusCode = hyper_resp.status();
                                tracing::trace!(
                                    remote_addr = ?source_ip,
                                    uri = ?request_data_cloned.uri,
                                    method = ?request_data_cloned.method,
                                    headers = ?request_data_cloned.headers,
                                    request_id = ?uuid,
                                    domain = ?domain.name,
                                    response_code = ?status,
                                    "Accepted request"
                                );
                                return Ok(hyper_resp);
                            }
                            std::result::Result::Err(err) => {
                                let error = format!("Error when send requests : {}",err.to_string());
                                let bad_gw = BAD_GATEWAY.replace("REPLACE_WITH_UUID_REQUESTS", &uuid);

                                tracing::trace!(
                                    remote_addr = ?source_ip,
                                    uri = ?request_data_cloned.uri,
                                    method = ?request_data_cloned.method,
                                    headers = ?request_data_cloned.headers,
                                    request_id = ?uuid,
                                    domain = ?domain.name,
                                    response_code = ?StatusCode::BAD_GATEWAY,
                                    error
                                );
                                return Ok(Response::builder()
                                    .status(StatusCode::BAD_GATEWAY)
                                    .body(Full::new(Bytes::from(bad_gw)))
                                    .unwrap());
                            }
                        }
                    }
                    Err(err) => {
                        let error = format!("{}",err.to_string());
                        tracing::trace!(
                            remote_addr = ?source_ip,
                            uri = ?request_data_cloned.uri,
                            method = ?request_data_cloned.method,
                            headers = ?request_data_cloned.headers,
                            request_id = ?uuid,
                            error
                        );
                        Err(anyhow!("Domain Not Found"))
                    }
                }
            } else {
                tracing::trace!(
                    remote_addr = ?source_ip,
                    uri = ?request_data.uri,
                    method = ?request_data.method,
                    headers = ?request_data.headers,
                    request_id = ?uuid,
                    response_code = ?StatusCode::NOT_FOUND,
                    "Not Found"
                );
        
                Err(anyhow!("Domain Not Found"))

        }
        

    } 

    
    
