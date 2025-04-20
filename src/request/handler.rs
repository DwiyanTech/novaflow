use std::net::IpAddr;

use uuid::Uuid;
use http_body_util::{BodyExt, Full};
use hyper::{
    body::Bytes,
     Request, Response, StatusCode,
};

use anyhow::{Ok, Result};
use crate::{config::{PolicyConfig, ServerConfig}, domain::handler::domain_handler, virtualserver::handler::virtual_server_handler};

use super::{filter::check_rules, RequestData};

pub async fn request_handler(
    req: Request<hyper::body::Incoming>,
    server_conf: ServerConfig,
    policy_conf: PolicyConfig,
    remote_addr: IpAddr,
) -> Result<Response<Full<Bytes>>> {
    let mut host : String = "".to_string();
    if let Some(host_uri) = req.uri().host() {
        host = host_uri.to_string();
    }
    let request_data = RequestData {
        
        uri: req.uri().path().to_string(),
        method: req.method().clone(),
        headers: req.headers().clone(),
        body: req.collect().await.unwrap().to_bytes(),
        host: host
    };
        let vs_conf = server_conf.virtual_server;
    let domain_conf = server_conf.domain_server;

    let uuid = Uuid::now_v7().to_string();
    let matched_rules = check_rules(policy_conf, request_data.clone()).await?;

    for rule in matched_rules {
        if let Some(_matched) = rule {
            tracing::info!(remote_addr = ?remote_addr, rule_name = ?_matched.name, policy_id = ?_matched.policy_id, uri = ?request_data.uri,method = ?request_data.method, headers = ?request_data.headers, request_id = ?uuid,  "Blocked request");
            let forbidden = super::BLOCKED_REQUEST.replace("REPLACE_WITH_UUID_REQUESTS", &uuid);
            return Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Full::new(Bytes::from(forbidden)))
            .unwrap());

        }
    }

    if request_data.uri.starts_with("/novaflow_healthz") {
        tracing::info!(remote_addr = ?remote_addr, uri = ?request_data.uri,method = ?request_data.method, headers = ?request_data.headers, request_id = ?uuid,  "Health check request");
        return Ok(Response::new(Full::new(Bytes::from("{\"status\": \"ok\"}"))));
    }


     match domain_handler(domain_conf.config, request_data.clone(), remote_addr.clone(), uuid.clone()).await {

         std::result::Result::Ok(resp) => {
      
        
            Ok(resp)
      
         }

        std::result::Result::Err(_) => {
            virtual_server_handler(vs_conf.config, request_data, remote_addr, uuid).await
        }
         
     }
      
  

}




