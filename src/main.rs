
use std::sync::Arc;
use config::load::{ load_policy_config, load_vs_config, read_policy_config,read_vs_config};
use hyper::{ server::conn::http1, service::service_fn};
use hyper_util::rt::{TokioIo, TokioTimer};
use request::handler::request_handler;
use tokio::{net::TcpListener, sync::RwLock};


mod config;
mod request;

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {

    // This address is localhost
    let conf_policy = load_policy_config("policy.yaml").await.unwrap();
    let conf_policy_load_memoy = Arc::new(RwLock::new(conf_policy));
    let conf_server =  load_vs_config("config.yaml").await.unwrap();
    let conf_server_load_memoy = Arc::new(RwLock::new(conf_server));
    let conf_mem_server = read_vs_config(conf_server_load_memoy.clone()).await;
    let addr = format!("{}:{}",conf_mem_server.listen_address,conf_mem_server.listen_port);
    let listener = TcpListener::bind(addr.clone()).await?;
    println!("Listening on http://{}", addr.clone());
    loop {
        let conf_mem_policy = read_policy_config(conf_policy_load_memoy.clone()).await;
        let conf_mem_server = read_vs_config(conf_server_load_memoy.clone()).await;
        let (tcp, _) = listener.accept().await?;
        let remote_addr = tcp.peer_addr().unwrap().ip();
        let io = TokioIo::new(tcp);
        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .timer(TokioTimer::new())
                .serve_connection(io, service_fn(move |req| {
                    request_handler(req,conf_mem_server.virtual_server.clone(), conf_mem_policy.clone(),remote_addr)
                }))
                .await
            {
                println!("Error serving connection: {:?}", err);
            }
        });
    }
}