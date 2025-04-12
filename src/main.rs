
use std::{fs::File, io::BufReader, process::ExitCode, sync::Arc};

use anyhow::{anyhow, Ok, Result};
use clap::Parser;
use config::{ PolicyConfig, ServerConfig};
use hyper::{ server::conn::http1, service::service_fn};
use hyper_util::rt::{TokioIo, TokioTimer};
use request::handler::request_handler;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing_subscriber::{filter, layer::SubscriberExt, util::SubscriberInitExt, Layer};


mod config;
mod request;
mod virtualserver;
mod response;
mod domain;



#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(short = 'c', long, default_value = "config.yaml")]
    config: String,
    #[arg(short = 'p', long, default_value = "policy.yaml")]
    policy: String
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Cli::parse()).await {
        std::result::Result::Ok(_) => ExitCode::SUCCESS,
        std::result::Result::Err(_) => ExitCode::FAILURE
    }

}

async fn run(args : Cli) -> Result<()> {
    let server_config  = ServerConfig::load_server_config(&args.config).await?;
    let policy_config = PolicyConfig::load_policy_config(&args.policy).await?;
    let logging_config = server_config.clone().logging;
    

    let file_layer  = json_subscriber::fmt::layer().with_current_span(false).with_writer(logging_config.output_tofile());
    let stdout_layer  = json_subscriber::fmt::layer().with_writer(logging_config.output_stdout());
    let logging_env = tracing_subscriber::fmt::layer().with_filter(filter::LevelFilter::from_level(logging_config.is_tafficlogging()));
    
    
    if logging_config.mode == "stdout" {
        tracing_subscriber::registry().with(stdout_layer).with(logging_env).init();
    } else if logging_config.mode == "file" {
        tracing_subscriber::registry().with(file_layer).with(logging_env).init();
   } else {
      Err(anyhow!("Logging config not initialized, please choose between `stdout` or `file` mode "))

   }

    if server_config.ssl.enabled {
        match serve_tls(server_config, policy_config).await {
            std::result::Result::Ok(_) => {
                Ok(())
            }
           std::result::Result::Err(e) => {
             Err(e)
           }
        }
    } else { 
        match serve_http(server_config, policy_config).await {
            std::result::Result::Ok(_) => {
                Ok(())
            }
           std::result::Result::Err(e) => {
             Err(e)
           }
        }

    }


}

async fn serve_tls(server_config : ServerConfig,policy_conf : PolicyConfig) -> Result<()> {
    let serverconf = server_config.clone();
    let cert_file = File::open(server_config.ssl.ca_path);
    let key_file  = File::open(server_config.ssl.key_path);

    if cert_file.is_ok() && key_file.is_ok() {
        let mut cert_byte = BufReader::new(cert_file.unwrap());
        let mut key_byte = BufReader::new(key_file.unwrap());
        let cert_chain = rustls_pemfile::certs(&mut cert_byte).map(|result| result.unwrap()).collect();
        let  keys =     rustls_pemfile::private_key(&mut key_byte).map(|key| key.unwrap())?;

        let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, keys);

        match config {
            std::result::Result::Ok(mut conf) => {
                let clone_serverconfig = serverconf.clone();
                let clone_policy_confog = policy_conf.clone();
                conf.alpn_protocols =  vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"http/1.0".to_vec()];
                let tls = TlsAcceptor::from(Arc::new(conf));
                let addr = format!("{}:{}",server_config.listen_address,server_config.listen_port);
                let addr_clone = addr.clone();    
                tracing::info!("Listen on Address {}",addr_clone);
                let listener = TcpListener::bind(addr).await?;
                loop {            
                    let serverconf_loop = clone_serverconfig.clone();
                    let policyconf_loop = clone_policy_confog.clone();
                    let (tcp,_) = listener.accept().await?;
                    let remote_addr = tcp.peer_addr().unwrap().ip();
                    let tls_acceptor = tls.clone();
                    tokio::task::spawn(async move {
                        let policyconf_move = policyconf_loop.clone();
                        let serverconf_move = serverconf_loop.clone();

                      let stream_tls =   match tls_acceptor.accept(tcp).await {
                            std::result::Result::Ok(stream) => stream,
                            std::result::Result::Err(_) => {
                               return;
                            } 
                        };

                        let tokio_io = TokioIo::new(stream_tls);
                        if let Err(_) = http1::Builder::new()
                        .timer(TokioTimer::new())
                        .serve_connection(tokio_io, service_fn(move |req| {
                            request_handler(req,serverconf_move.clone(),policyconf_move.clone(),remote_addr)
                        }))
                        .await {
                            
                        }
            
                    });
                    
                }

            },
            std::result::Result::Err(_) => {

            }
        }

    }

    Ok(())   
}



async fn serve_http(server_config : ServerConfig,policy_conf : PolicyConfig) -> Result<()> {
    let addr = format!("{}:{}",server_config.listen_address,server_config.listen_port);
    let addr_clone = addr.clone();
    let listener = TcpListener::bind(addr).await?;
    let server_conf_clone = server_config.clone();
    tracing::info!("Listen on Address {}",addr_clone);
    loop {            
        let serverconf_loop = server_conf_clone.clone();
        let policyconf_loop = policy_conf.clone();
        let (tcp,_) = listener.accept().await?;
        let remote_addr = tcp.peer_addr().unwrap().ip();
        let io = TokioIo::new(tcp);
        tokio::task::spawn(async move {
            let policyconf_move = policyconf_loop.clone();
            let serverconf_move = serverconf_loop.clone();
            if let Err(_) = http1::Builder::new()
            .timer(TokioTimer::new())
            .serve_connection(io, service_fn(move |req| {
                request_handler(req,serverconf_move.clone(),policyconf_move.clone(),remote_addr)
            }))
            .await {
                
            }

        });
        
    }
}