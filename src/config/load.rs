

use anyhow::{anyhow, Ok, Result};
use tracing::Level;
use tracing_appender::non_blocking:: NonBlocking;

use super::{LoggingConfig, PolicyConfig, ServerConfig};

impl ServerConfig {
    pub async fn load_server_config(file_path: &str) -> Result<ServerConfig> {

        let contents = tokio::fs::read_to_string(file_path).await.map_err(|err| {
            println!("Error reading file: {}", err);
            err
        })?;


        let config = serde_yaml::from_str::<ServerConfig>(&contents);

        match config {
            std::result::Result::Ok(res) => return Ok(res),
            std::result::Result::Err(err) => {
                println!("Error in Yaml configuration {} : {}",file_path,err);
                return Err(anyhow!(err));
            }

        }

   
    }

}


impl PolicyConfig {
    pub async fn load_policy_config(file_path: &str) ->  Result<PolicyConfig> {
        let contents = tokio::fs::read_to_string(file_path).await?;
        let config = serde_yaml::from_str::<PolicyConfig>(&contents);
        match config {
            std::result::Result::Ok(res) => return  Ok(res),
            std::result::Result::Err(err) => {
                tracing::error!("Error in Yaml configuration : {}",err);
                return Err(anyhow!(err));
            }
        }
    }
    
}


impl LoggingConfig {
    pub fn is_tafficlogging(&self) -> Level {
        if self.trace_traffic {
            tracing::Level::TRACE
        } else {
            tracing::Level::DEBUG
        }
    }

    pub fn output_tofile(&self) -> NonBlocking {
        let file_appender = tracing_appender::rolling::daily(self.clone().file_path, self.clone().file_name);
        let (file_writer, _) = tracing_appender::non_blocking(file_appender);
        file_writer
    }

    pub fn output_stdout(&self) -> NonBlocking {
        let (stdout_writer, _) = tracing_appender::non_blocking(std::io::stdout());
        stdout_writer
    }
}


