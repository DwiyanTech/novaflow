use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use tracing::Level;
use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};

use super::{GeoIpConfig, LoggingConfig, PolicyConfig, RateLimitConfig, ServerConfig};

/// Resolve a path that may be relative to the directory containing `base_path`.
fn resolve_relative_path(base_path: &str, rel: &str) -> PathBuf {
    let base = Path::new(base_path);
    if let Some(parent) = base.parent() {
        parent.join(rel)
    } else {
        PathBuf::from(rel)
    }
}

impl ServerConfig {
    pub async fn load_server_config(file_path: &str) -> Result<ServerConfig> {
        let contents = tokio::fs::read_to_string(file_path).await.map_err(|err| {
            println!("Error reading file: {}", err);
            err
        })?;

        let mut config = match serde_yaml::from_str::<ServerConfig>(&contents) {
            std::result::Result::Ok(res) => res,
            std::result::Result::Err(err) => {
                println!("Error in Yaml configuration {} : {}", file_path, err);
                return Err(anyhow!(err));
            }
        };

        // If split config paths are set, load those sections from their own files.
        if let Some(path) = config.geoip_config_path.as_deref() {
            let resolved = resolve_relative_path(file_path, path);
            match tokio::fs::read_to_string(&resolved).await {
                std::result::Result::Ok(contents) => {
                    match serde_yaml::from_str::<GeoIpConfig>(&contents) {
                        std::result::Result::Ok(geoip) => config.geoip = geoip,
                        std::result::Result::Err(err) => {
                            return Err(anyhow!(
                                "invalid geoip config {}: {}",
                                resolved.display(),
                                err
                            ));
                        }
                    }
                }
                std::result::Result::Err(err) => {
                    tracing::warn!(
                        "failed to read geoip config {}: {}; keeping inline values",
                        resolved.display(),
                        err
                    );
                }
            }
        }

        if let Some(path) = config.rate_limit_config_path.as_deref() {
            let resolved = resolve_relative_path(file_path, path);
            match tokio::fs::read_to_string(&resolved).await {
                std::result::Result::Ok(contents) => {
                    match serde_yaml::from_str::<RateLimitConfig>(&contents) {
                        std::result::Result::Ok(rate_limit) => config.rate_limit = rate_limit,
                        std::result::Result::Err(err) => {
                            return Err(anyhow!(
                                "invalid rate_limit config {}: {}",
                                resolved.display(),
                                err
                            ));
                        }
                    }
                }
                std::result::Result::Err(err) => {
                    tracing::warn!(
                        "failed to read rate_limit config {}: {}; keeping inline values",
                        resolved.display(),
                        err
                    );
                }
            }
        }

        Ok(config)
    }
}

impl PolicyConfig {
    pub async fn load_policy_config(file_path: &str) -> Result<PolicyConfig> {
        let contents = tokio::fs::read_to_string(file_path).await?;
        let config = serde_yaml::from_str::<PolicyConfig>(&contents);
        match config {
            std::result::Result::Ok(res) => return Ok(res),
            std::result::Result::Err(err) => {
                tracing::error!("Error in Yaml configuration : {}", err);
                return Err(anyhow!(err));
            }
        }
    }
}

#[allow(dead_code)]
impl LoggingConfig {
    pub fn is_tafficlogging(&self) -> Level {
        if self.trace_traffic {
            tracing::Level::TRACE
        } else {
            tracing::Level::DEBUG
        }
    }

    pub fn output_tofile(&self) -> (NonBlocking, WorkerGuard) {
        let file_appender =
            tracing_appender::rolling::daily(self.clone().file_path, self.clone().file_name);
        tracing_appender::non_blocking(file_appender)
    }

    pub fn output_stdout(&self) -> (NonBlocking, WorkerGuard) {
        tracing_appender::non_blocking(std::io::stdout())
    }

    /// Blocking stdout writer. Use this when logs must appear immediately
    /// and the process stdout is redirected to a file or pipe.
    pub fn stdout_blocking(&self) -> std::io::Stdout {
        std::io::stdout()
    }
}
