

use super::{PolicyConfig, ServerConfig, SharedPolicyConfig,SharedVSConfig};



pub async fn load_policy_config(file_path: &str) -> Result<PolicyConfig, Box<dyn std::error::Error>> {
    let contents = tokio::fs::read_to_string(file_path).await?;
    let config: PolicyConfig = serde_yaml::from_str(&contents)?;
    Ok(config)
}


pub async fn read_policy_config(conf : SharedPolicyConfig) -> PolicyConfig {
    let cfg = conf.read().await;
    cfg.to_owned()
}

pub async fn load_vs_config(file_path: &str) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    let contents = tokio::fs::read_to_string(file_path).await?;
    let config: ServerConfig = serde_yaml::from_str(&contents)?;
    Ok(config)
}


pub async fn read_vs_config(conf : SharedVSConfig) -> ServerConfig {
    let cfg = conf.read().await;
    cfg.to_owned()
}