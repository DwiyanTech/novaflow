use std::sync::Arc;

use serde::Deserialize;
use tokio::sync::RwLock;

pub mod load;


pub type SharedPolicyConfig = Arc<RwLock<PolicyConfig>>;

pub type SharedVSConfig = Arc<RwLock<ServerConfig>>;

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
     pub listen_address : String,
     pub listen_port : i32,
     pub virtual_server : Vec<VirtualServer>
}

#[derive(Debug, Deserialize, Clone)]
pub struct PolicyConfig {
     pub policy_block : Vec<RulesConfig>
} 

#[derive(Debug, Deserialize, Clone)]
pub struct RulesConfig {
    pub policy_id : i32,
    pub name : String,
    pub pattern: String,
    pub option: RulesOptions
}

#[derive(Debug, Deserialize, Clone)]
pub struct RulesOptions {
   pub header: bool,
   pub body: bool,
   pub uri: bool
}

#[derive(Debug, Deserialize, Clone)]
pub struct VirtualServer {
    pub name : String,
    pub path : String,
    pub remote_address : String,
}