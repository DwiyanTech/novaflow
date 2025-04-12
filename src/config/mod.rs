
use serde::Deserialize;

pub mod load;

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
     pub listen_address : String,
     pub listen_port : i32,
     pub ssl : SSLServer,
     pub logging: LoggingConfig,
     pub virtual_server : Vec<VirtualServer>,
     pub domain_config : Vec<DomainServer>
     
}

#[derive(Debug, Deserialize, Clone)]
pub struct LoggingConfig {
     pub mode : String,
     pub trace_traffic : bool,
     pub file_directory : String,
     pub file_name : String,
     

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

#[derive(Debug, Deserialize, Clone)]
pub struct DomainServer {
    pub name : String,
    pub domain_name : String,
    pub remote_address : String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SSLServer {
    pub enabled : bool,
    pub ca_path : String,
    pub key_path : String,
}
