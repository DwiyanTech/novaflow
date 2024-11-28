use futures::future;
use hyper::HeaderMap;
use regex::Regex;
use tokio::task;

use crate::config::{PolicyConfig, RulesConfig};


pub async fn check_rules(list_patterns : PolicyConfig, body : String,uri : String, header : HeaderMap ) -> Result<Vec<Option<RulesConfig>>,hyper::Error> {
        let check : Vec<_>= list_patterns.policy_block.into_iter().map(|obj| {
            let val_uri_clone = uri.clone();
            let header_uri_clone = header.clone();
            let body_clone = body.clone();
            task::spawn_blocking( move || {
                if obj.option.uri {
                    check_regex_pattern(obj, val_uri_clone)
                } else if obj.option.header {
                    check_header(obj, header_uri_clone)
                } else if obj.option.body {
                    check_regex_pattern(obj, body_clone)
                } else {
                None
                }
                 
            })
        }).collect();
        
        let results = future::join_all(check).await;
        Ok(results.into_iter().map(|res  | res.unwrap()).collect())
}

 fn check_regex_pattern(obj : RulesConfig,val : String) -> Option<RulesConfig>{
    let regex = Regex::new(&obj.pattern).unwrap();
    if let Some(_) = regex.find(&val) {
        Some(obj)
    } else {
        None
    }

}

fn check_header(obj : RulesConfig,header : HeaderMap) -> Option<RulesConfig> {
    let mut matched_regex : Option<RulesConfig> = None;    
    for (key,value) in header.iter() {
        let check_key_value : String = format!("{} : {}",key.to_string(),value.to_str().unwrap_or("").to_string());
        matched_regex =  check_regex_pattern(obj.clone(), check_key_value);
        if matched_regex.is_some() {
            break;
        }
    }
    matched_regex

}