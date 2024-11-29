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
                let mut checked_val = false;
                let obj_rules: RulesConfig = obj.clone();
                let obj_val: RulesConfig = obj_rules.clone();
                let mut match_regex: Option<RulesConfig> = None;
                
                if obj_rules.option.uri && !checked_val{
                   match_regex = check_regex_pattern(obj_val.clone(), val_uri_clone);
                   if match_regex.is_some()  {
                    checked_val = true;
                   }
                } 
                
                 if obj_rules.option.header && !checked_val {
                    match_regex = check_header(obj_val.clone(), header_uri_clone);
                    if match_regex.is_some()  {
                        checked_val = true;
                       }
                } 
                 if obj_rules.option.body && !checked_val {
                    match_regex = check_regex_pattern(obj_val.clone(), body_clone);
                    if match_regex.is_some()  {
                        checked_val = true;
                       }
                } 

                match_regex
                 
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