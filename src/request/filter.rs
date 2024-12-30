use futures::future;
use hyper::HeaderMap;
use regex::Regex;
use tokio::task;

use crate::config::{PolicyConfig, RulesConfig};

use super::RequestData;


 pub async fn check_rules(list_patterns : PolicyConfig, req_data : RequestData ) -> Result<Vec<Option<RulesConfig>>,hyper::Error> {
        let check : Vec<_>= list_patterns.policy_block.into_iter().map(|obj| {
            let req_data = req_data.clone();
            task::spawn_blocking( move || {
                let body_string = String::from_utf8_lossy(&req_data.body).to_string().clone();
                let mut match_regex: Option<RulesConfig> = None;
                let checks = [
                    (obj.option.header, check_header(obj.clone(), req_data.headers)),
                    (obj.option.body, check_regex_pattern(obj.clone(), body_string)),
                    (obj.option.uri, check_regex_pattern(obj.clone(), req_data.uri))
                     ];
        
                     checks.iter().find_map(|(condition,res_val)| {
                        if *condition {
                            match res_val {
                                Ok(Some(val)) => {
                                    match_regex = Some(val.clone());
                                    return Some(val.clone());
                                }
                                Ok(None) => {
                                    return None;
                                }
                                Err(_) => {
                                    return None;
                                }
                            }
                        }
                        None
                     })
         
            })


        }).collect();
        
        let results = future::join_all(check).await;
        Ok(results.into_iter().map(|res  | res.unwrap()).collect())
}
 
 fn check_regex_pattern(obj : RulesConfig,val : String)-> Result<Option<RulesConfig>, Box<dyn std::error::Error>> {
    let regex = Regex::new(&obj.pattern).unwrap();
    if let Some(_) = regex.find(&val) {
        Ok(Some(obj))
    } else {
       Ok( None)
    }

}

fn check_header(obj : RulesConfig,header : HeaderMap) -> Result<Option<RulesConfig>, Box<dyn std::error::Error>> {
    for (key,value) in header.iter() {
        let  convert_header_string = format!("{}: {}",key.to_string(),value.to_str()?);
        if let Some(matched) = check_regex_pattern(obj.clone(),convert_header_string)? {
            return Ok(Some(matched));
        }
    }

    Ok(None)


}