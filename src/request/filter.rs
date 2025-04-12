use futures::future;
use hyper::HeaderMap;
use regex::Regex;
use tokio::task;
use crate::config::{PolicyConfig, RulesConfig};
use super::RequestData;

pub async fn check_rules(
    list_patterns: PolicyConfig,
    req_data: RequestData,
) -> Result<Vec<Option<RulesConfig>>, hyper::Error> {


    let checks: Vec<_> = list_patterns
        .policy_block
        .into_iter()
        .map(|obj| {
            let req_data = req_data.clone();
            task::spawn_blocking(move || {
                let body_string = String::from_utf8_lossy(&req_data.body).to_string();
                let mut match_result: Option<RulesConfig> = None;

                if obj.option.uri {
                    if let Ok(Some(matched)) = check_regex_pattern(obj.clone(), req_data.uri.clone()) {
                        match_result = Some(matched);
                    }
                }

                if match_result.is_none() && obj.option.header {
                    if let Ok(Some(matched)) = check_header(obj.clone(), req_data.headers.clone()) {
                        match_result = Some(matched);
                    }
                }

                if match_result.is_none() && obj.option.body {
                    if let Ok(Some(matched)) = check_regex_pattern(obj.clone(), body_string.clone()) {
                        match_result = Some(matched);
                    }
                }

                match_result
            })
        })
        .collect();

    let results = future::join_all(checks)
        .await
        .into_iter()
        .map(|res| res.unwrap()) 
        .collect();

    Ok(results)
}

fn check_regex_pattern(
    obj: RulesConfig,
    val: String,
) -> Result<Option<RulesConfig>, Box<dyn std::error::Error>> {
    let regex = Regex::new(&obj.pattern)?;
    if regex.is_match(&val) {
        Ok(Some(obj))
    } else {
        Ok(None)
    }
}

fn check_header(
    obj: RulesConfig,
    header: HeaderMap,
) -> Result<Option<RulesConfig>, Box<dyn std::error::Error>> {
    for (key, value) in header.iter() {
        let header_string = format!("{}: {}", key.as_str(), value.to_str()?);
        if let Some(matched) = check_regex_pattern(obj.clone(), header_string)? {
            return Ok(Some(matched));
        }
    }
    Ok(None)
}