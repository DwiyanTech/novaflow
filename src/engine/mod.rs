//! Novaflow detection engine (v2).
//!
//! Pipeline per request:
//!   1. **Surfaces** — path, every query value, every header value, body
//!      (the old engine only looked at the raw path).
//!   2. **Normalize** each surface (multi-decode, entities, control chars)
//!      so encoding evasion collapses before matching.
//!   3. **Semantic detectors** (SQLi, XSS, traversal, CMDi, RFI) score
//!      contextual signals, all configured via `policy.yaml`.
//!   4. **Custom regex rules** (precompiled at startup — the old engine
//!      recompiled every pattern for every request) add their score.
//!   5. **Anomaly scoring**: scores are summed; a request is blocked when
//!      the total reaches `detection.anomaly_threshold` — single weak
//!      signals pass, combined signals block. In `mode: detect` nothing is
//!      blocked, detections are only logged (learning mode).

pub mod detectors;
pub mod normalize;

use regex::Regex;

use crate::config::{Mode, PolicyConfig};
use crate::request::RequestData;

pub use detectors::Detection;

/// A custom regex rule with its pattern compiled once at startup.
#[derive(Debug)]
struct CompiledRule {
    name: String,
    score: u32,
    policy_id: i32,
    regex: Regex,
    check_uri: bool,
    check_header: bool,
    check_body: bool,
}

/// Precompiled, ready-to-evaluate engine. Cheap to clone into tasks.
#[derive(Debug, Clone)]
pub struct Engine {
    policy: PolicyConfig,
    compiled: std::sync::Arc<Vec<CompiledRule>>,
}

/// Final verdict for one request.
#[derive(Debug)]
pub struct Verdict {
    pub score: u32,
    pub detections: Vec<Detection>,
    pub should_block: bool,
}

impl Engine {
    /// Build the engine from the policy file; regexes are compiled ONCE.
    pub fn new(policy: PolicyConfig) -> Result<Self, String> {
        let mut compiled = Vec::with_capacity(policy.custom_rules.len());
        for rule in &policy.custom_rules {
            let regex = Regex::new(&rule.pattern)
                .map_err(|e| format!("custom rule `{}` has invalid regex: {e}", rule.name))?;
            compiled.push(CompiledRule {
                name: rule.name.clone(),
                score: rule.score,
                policy_id: rule.policy_id,
                regex,
                check_uri: rule.option.uri,
                check_header: rule.option.header,
                check_body: rule.option.body,
            });
        }
        Ok(Self {
            policy,
            compiled: std::sync::Arc::new(compiled),
        })
    }

    pub fn mode(&self) -> Mode {
        self.policy.detection.mode
    }

    pub fn policy(&self) -> &PolicyConfig {
        &self.policy
    }

    /// Maximum body size inspected (also caps proxy buffering).
    pub fn max_body_bytes(&self) -> usize {
        self.policy.detection.max_body_bytes
    }

    /// Inspect a request and compute the anomaly verdict.
    pub fn inspect(&self, req: &RequestData) -> Verdict {
        let rules = &self.policy.rules;
        let mut detections: Vec<Detection> = Vec::new();

        let mut scan = |surface: Surface, raw: &str| {
            if raw.len() > self.policy.detection.max_body_bytes.max(4096)
                && surface == Surface::Header
            {
                return; // skip absurdly large headers
            }
            let norm = normalize::normalize(raw);
            let folded = normalize::fold(&norm);

            let mut d = detectors::detect_sqli(&folded, &rules.sqli);
            d.extend(detectors::detect_xss(&folded, &rules.xss));
            d.extend(detectors::detect_path_traversal(
                &folded,
                &rules.path_traversal,
            ));
            d.extend(detectors::detect_command_injection(
                &folded,
                &rules.command_injection,
            ));
            d.extend(detectors::detect_rfi(&folded, &rules.rfi));

            // custom regex rules on the normalized surface
            for cr in self.compiled.iter() {
                let applies = matches!(surface, Surface::Path | Surface::Query) && cr.check_uri
                    || surface == Surface::Header && cr.check_header
                    || surface == Surface::Body && cr.check_body;
                if applies && cr.regex.is_match(&norm) {
                    d.push(Detection {
                        family: "custom",
                        rule: format!("custom rule `{}`", cr.name),
                        score: cr.score,
                        evidence: norm.chars().take(80).collect(),
                        policy_id: cr.policy_id,
                    });
                }
            }

            detections.extend(d);
        };

        // path
        scan(Surface::Path, &req.uri);

        // query values (split & decode each — old engine never saw these)
        if let Some(query) = req.query.as_deref() {
            for pair in query.split('&') {
                // Scan the full `key=value` pair — detectors like RFI need
                // the parameter name for context.
                scan(Surface::Query, pair);
            }
        }

        // header values
        for (name, value) in req.headers.iter() {
            // Host and cookies are the classic carriers; inspect all.
            if let Ok(v) = value.to_str() {
                let _ = name;
                scan(Surface::Header, v);
            }
        }

        // body
        if !req.body.is_empty() && req.body.len() <= self.policy.detection.max_body_bytes {
            let body = String::from_utf8_lossy(&req.body);
            scan(Surface::Body, &body);
        }

        let score: u32 = detections.iter().map(|d| d.score).sum();
        let should_block = self.policy.detection.mode == Mode::Block
            && score >= self.policy.detection.anomaly_threshold;

        Verdict {
            score,
            detections,
            should_block,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Surface {
    Path,
    Query,
    Header,
    Body,
}

impl std::fmt::Display for Surface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Surface::Path => "path",
            Surface::Query => "query",
            Surface::Header => "header",
            Surface::Body => "body",
        };
        f.write_str(s)
    }
}

// ------------------------------------------------------------------ tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CustomRule, RulesOptions};
    use hyper::body::Bytes;
    use hyper::{HeaderMap, Method};

    fn req(uri: &str, query: Option<&str>, body: &str) -> RequestData {
        let body = Bytes::from(body.to_string());
        RequestData {
            body_bytes: body.len(),
            body,
            headers: HeaderMap::new(),
            uri: uri.to_string(),
            query: query.map(|q| q.to_string()),
            method: Method::GET,
            host: "example.com".to_string(),
        }
    }

    fn engine() -> Engine {
        Engine::new(PolicyConfig::default()).unwrap()
    }

    #[test]
    fn blocks_sqli_in_query_param() {
        let v = engine().inspect(&req("/users", Some("id=1%20UNION%20SELECT%20a,b"), ""));
        assert!(v.should_block, "verdict: {v:?}");
        assert!(v.score >= 5);
    }

    #[test]
    fn passes_benign_query() {
        let v = engine().inspect(&req("/products", Some("q=please+select+your+size"), ""));
        assert!(!v.should_block, "false positive: {v:?}");
        assert_eq!(v.score, 0);
    }

    #[test]
    fn blocks_encoded_xss() {
        let v = engine().inspect(&req(
            "/search",
            Some("q=%3Cscript%3Ealert(1)%3C/script%3E"),
            "",
        ));
        assert!(v.should_block);
    }

    #[test]
    fn detect_mode_never_blocks() {
        let mut policy = PolicyConfig::default();
        policy.detection.mode = Mode::Detect;
        let e = Engine::new(policy).unwrap();
        let v = e.inspect(&req("/x", Some("id=1' OR '1'='1"), ""));
        assert!(v.score >= 5);
        assert!(!v.should_block);
    }

    #[test]
    fn custom_rule_scores_and_blocks() {
        let mut policy = PolicyConfig::default();
        policy.custom_rules.push(CustomRule {
            policy_id: 9001,
            name: "wp-admin probe".into(),
            pattern: "(?i)wp-admin".into(),
            option: RulesOptions {
                uri: true,
                header: false,
                body: false,
            },
            score: 5,
        });
        let e = Engine::new(policy).unwrap();
        let v = e.inspect(&req("/wp-admin/setup.php", None, ""));
        assert!(v.should_block);
        assert!(v.detections.iter().any(|d| d.family == "custom"));
    }

    #[test]
    fn weak_signals_accumulate_across_surfaces() {
        // threshold 5: a 3-score hit in query + 3-score hit in body
        let mut policy = PolicyConfig::default();
        policy.custom_rules = vec![
            CustomRule {
                policy_id: 1,
                name: "odd-q".into(),
                pattern: "oddvalue".into(),
                option: RulesOptions {
                    uri: true,
                    header: false,
                    body: false,
                },
                score: 3,
            },
            CustomRule {
                policy_id: 2,
                name: "odd-b".into(),
                pattern: "oddcontent".into(),
                option: RulesOptions {
                    uri: false,
                    header: false,
                    body: true,
                },
                score: 3,
            },
        ];
        let e = Engine::new(policy).unwrap();
        let v = e.inspect(&req("/p", Some("a=oddvalue"), "oddcontent"));
        assert_eq!(v.score, 6);
        assert!(v.should_block);
    }

    #[test]
    fn invalid_custom_regex_rejected_at_startup() {
        let mut policy = PolicyConfig::default();
        policy.custom_rules.push(CustomRule {
            policy_id: 1,
            name: "broken".into(),
            pattern: "([unclosed".into(),
            option: RulesOptions::default(),
            score: 5,
        });
        assert!(Engine::new(policy).is_err());
    }
}
