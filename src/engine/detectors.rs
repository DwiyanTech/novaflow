//! Semantic attack detectors — 100% configuration-driven.
//!
//! Every keyword list, tag list, command list and per-item score below comes
//! from `policy.yaml` (`rules:` section); nothing is baked into the binary.
//! The heuristics follow the anomaly-scoring philosophy of OWASP CRS and
//! libinjection: a signal only scores high in an *attack context* (SQL
//! keyword + quote/comment/operator), which is what keeps false positives
//! low on prose like "select your size".

use crate::config::{CommandRules, RfiRules, ScoredItem, SqliRules, TraversalRules, XssRules};

use super::normalize;

/// A single detection event.
/// (`family`/`evidence` feed structured logging and future dashboards.)
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct Detection {
    /// Attack family: sqli | xss | path_traversal | command_injection | rfi | custom
    pub family: &'static str,
    /// Human-readable rule that fired.
    pub rule: String,
    /// CRS-style severity score (5=critical, 4=high, 3=medium, 2=low).
    pub score: u32,
    /// Truncated evidence for logging.
    pub evidence: String,
    /// Optional policy/rule ID for log tracing (semantic rules and custom rules).
    pub policy_id: i32,
}

fn evidence(s: &str) -> String {
    s.chars().take(80).collect()
}

fn max_score(items: &[ScoredItem]) -> u32 {
    items.iter().map(|i| i.score).max().unwrap_or(5)
}

fn sum_scores(items: &[ScoredItem]) -> u32 {
    items.iter().map(|i| i.score).sum()
}

// ------------------------------------------------------------------ SQLi

/// SQL injection heuristics. `norm` is the normalized+lowercased input.
pub fn detect_sqli(norm: &str, cfg: &SqliRules) -> Vec<Detection> {
    if !cfg.enabled {
        return Vec::new();
    }
    let mut out = Vec::new();
    let clean_lower = normalize::strip_sql_comments(norm).to_lowercase();

    let has_quote = norm.contains('\'') || norm.contains('"') || norm.contains('`');
    let has_comment = norm.contains("--") || norm.contains("/*") || norm.contains('#');
    let keyword_hits: Vec<ScoredItem> = cfg
        .keywords
        .items
        .iter()
        .filter(|kw| contains_word(&clean_lower, &kw.name))
        .cloned()
        .collect();

    // 1. UNION SELECT — near-certain attack. The two keywords must be
    // adjacent (allowing `ALL`/`DISTINCT` between), otherwise prose like
    // "union workers select new representative" would false-positive.
    let union = cfg.keywords.items.iter().find(|k| k.name == "union");
    let select = cfg.keywords.items.iter().find(|k| k.name == "select");
    if union.is_some() && select.is_some() && union_select_adjacent(&clean_lower) {
        out.push(Detection {
            family: "sqli",
            rule: "UNION SELECT statement".into(),
            score: union.unwrap().score + select.unwrap().score,
            evidence: evidence(norm),
            policy_id: cfg.keywords.policy_id,
        });
    }

    // 2. Tautologies: ' OR 1=1 / "AND 'a'='a
    if is_tautology(&clean_lower, has_quote) {
        let logic_score = cfg
            .keywords
            .items
            .iter()
            .filter(|k| k.name == "or" || k.name == "and")
            .map(|k| k.score)
            .max()
            .unwrap_or(5);
        out.push(Detection {
            family: "sqli",
            rule: "SQL tautology (OR/AND true condition)".into(),
            score: logic_score,
            evidence: evidence(norm),
            policy_id: cfg.keywords.policy_id,
        });
    }

    // 3. Stacked queries: ; SELECT/DROP/...
    if let Some(starter) = find_stacked_starter(&clean_lower, &cfg.stacked_starters.items) {
        out.push(Detection {
            family: "sqli",
            rule: "stacked SQL query".into(),
            score: starter.score,
            evidence: evidence(norm),
            policy_id: cfg.stacked_starters.policy_id,
        });
    }

    // 4. SQL comment sequence combined with quote or keyword
    if has_comment && (has_quote || !keyword_hits.is_empty()) {
        out.push(Detection {
            family: "sqli",
            rule: "SQL comment sequence in attack context".into(),
            score: max_score(&keyword_hits),
            evidence: evidence(norm),
            policy_id: cfg.keywords.policy_id,
        });
    }

    // 5. Quote immediately followed by SQL keyword: ' OR, " UNION
    if has_quote
        && !keyword_hits.is_empty()
        && quote_before_keyword(&clean_lower, &cfg.keywords.items)
    {
        out.push(Detection {
            family: "sqli",
            rule: "quote breaking into SQL keyword".into(),
            score: max_score(&keyword_hits),
            evidence: evidence(norm),
            policy_id: cfg.keywords.policy_id,
        });
    }

    // 6. Time-based / error-based function calls (needs context)
    if let Some(func) = cfg
        .functions
        .items
        .iter()
        .find(|f| clean_lower.contains(f.name.as_str()))
    {
        if has_quote || has_comment || !keyword_hits.is_empty() {
            out.push(Detection {
                family: "sqli",
                rule: "SQL probing function call".into(),
                score: func.score,
                evidence: evidence(norm),
                policy_id: cfg.functions.policy_id,
            });
        }
    }

    // 7. Keyword cluster — catches quote-less injection in numeric params.
    // Query assignments (`?q=...&from=...`) are stripped first so the `=`
    // of ordinary parameters doesn't count as a comparison operator.
    if keyword_hits.len() >= cfg.cluster_min_keywords
        && has_operator(&strip_param_assignments(&clean_lower))
    {
        out.push(Detection {
            family: "sqli",
            rule: format!(
                "SQL keyword cluster ({})",
                keyword_hits
                    .iter()
                    .map(|k| k.name.as_str())
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            score: sum_scores(&keyword_hits),
            evidence: evidence(norm),
            policy_id: cfg.keywords.policy_id,
        });
    }

    out
}

/// `union select` / `union all select` / `union distinct select` —
/// keywords adjacent (comments already stripped upstream).
fn union_select_adjacent(clean: &str) -> bool {
    let tokens: Vec<&str> = clean
        .split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .filter(|t| !t.is_empty())
        .collect();
    for w in tokens.windows(2) {
        if w[0] == "union" && w[1] == "select" {
            return true;
        }
    }
    for w in tokens.windows(3) {
        if w[0] == "union" && (w[1] == "all" || w[1] == "distinct") && w[2] == "select" {
            return true;
        }
    }
    false
}

/// `or 1=1`, `and 2>1`, `'or'a'='a`, etc.
fn is_tautology(clean: &str, has_quote: bool) -> bool {
    let tokens: Vec<&str> = clean
        .split(|c: char| !(c.is_alphanumeric() || c == '_' || c == '@'))
        .filter(|t| !t.is_empty())
        .collect();
    for w in tokens.windows(3) {
        let is_logic = w[0] == "or" || w[0] == "and";
        if !is_logic {
            continue;
        }
        // or 1 = 1  → tokens: or,1,1 (the '=' vanished in the split)
        // or 'a' = 'a' → tokens: or,a,a
        if w[1] == w[2] && (w[1].chars().next().is_some_and(|c| c.is_ascii_digit()) || has_quote) {
            return true;
        }
    }
    // `or 1 like 1` style
    for w in tokens.windows(4) {
        if (w[0] == "or" || w[0] == "and")
            && w[1].chars().all(|c| c.is_ascii_digit())
            && w[2] == "like"
        {
            return true;
        }
    }
    false
}

fn find_stacked_starter<'a>(clean: &str, starters: &'a [ScoredItem]) -> Option<&'a ScoredItem> {
    let mut idx = 0;
    while let Some(pos) = clean[idx..].find(';') {
        let abs = idx + pos;
        let rest = clean[abs + 1..].trim_start();
        if let Some(starter) = starters.iter().find(|s| rest.starts_with(s.name.as_str())) {
            return Some(starter);
        }
        idx = abs + 1;
        if idx >= clean.len() {
            break;
        }
    }
    None
}

fn quote_before_keyword(clean: &str, keywords: &[ScoredItem]) -> bool {
    for (i, b) in clean.bytes().enumerate() {
        if b == b'\'' || b == b'"' || b == b'`' {
            let rest = clean[i + 1..].trim_start();
            if keywords.iter().any(|kw| rest.starts_with(kw.name.as_str()))
                || rest.starts_with("or ")
                || rest.starts_with("and ")
            {
                return true;
            }
        }
    }
    false
}

/// Blank out `name=` at query-pair boundaries (start, `?` or `&`) so
/// ordinary parameter syntax is not mistaken for SQL comparison.
fn strip_param_assignments(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = bytes.to_vec();
    let mut i = 0;
    while i < bytes.len() {
        if i == 0 || bytes[i - 1] == b'?' || bytes[i - 1] == b'&' {
            let mut j = i;
            while j < bytes.len()
                && (bytes[j].is_ascii_alphanumeric()
                    || bytes[j] == b'_'
                    || bytes[j] == b'-'
                    || bytes[j] == b'.')
            {
                j += 1;
            }
            if j > i && j < bytes.len() && bytes[j] == b'=' {
                out[j] = b' ';
            }
            i = j;
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn has_operator(s: &str) -> bool {
    s.contains('=') || s.contains('<') || s.contains('>') || s.contains('\'') || s.contains('"')
}

/// Whole-word-ish containment: keyword bounded by non-alphanumerics.
fn contains_word(haystack: &str, needle: &str) -> bool {
    let nb = needle.as_bytes();
    let hb = haystack.as_bytes();
    if nb.is_empty() || nb.len() > hb.len() {
        return false;
    }
    let boundary = |c: u8| !(c.is_ascii_alphanumeric() || c == b'_');
    (0..=hb.len() - nb.len()).any(|i| {
        &hb[i..i + nb.len()] == nb
            && (i == 0 || boundary(hb[i - 1]))
            && (i + nb.len() == hb.len() || boundary(hb[i + nb.len()]))
    })
}

// ------------------------------------------------------------------- XSS

/// Cross-site scripting heuristics on normalized+lowercased input.
pub fn detect_xss(norm: &str, cfg: &XssRules) -> Vec<Detection> {
    if !cfg.enabled {
        return Vec::new();
    }
    let mut out = Vec::new();
    let has_tag_open = norm.contains('<');

    // 1. <script> tag, any spacing/casing
    if has_tag_open {
        if let Some(script) = cfg.dangerous_tags.items.iter().find(|t| t.name == "script") {
            if contains_after_lt(norm, "script") {
                out.push(Detection {
                    family: "xss",
                    rule: "<script> tag injection".into(),
                    score: script.score,
                    evidence: evidence(norm),
                    policy_id: cfg.dangerous_tags.policy_id,
                });
            }
        }
    }

    // 2. HTML tag carrying an on* event handler
    if has_tag_open && has_event_handler(norm, cfg) {
        out.push(Detection {
            family: "xss",
            rule: "HTML event handler injection (onerror=, onload=, ...)".into(),
            score: max_score(&cfg.event_tags.items),
            evidence: evidence(norm),
            policy_id: cfg.event_tags.policy_id,
        });
    }

    // 3. javascript:/vbscript: URI in an attribute context
    if (norm.contains("javascript:") || norm.contains("vbscript:"))
        && (norm.contains('=')
            || norm.contains('\'')
            || norm.contains('"')
            || norm.contains('(')
            || norm.contains('<'))
    {
        out.push(Detection {
            family: "xss",
            rule: "javascript:/vbscript: URI scheme".into(),
            score: max_score(&cfg.dangerous_tags.items),
            evidence: evidence(norm),
            policy_id: cfg.dangerous_tags.policy_id,
        });
    }

    // 4. Dangerous embedded tags
    if has_tag_open {
        if let Some(tag) = cfg
            .dangerous_tags
            .items
            .iter()
            .find(|t| contains_after_lt(norm, &t.name))
        {
            out.push(Detection {
                family: "xss",
                rule: "dangerous HTML tag injection".into(),
                score: tag.score,
                evidence: evidence(norm),
                policy_id: cfg.dangerous_tags.policy_id,
            });
        }
    }

    // 5. DOM / JS API abuse in an injection context
    if let Some(prim) = cfg
        .js_primitives
        .items
        .iter()
        .find(|d| norm.contains(d.name.as_str()))
    {
        if has_tag_open || norm.contains("javascript:") || norm.contains("on") {
            out.push(Detection {
                family: "xss",
                rule: "JavaScript execution primitive".into(),
                score: prim.score,
                evidence: evidence(norm),
                policy_id: cfg.js_primitives.policy_id,
            });
        }
    }

    out
}

/// `<tag` with optional whitespace/`/` between `<` and the tag name.
fn contains_after_lt(norm: &str, tag: &str) -> bool {
    let mut start = 0;
    while let Some(pos) = norm[start..].find('<') {
        let abs = start + pos + 1;
        let rest = norm[abs..].trim_start_matches([' ', '/', '\t', '\n']);
        if rest.starts_with(tag) {
            let after = rest.as_bytes().get(tag.len()).copied().unwrap_or(b' ');
            if !(after.is_ascii_alphanumeric() || after == b'_') {
                return true;
            }
        }
        start = abs;
    }
    false
}

fn has_event_handler(norm: &str, cfg: &XssRules) -> bool {
    // look for `on<word>=` inside a tag context
    let mut idx = 0;
    while let Some(pos) = norm[idx..].find("on") {
        let abs = idx + pos;
        let after = &norm[abs + 2..];
        let name_len = after
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric())
            .count();
        if name_len >= cfg.event_min_len {
            let rest = after[name_len..].trim_start();
            if rest.starts_with('=') {
                // require a tag-ish or attribute-ish context nearby to cut FP
                let before = &norm[..abs];
                if before.contains('<')
                    || cfg
                        .event_tags
                        .items
                        .iter()
                        .any(|t| before.contains(t.name.as_str()))
                    || before.trim_end().ends_with(['"', '\'', ' ', '/'])
                {
                    return true;
                }
            }
        }
        idx = abs + 2;
    }
    false
}

// ------------------------------------------------------- path traversal

pub fn detect_path_traversal(norm: &str, cfg: &TraversalRules) -> Vec<Detection> {
    if !cfg.enabled {
        return Vec::new();
    }
    let mut out = Vec::new();

    if let Some(seq) = cfg
        .sequences
        .items
        .iter()
        .find(|s| norm.contains(s.name.as_str()))
    {
        out.push(Detection {
            family: "path_traversal",
            rule: "directory traversal sequence (../)".into(),
            score: seq.score,
            evidence: evidence(norm),
            policy_id: cfg.sequences.policy_id,
        });
    }

    if let Some(f) = cfg
        .sensitive_files
        .items
        .iter()
        .find(|f| norm.contains(f.name.as_str()))
    {
        out.push(Detection {
            family: "path_traversal",
            rule: format!("sensitive file access ({})", f.name),
            score: f.score,
            evidence: evidence(norm),
            policy_id: cfg.sensitive_files.policy_id,
        });
    }

    if let Some(w) = cfg
        .wrappers
        .items
        .iter()
        .find(|w| norm.contains(w.name.as_str()))
    {
        out.push(Detection {
            family: "path_traversal",
            rule: format!("PHP stream wrapper ({})", w.name),
            score: w.score,
            evidence: evidence(norm),
            policy_id: cfg.wrappers.policy_id,
        });
    }

    out
}

// ------------------------------------------------------ command injection

pub fn detect_command_injection(norm: &str, cfg: &CommandRules) -> Vec<Detection> {
    if !cfg.enabled {
        return Vec::new();
    }
    let mut out = Vec::new();

    let has_metachar = norm.contains(';')
        || norm.contains('|')
        || norm.contains("&&")
        || norm.contains("||")
        || norm.contains('`')
        || norm.contains('\n')
        || cfg
            .substitutions
            .items
            .iter()
            .any(|s| norm.contains(s.name.as_str()));

    if !has_metachar {
        return out;
    }

    // Command word reachable from a metachar = classic injection.
    let tokens: Vec<&str> = norm
        .split(|c: char| !(c.is_alphanumeric() || c == '_' || c == '-' || c == '.'))
        .filter(|t| !t.is_empty())
        .collect();
    if let Some(cmd) = tokens
        .iter()
        .find(|t| cfg.commands.items.iter().any(|c| c.name == **t))
    {
        let scored = cfg.commands.items.iter().find(|c| c.name == *cmd).unwrap();
        out.push(Detection {
            family: "command_injection",
            rule: "shell command after shell metacharacter".into(),
            score: scored.score,
            evidence: evidence(norm),
            policy_id: cfg.commands.policy_id,
        });
    } else if let Some(sub) = cfg
        .substitutions
        .items
        .iter()
        .find(|s| norm.contains(s.name.as_str()))
    {
        // command substitution alone is already highly suspicious.
        out.push(Detection {
            family: "command_injection",
            rule: "command substitution ($() or backticks)".into(),
            score: sub.score,
            evidence: evidence(norm),
            policy_id: cfg.substitutions.policy_id,
        });
    }

    out
}

// ------------------------------------------------------------------- RFI

/// Remote file inclusion: `?page=http://evil.tld/shell.txt`.
pub fn detect_rfi(norm: &str, cfg: &RfiRules) -> Vec<Detection> {
    if !cfg.enabled {
        return Vec::new();
    }
    let mut out = Vec::new();
    for pair in norm.split(['&', '?']) {
        let Some((key, value)) = pair.split_once('=') else {
            continue;
        };
        let key_trim = key.trim();
        if let Some(param) = cfg.params.items.iter().find(|p| p.name == key_trim) {
            if let Some(scheme) = cfg
                .schemes
                .items
                .iter()
                .find(|s| value.starts_with(s.name.as_str()))
            {
                out.push(Detection {
                    family: "rfi",
                    rule: format!("remote file inclusion via `{}` parameter", key_trim),
                    score: param.score.max(scheme.score),
                    evidence: evidence(norm),
                    policy_id: cfg.params.policy_id,
                });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CommandRules, RfiRules, SqliRules, TraversalRules, XssRules};

    fn sqli(raw: &str) -> Vec<Detection> {
        detect_sqli(
            &normalize::fold(&normalize::normalize(raw)),
            &SqliRules::default(),
        )
    }
    fn xss(raw: &str) -> Vec<Detection> {
        detect_xss(
            &normalize::fold(&normalize::normalize(raw)),
            &XssRules::default(),
        )
    }
    fn trav(raw: &str) -> Vec<Detection> {
        detect_path_traversal(
            &normalize::fold(&normalize::normalize(raw)),
            &TraversalRules::default(),
        )
    }
    fn cmdi(raw: &str) -> Vec<Detection> {
        detect_command_injection(
            &normalize::fold(&normalize::normalize(raw)),
            &CommandRules::default(),
        )
    }
    fn rfi(raw: &str) -> Vec<Detection> {
        detect_rfi(
            &normalize::fold(&normalize::normalize(raw)),
            &RfiRules::default(),
        )
    }

    #[test]
    fn catches_encoded_union_select() {
        assert!(!sqli("?id=1%20UNION%20SELECT%20user,password%20FROM%20users").is_empty());
        assert!(!sqli("?id=1%2520union%2520select").is_empty());
    }

    #[test]
    fn catches_tautologies() {
        assert!(!sqli("' OR '1'='1").is_empty());
        assert!(!sqli("1 or 1=1--").is_empty());
        assert!(!sqli("admin'--").is_empty());
    }

    #[test]
    fn catches_comment_stuffing() {
        assert!(!sqli("1' UN/**/ION SEL/**/ECT password FROM users--").is_empty());
    }

    #[test]
    fn catches_time_based() {
        assert!(!sqli("1' AND SLEEP(5)--").is_empty());
    }

    #[test]
    fn benign_prose_is_not_sqli() {
        assert!(sqli("?q=please select your size and update preferences").is_empty());
        assert!(sqli("?title=Union workers select new representative").is_empty());
        assert!(sqli("?delete=0&from=cart").is_empty());
    }

    #[test]
    fn catches_xss_variants() {
        assert!(!xss("<script>alert(1)</script>").is_empty());
        assert!(!xss("%3Cscript%3Ealert(1)%3C/script%3E").is_empty());
        assert!(!xss("<img src=x onerror=alert(1)>").is_empty());
        assert!(!xss("<svg/onload=alert(1)>").is_empty());
        assert!(!xss("&lt;script&gt;alert(1)&lt;/script&gt;").is_empty());
        assert!(!xss("\"><a href=javascript:alert(1)>x</a>").is_empty());
    }

    #[test]
    fn benign_prose_is_not_xss() {
        assert!(xss("?q=how to write a script for a movie").is_empty());
        assert!(xss("?text=turn on notifications").is_empty());
        assert!(xss("?review=1 < 2 and 3 > 2").is_empty());
    }

    #[test]
    fn catches_traversal() {
        assert!(!trav("../../etc/passwd").is_empty());
        assert!(!trav("..%2f..%2fetc%2fpasswd").is_empty());
        assert!(trav("/docs/readme.txt").is_empty());
    }

    #[test]
    fn catches_cmdi() {
        assert!(!cmdi("127.0.0.1; cat /etc/passwd").is_empty());
        assert!(!cmdi("$(whoami)").is_empty());
        assert!(!cmdi("`id`").is_empty());
        assert!(cmdi("hello world").is_empty());
    }

    #[test]
    fn catches_rfi() {
        assert!(!rfi("?page=http://evil.example/shell.txt").is_empty());
        assert!(rfi("?redirect=http://example.com").is_empty()); // not an include-ish param
    }

    #[test]
    fn per_item_scores_flow_through() {
        let mut cfg = SqliRules::default();
        cfg.keywords.items = vec![
            ScoredItem {
                name: "union".into(),
                score: 7,
            },
            ScoredItem {
                name: "select".into(),
                score: 3,
            },
        ];
        let d = detect_sqli(
            &normalize::fold(&normalize::normalize("?id=1 union select a,b")),
            &cfg,
        );
        assert!(!d.is_empty());
        assert_eq!(d[0].score, 10);
    }

    #[test]
    fn disabling_a_family_silences_it() {
        let cfg = SqliRules {
            enabled: false,
            ..Default::default()
        };
        assert!(
            detect_sqli(&normalize::fold(&normalize::normalize("' OR 1=1--")), &cfg).is_empty()
        );
    }
}
