use serde::{Deserialize, Deserializer, Serialize};

pub mod load;

// ============================================================ server.yaml

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ServerConfig {
    pub listen_address: String,
    pub listen_port: i32,
    pub ssl: SSLServer,
    pub logging: LoggingConfig,
    pub virtual_server: VirtualServerConfig,
    pub domain_server: DomainServerConfig,
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    #[serde(default)]
    pub geoip: GeoIpConfig,
    #[serde(default)]
    pub geoip_config_path: Option<String>,
    #[serde(default)]
    pub rate_limit_config_path: Option<String>,
    #[serde(default)]
    pub admin_api_token: String,
    #[serde(default)]
    pub error_pages: ErrorPagesConfig,
    #[serde(default)]
    pub admin_api: AdminApiConfig,
    #[serde(default)]
    pub otel: OtelConfig,
}

/// Optional OpenTelemetry (OTLP/HTTP) exporter configuration.
///
/// When `enabled` is true, novaflow exports traces and metrics to an OTLP
/// compatible backend (opentelemetry-collector, Jaeger, Tempo, Grafana...).
/// The tracer and meter are initialized once at startup, so changing this
/// section requires a restart.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OtelConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_otel_endpoint")]
    pub endpoint: String,
    #[serde(default = "default_otel_service_name")]
    pub service_name: String,
    #[serde(default = "default_otel_sample_ratio")]
    pub sample_ratio: f64,
}

impl Default for OtelConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: default_otel_endpoint(),
            service_name: default_otel_service_name(),
            sample_ratio: default_otel_sample_ratio(),
        }
    }
}

fn default_otel_endpoint() -> String {
    "http://localhost:4318".to_string()
}

fn default_otel_service_name() -> String {
    "novaflow".to_string()
}

fn default_otel_sample_ratio() -> f64 {
    1.0
}

/// Admin API listener configuration.
///
/// When `enabled` is true and a custom address/port is provided, the admin
/// API listens on its own socket. When enabled with empty address and port 0,
/// it shares the main WAF listener (backward-compatible default).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AdminApiConfig {
    #[serde(default = "default_admin_api_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub listen_address: String,
    #[serde(default)]
    pub listen_port: i32,
}

impl Default for AdminApiConfig {
    fn default() -> Self {
        Self {
            enabled: default_admin_api_enabled(),
            listen_address: String::new(),
            listen_port: 0,
        }
    }
}

fn default_admin_api_enabled() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct RateLimitConfig {
    pub enabled: bool,
    #[serde(default)]
    pub backend: RateLimitBackend,
    #[serde(default)]
    pub redis: RedisConfig,
    #[serde(default)]
    pub rules: Vec<RateLimitRule>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RateLimitBackend {
    Memory,
    Redis,
}

impl Default for RateLimitBackend {
    fn default() -> Self {
        RateLimitBackend::Memory
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct RedisConfig {
    pub url: String,
    #[serde(default = "default_redis_timeout_seconds")]
    pub timeout_seconds: u64,
    #[serde(default = "default_redis_connection_timeout_seconds")]
    pub connection_timeout_seconds: u64,
}

fn default_redis_timeout_seconds() -> u64 {
    2
}

fn default_redis_connection_timeout_seconds() -> u64 {
    5
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RateLimitRule {
    pub name: String,
    #[serde(default)]
    pub by: Vec<String>,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub requests_per_second: Option<u32>,
    #[serde(default)]
    pub requests_per_minute: Option<u32>,
    #[serde(default)]
    pub burst: Option<u32>,
    #[serde(default)]
    pub window_seconds: Option<u64>,
    #[serde(default)]
    pub anomaly_score: Option<u32>,
    #[serde(default = "default_rate_limit_action")]
    pub action: RateLimitAction,
    #[serde(default = "default_block_ttl_seconds")]
    pub block_ttl_seconds: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RateLimitAction {
    Alert,
    Block,
}

impl Default for RateLimitAction {
    fn default() -> Self {
        RateLimitAction::Block
    }
}

fn default_rate_limit_action() -> RateLimitAction {
    RateLimitAction::Block
}

fn default_block_ttl_seconds() -> u64 {
    600
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GeoIpMode {
    Blacklist,
    Whitelist,
}

impl Default for GeoIpMode {
    fn default() -> Self {
        GeoIpMode::Blacklist
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct GeoIpConfig {
    pub enabled: bool,
    pub database_path: String,
    #[serde(default = "default_geoip_cache_size")]
    pub cache_size: u64,
    #[serde(default = "default_geoip_cache_ttl_seconds")]
    pub cache_ttl_seconds: u64,
    #[serde(default)]
    pub mode: GeoIpMode,
    #[serde(default)]
    pub allow_countries: Vec<String>,
    #[serde(default)]
    pub block_countries: Vec<String>,
    #[serde(default)]
    pub allow_asns: Vec<u32>,
    #[serde(default)]
    pub block_asns: Vec<u32>,
    #[serde(default)]
    pub auto_download: AutoDownloadConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct AutoDownloadConfig {
    pub enabled: bool,
    pub url: String,
    #[serde(default)]
    pub license_key: String,
    #[serde(default)]
    pub output_path: String,
    #[serde(default = "default_refresh_days")]
    pub refresh_days: u64,
}

fn default_refresh_days() -> u64 {
    7
}

fn default_geoip_cache_size() -> u64 {
    100_000
}

fn default_geoip_cache_ttl_seconds() -> u64 {
    3600
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LoggingConfig {
    pub mode: String,
    pub trace_traffic: bool,
    pub file_path: String,
    pub file_name: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct VirtualServerConfig {
    pub enabled: bool,
    #[serde(default)]
    pub config: Vec<VirtualServer>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct DomainServerConfig {
    pub enabled: bool,
    #[serde(default)]
    pub config: Vec<DomainServer>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct VirtualServer {
    pub name: String,
    pub path: String,
    pub remote_address: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct DomainServer {
    pub name: String,
    pub domain_name: String,
    pub remote_address: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SSLServer {
    pub enabled: bool,
    pub ca_path: String,
    pub key_path: String,
}

/// Custom HTML error pages returned by NovaFlow itself.
///
/// Each field accepts raw HTML.  The strings `REPLACE_WITH_UUID_REQUESTS`
/// will be replaced with the request id where applicable.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ErrorPagesConfig {
    #[serde(default = "default_forbidden_html")]
    pub forbidden_html: String,
    #[serde(default = "default_not_found_html")]
    pub not_found_html: String,
    #[serde(default = "default_bad_gateway_html")]
    pub bad_gateway_html: String,
}

impl Default for ErrorPagesConfig {
    fn default() -> Self {
        Self {
            forbidden_html: default_forbidden_html(),
            not_found_html: default_not_found_html(),
            bad_gateway_html: default_bad_gateway_html(),
        }
    }
}

fn default_forbidden_html() -> String {
    crate::request::BLOCKED_REQUEST.to_string()
}

fn default_not_found_html() -> String {
    crate::request::NOT_FOUND.to_string()
}

fn default_bad_gateway_html() -> String {
    crate::request::BAD_GATEWAY.to_string()
}

// ============================================================ policy.yaml
//
// The ENTIRE detection algorithm is data-driven from this file:
// keyword/tag/command lists, per-item scores, the anomaly threshold and
// the operating mode. Nothing about detection is hardcoded in the binary;
// the built-in `Default` impls below only act as documentation/fallback.

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PolicyConfig {
    /// Global engine settings (mode + anomaly threshold).
    #[serde(default)]
    pub detection: DetectionConfig,
    /// Semantic rule families (SQLi, XSS, traversal, CMDi, RFI).
    #[serde(default)]
    pub rules: SemanticRulesConfig,
    /// Custom regex rules, evaluated on the normalized request and added
    /// to the anomaly score like any other detection.
    /// (`policy_block` from v1 configs is still accepted.)
    #[serde(default, alias = "policy_block")]
    pub custom_rules: Vec<CustomRule>,
}

/// `custom_rules` was previously called `policy_block`; both are accepted.
#[allow(dead_code)]
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CustomRule {
    #[serde(default)]
    pub policy_id: i32,
    pub name: String,
    /// Rust regex, applied to the *normalized* request values.
    pub pattern: String,
    #[serde(default)]
    pub option: RulesOptions,
    /// Score contributed when the pattern matches (default 5).
    #[serde(default = "default_rule_score")]
    pub score: u32,
}

fn default_rule_score() -> u32 {
    5
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct RulesOptions {
    #[serde(default)]
    pub header: bool,
    #[serde(default)]
    pub body: bool,
    #[serde(default)]
    pub uri: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Block requests whose anomaly score >= threshold (403).
    Block,
    /// Alert / monitoring mode: detections are logged but the request is
    /// never blocked, regardless of the anomaly threshold.
    Detect,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DetectionConfig {
    #[serde(default = "default_mode")]
    pub mode: Mode,
    /// CRS-style anomaly threshold: block when summed scores reach this.
    #[serde(default = "default_threshold")]
    pub anomaly_threshold: u32,
    /// Maximum request body (bytes) buffered for inspection.
    #[serde(default = "default_max_body")]
    pub max_body_bytes: usize,
}

fn default_mode() -> Mode {
    Mode::Block
}
fn default_threshold() -> u32 {
    5
}
fn default_max_body() -> usize {
    1_048_576
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            mode: default_mode(),
            anomaly_threshold: default_threshold(),
            max_body_bytes: default_max_body(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct SemanticRulesConfig {
    #[serde(default)]
    pub sqli: SqliRules,
    #[serde(default)]
    pub xss: XssRules,
    #[serde(default)]
    pub path_traversal: TraversalRules,
    #[serde(default)]
    pub command_injection: CommandRules,
    #[serde(default)]
    pub rfi: RfiRules,
}

fn enabled() -> bool {
    true
}

// ------------------------------------------------------------------ ScoredItem

/// An item that carries its own anomaly score.
///
/// Accepts either a plain string (uses the global default score of 5) or an
/// object `{ name, score }` for explicit per-item tuning.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ScoredItem {
    pub name: String,
    pub score: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum ScoredItemInput {
    String(String),
    Object {
        name: String,
        #[serde(default)]
        score: Option<u32>,
    },
}

impl ScoredItem {
    fn from_input(input: ScoredItemInput) -> Self {
        const DEFAULT_SCORE: u32 = 5;
        match input {
            ScoredItemInput::String(name) => Self {
                name,
                score: DEFAULT_SCORE,
            },
            ScoredItemInput::Object { name, score: None } => Self {
                name,
                score: DEFAULT_SCORE,
            },
            ScoredItemInput::Object {
                name,
                score: Some(s),
            } => Self { name, score: s },
        }
    }
}

fn deserialize_scored_items<'de, D>(deserializer: D) -> Result<Vec<ScoredItem>, D::Error>
where
    D: Deserializer<'de>,
{
    let inputs = Vec::<ScoredItemInput>::deserialize(deserializer)?;
    Ok(inputs.into_iter().map(ScoredItem::from_input).collect())
}

// ------------------------------------------------------------------ ScoredList

/// A scored rule list together with its policy ID.
///
/// Accepts either the explicit form `{ policy_id, items }` or the legacy
/// plain array `[ ... ]` for backward compatibility.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ScoredList {
    pub policy_id: i32,
    #[serde(default, deserialize_with = "deserialize_scored_items")]
    pub items: Vec<ScoredItem>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ScoredListInput {
    Legacy(Vec<ScoredItemInput>),
    Structured {
        #[serde(default)]
        policy_id: i32,
        #[serde(default, deserialize_with = "deserialize_scored_items")]
        items: Vec<ScoredItem>,
    },
}

fn deserialize_scored_list<'de, D, const DEFAULT_POLICY_ID: i32>(
    deserializer: D,
) -> Result<ScoredList, D::Error>
where
    D: Deserializer<'de>,
{
    match ScoredListInput::deserialize(deserializer)? {
        ScoredListInput::Legacy(inputs) => Ok(ScoredList {
            policy_id: DEFAULT_POLICY_ID,
            items: inputs.into_iter().map(ScoredItem::from_input).collect(),
        }),
        ScoredListInput::Structured { policy_id, items } => Ok(ScoredList {
            policy_id: if policy_id == 0 {
                DEFAULT_POLICY_ID
            } else {
                policy_id
            },
            items,
        }),
    }
}

// ------------------------------------------------------------------ SQLi

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SqliRules {
    #[serde(default = "enabled")]
    pub enabled: bool,
    /// Keywords watched for injection context (whole-word matching).
    #[serde(
        default = "default_sql_keywords",
        deserialize_with = "deserialize_scored_list::<_, 1009>"
    )]
    pub keywords: ScoredList,
    /// Function calls used for time/error-based probing.
    #[serde(
        default = "default_sql_functions",
        deserialize_with = "deserialize_scored_list::<_, 10010>"
    )]
    pub functions: ScoredList,
    /// Statement starters allowed after `;` (stacked-query detection).
    #[serde(
        default = "default_sql_stacked",
        deserialize_with = "deserialize_scored_list::<_, 10011>"
    )]
    pub stacked_starters: ScoredList,
    /// How many distinct keywords count as a "cluster".
    #[serde(default = "two")]
    pub cluster_min_keywords: usize,
}

fn default_sql_keywords() -> ScoredList {
    ScoredList {
        policy_id: 1009,
        items: [
            "select",
            "union",
            "insert",
            "update",
            "delete",
            "drop",
            "truncate",
            "alter",
            "exec",
            "execute",
            "declare",
            "from",
            "where",
            "information_schema",
            "group_concat",
            "load_file",
            "xp_cmdshell",
            "waitfor",
            "benchmark",
            "sleep",
            "having",
            "concat",
            "or",
            "and",
        ]
        .iter()
        .map(|s| ScoredItem {
            name: s.to_string(),
            score: 5,
        })
        .collect(),
    }
}

fn default_sql_functions() -> ScoredList {
    ScoredList {
        policy_id: 10010,
        items: [
            "sleep(",
            "benchmark(",
            "load_file(",
            "group_concat(",
            "database(",
            "version(",
            "user(",
            "@@version",
            "updatexml(",
            "extractvalue(",
            "floor(rand(",
        ]
        .iter()
        .map(|s| ScoredItem {
            name: s.to_string(),
            score: 5,
        })
        .collect(),
    }
}

fn default_sql_stacked() -> ScoredList {
    ScoredList {
        policy_id: 10011,
        items: [
            "select", "insert", "update", "delete", "drop", "exec", "declare", "truncate", "alter",
            "grant",
        ]
        .iter()
        .map(|s| ScoredItem {
            name: s.to_string(),
            score: 5,
        })
        .collect(),
    }
}

fn two() -> usize {
    2
}

impl Default for SqliRules {
    fn default() -> Self {
        Self {
            enabled: true,
            keywords: default_sql_keywords(),
            functions: default_sql_functions(),
            stacked_starters: default_sql_stacked(),
            cluster_min_keywords: two(),
        }
    }
}

// ------------------------------------------------------------------- XSS

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct XssRules {
    #[serde(default = "enabled")]
    pub enabled: bool,
    /// Tags that always indicate injection (<script>, <iframe>, ...).
    #[serde(
        default = "default_xss_tags",
        deserialize_with = "deserialize_scored_list::<_, 10020>"
    )]
    pub dangerous_tags: ScoredList,
    /// Tags that make an `on*=` attribute suspicious (<img onerror=...>).
    #[serde(
        default = "default_xss_event_tags",
        deserialize_with = "deserialize_scored_list::<_, 10021>"
    )]
    pub event_tags: ScoredList,
    /// DOM/JS primitives (document.cookie, eval(, alert(, ...).
    #[serde(
        default = "default_xss_js_primitives",
        deserialize_with = "deserialize_scored_list::<_, 10022>"
    )]
    pub js_primitives: ScoredList,
    /// Minimum letters after `on` to count as an event handler name.
    #[serde(default = "two")]
    pub event_min_len: usize,
}

fn default_xss_tags() -> ScoredList {
    ScoredList {
        policy_id: 10020,
        items: [
            "script", "iframe", "object", "embed", "svg", "math", "form", "meta", "link", "base",
        ]
        .iter()
        .map(|s| ScoredItem {
            name: s.to_string(),
            score: 5,
        })
        .collect(),
    }
}

fn default_xss_event_tags() -> ScoredList {
    ScoredList {
        policy_id: 10021,
        items: [
            "img", "svg", "body", "input", "details", "marquee", "video", "audio", "image",
            "select",
        ]
        .iter()
        .map(|s| ScoredItem {
            name: s.to_string(),
            score: 5,
        })
        .collect(),
    }
}

fn default_xss_js_primitives() -> ScoredList {
    ScoredList {
        policy_id: 10022,
        items: [
            "document.cookie",
            "document.write",
            "window.location",
            "eval(",
            "alert(",
            "prompt(",
            "confirm(",
            ".innerhtml",
            "fromcharcode",
        ]
        .iter()
        .map(|s| ScoredItem {
            name: s.to_string(),
            score: 5,
        })
        .collect(),
    }
}

impl Default for XssRules {
    fn default() -> Self {
        Self {
            enabled: true,
            dangerous_tags: default_xss_tags(),
            event_tags: default_xss_event_tags(),
            js_primitives: default_xss_js_primitives(),
            event_min_len: two(),
        }
    }
}

// ------------------------------------------------------- path traversal

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TraversalRules {
    #[serde(default = "enabled")]
    pub enabled: bool,
    #[serde(
        default = "default_traversal_sequences",
        deserialize_with = "deserialize_scored_list::<_, 10030>"
    )]
    pub sequences: ScoredList,
    #[serde(
        default = "default_sensitive_files",
        deserialize_with = "deserialize_scored_list::<_, 10031>"
    )]
    pub sensitive_files: ScoredList,
    #[serde(
        default = "default_php_wrappers",
        deserialize_with = "deserialize_scored_list::<_, 10032>"
    )]
    pub wrappers: ScoredList,
}

fn default_traversal_sequences() -> ScoredList {
    ScoredList {
        policy_id: 10030,
        items: ["../", "..\\", "..;/"]
            .iter()
            .map(|s| ScoredItem {
                name: s.to_string(),
                score: 5,
            })
            .collect(),
    }
}

fn default_sensitive_files() -> ScoredList {
    ScoredList {
        policy_id: 10031,
        items: [
            "etc/passwd",
            "etc/shadow",
            "etc/hosts",
            "proc/self",
            "proc/version",
            "boot.ini",
            "win.ini",
            "windows/system32",
            "web-inf/",
            ".ssh/",
            ".aws/credentials",
            ".env",
            "id_rsa",
        ]
        .iter()
        .map(|s| ScoredItem {
            name: s.to_string(),
            score: 5,
        })
        .collect(),
    }
}

fn default_php_wrappers() -> ScoredList {
    ScoredList {
        policy_id: 10032,
        items: [
            "php://",
            "file://",
            "expect://",
            "zip://",
            "phar://",
            "glob://",
            "data://",
        ]
        .iter()
        .map(|s| ScoredItem {
            name: s.to_string(),
            score: 5,
        })
        .collect(),
    }
}

impl Default for TraversalRules {
    fn default() -> Self {
        Self {
            enabled: true,
            sequences: default_traversal_sequences(),
            sensitive_files: default_sensitive_files(),
            wrappers: default_php_wrappers(),
        }
    }
}

// ------------------------------------------------------ command injection

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CommandRules {
    #[serde(default = "enabled")]
    pub enabled: bool,
    #[serde(
        default = "default_shell_commands",
        deserialize_with = "deserialize_scored_list::<_, 10040>"
    )]
    pub commands: ScoredList,
    /// Substrings that count as command substitution.
    #[serde(
        default = "default_substitutions",
        deserialize_with = "deserialize_scored_list::<_, 10041>"
    )]
    pub substitutions: ScoredList,
}

fn default_shell_commands() -> ScoredList {
    ScoredList {
        policy_id: 10040,
        items: [
            "whoami",
            "uname",
            "cat",
            "ls",
            "pwd",
            "id",
            "curl",
            "wget",
            "nc",
            "ncat",
            "netcat",
            "bash",
            "sh",
            "zsh",
            "cmd",
            "powershell",
            "ping",
            "nslookup",
            "chmod",
            "chown",
            "rm",
            "kill",
            "python",
            "python3",
            "perl",
            "ruby",
            "php",
            "telnet",
            "ftp",
            "scp",
            "base64",
        ]
        .iter()
        .map(|s| ScoredItem {
            name: s.to_string(),
            score: 5,
        })
        .collect(),
    }
}

fn default_substitutions() -> ScoredList {
    ScoredList {
        policy_id: 10041,
        items: ["$(", "`", "${"]
            .iter()
            .map(|s| ScoredItem {
                name: s.to_string(),
                score: 5,
            })
            .collect(),
    }
}

impl Default for CommandRules {
    fn default() -> Self {
        Self {
            enabled: true,
            commands: default_shell_commands(),
            substitutions: default_substitutions(),
        }
    }
}

// ------------------------------------------------------------------- RFI

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RfiRules {
    #[serde(default = "enabled")]
    pub enabled: bool,
    /// Parameter names that include files server-side (?page=, ?file=, ...).
    #[serde(
        default = "default_rfi_params",
        deserialize_with = "deserialize_scored_list::<_, 10050>"
    )]
    pub params: ScoredList,
    /// Schemes considered remote when used as parameter values.
    #[serde(
        default = "default_rfi_schemes",
        deserialize_with = "deserialize_scored_list::<_, 10051>"
    )]
    pub schemes: ScoredList,
}

fn default_rfi_params() -> ScoredList {
    ScoredList {
        policy_id: 10050,
        items: [
            "page", "file", "url", "path", "include", "inc", "doc", "document", "folder", "root",
            "pg", "style", "template", "php_path", "load", "src", "view", "content",
        ]
        .iter()
        .map(|s| ScoredItem {
            name: s.to_string(),
            score: 5,
        })
        .collect(),
    }
}

fn default_rfi_schemes() -> ScoredList {
    ScoredList {
        policy_id: 10051,
        items: ["http://", "https://", "ftp://"]
            .iter()
            .map(|s| ScoredItem {
                name: s.to_string(),
                score: 5,
            })
            .collect(),
    }
}

impl Default for RfiRules {
    fn default() -> Self {
        Self {
            enabled: true,
            params: default_rfi_params(),
            schemes: default_rfi_schemes(),
        }
    }
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            detection: DetectionConfig::default(),
            rules: SemanticRulesConfig::default(),
            custom_rules: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scored_item_accepts_string_form() {
        let yaml = r#"
            rules:
              sqli:
                enabled: true
                keywords:
                  - select
                  - union
                functions:
                  - "sleep("
                stacked_starters:
                  - select
                cluster_min_keywords: 2
        "#;
        let policy: PolicyConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(policy.rules.sqli.keywords.items.len(), 2);
        assert_eq!(policy.rules.sqli.keywords.items[0].name, "select");
        assert_eq!(policy.rules.sqli.keywords.items[0].score, 5);
        assert_eq!(policy.rules.sqli.functions.items[0].score, 5);
    }

    #[test]
    fn scored_item_accepts_object_form() {
        let yaml = r#"
            rules:
              sqli:
                enabled: true
                keywords:
                  - name: select
                    score: 2
                  - name: union
                    score: 3
                functions:
                  - name: "sleep("
                    score: 7
                stacked_starters:
                  - name: select
                    score: 4
                cluster_min_keywords: 2
        "#;
        let policy: PolicyConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(policy.rules.sqli.keywords.items[0].score, 2);
        assert_eq!(policy.rules.sqli.keywords.items[1].score, 3);
        assert_eq!(policy.rules.sqli.functions.items[0].score, 7);
        assert_eq!(policy.rules.sqli.stacked_starters.items[0].score, 4);
    }

    #[test]
    fn root_policy_yaml_loads() {
        let yaml = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/policy.yaml"));
        let policy: PolicyConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(policy.rules.xss.enabled);
        assert!(!policy.rules.sqli.keywords.items.is_empty());
        assert_eq!(policy.rules.sqli.keywords.items[0].score, 5);
    }
}
