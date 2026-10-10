use hyper::{body::Bytes, HeaderMap, Method};

use crate::config::ServerConfig;

pub mod handler;

#[derive(Clone, Debug)]
pub struct RequestData {
    pub body: Bytes,
    /// Original request body size in bytes before inspection caps.
    pub body_bytes: usize,
    pub headers: HeaderMap,
    /// Path only (no query string).
    pub uri: String,
    /// Raw query string, e.g. `id=1&name=x`.
    pub query: Option<String>,
    pub method: Method,
    /// Host from the **Host header** (the old code read uri.host(), which
    /// is empty for origin-form requests — breaking domain routing).
    pub host: String,
}

#[derive(Clone)]
/// An Executor that uses the tokio runtime.
pub struct TokioExecutor;

impl<F> hyper::rt::Executor<F> for TokioExecutor
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn execute(&self, fut: F) {
        tokio::task::spawn(fut);
    }
}

pub static BLOCKED_REQUEST: &str = r#"

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>Your request was blocked by the Novaflow WAF. Contact your administrator if you believe this is a false positive. RequestID : REPLACE_WITH_UUID_REQUESTS</p>
<hr>
<address>Powered by <a href="https://github.com/DwiyanTech/novaflow">Novaflow</a></address>
</body></html>

"#;

pub static BAD_GATEWAY: &str = r#"
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>502 Bad Gateway</title>
</head><body>
<h1>Bad Gateway</h1>
<p>The WAF received an invalid response from the upstream server. RequestID : REPLACE_WITH_UUID_REQUESTS</p>
<hr>
<address>Powered by <a href="https://github.com/DwiyanTech/novaflow">Novaflow</a></address>
</body></html>

"#;

pub static NOT_FOUND: &str = r#"

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Powered by <a href="https://github.com/DwiyanTech/novaflow">Novaflow</a></address>
</body></html>

"#;

/// Return the configured 403 Forbidden page, substituting the request id.
pub fn forbidden_page(config: &ServerConfig, request_id: &str) -> String {
    config
        .error_pages
        .forbidden_html
        .replace("REPLACE_WITH_UUID_REQUESTS", request_id)
}

/// Return the configured 404 Not Found page.
pub fn not_found_page(config: &ServerConfig) -> String {
    config.error_pages.not_found_html.clone()
}

/// Return the configured 502 Bad Gateway page, substituting the request id.
pub fn bad_gateway_page(config: &ServerConfig, request_id: &str) -> String {
    config
        .error_pages
        .bad_gateway_html
        .replace("REPLACE_WITH_UUID_REQUESTS", request_id)
}
