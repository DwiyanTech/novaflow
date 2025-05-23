
use hyper::{body::Bytes, HeaderMap, Method};



pub mod handler;
pub mod filter;


#[derive(Clone,Debug)]
pub struct RequestData {
    pub body: Bytes,
    pub headers : HeaderMap,
    pub uri : String,
    pub method : Method,
    pub host : String


}


#[derive(Clone)]
// An Executor that uses the tokio runtime.
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


pub static BLOCKED_REQUEST : &str = r#"

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>Your Request has blocked, please contact your administrator if this marked as false positive RequestID : REPLACE_WITH_UUID_REQUESTS</p>
<hr>
<address>Powered by <a href="https://github.com/DwiyanTech/novaflow">Novaflow</a></address>
</body></html>

"#;


pub static  BAD_GATEWAY : &str = r#"
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>503 Bad Gateway</title>
</head><body>
<h1>Bad Gateway</h1>
<p>The 502 (Bad Gateway) status code indicates that the server, while acting as a gateway or proxy, received an invalid response from an inbound server it accessed while attempting to fulfill the request, RequestID : REPLACE_WITH_UUID_REQUESTS</p>
<hr>
<address>Powered by <a href="https://github.com/DwiyanTech/novaflow">Novaflow</a></address>
</body></html>

"#;


pub static  NOT_FOUND : &str = r#"

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