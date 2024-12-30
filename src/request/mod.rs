
use hyper::{body::Bytes, HeaderMap, Method};



pub mod handler;
pub mod filter;


#[derive(Clone)]
pub struct RequestData {
    body: Bytes,
    headers : HeaderMap,
    uri : String,
    method : Method

}


static RULES_N_A : &str = "N/A";
pub static  BLOCKED_REQUEST : &str = r#"

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>Your Request has blocked, please contact your administrator if this marked as false positive</p>
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
<p>The 502 (Bad Gateway) status code indicates that the server, while acting as a gateway or proxy, received an invalid response from an inbound server it accessed while attempting to fulfill the request</p>
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