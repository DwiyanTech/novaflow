
use http_body_util::Full;
use hyper::{
    body::Bytes,
    HeaderMap,  Response,
};

pub async fn convert_reqwest_to_hyper_response(
    reqwest_resp: reqwest::Response,
) -> Result<Response<Full<Bytes>>, Box<dyn std::error::Error>> {
    let status = reqwest_resp.status();

    // Convert reqwest headers to hyper headers
    let mut hyper_headers = HeaderMap::new();
    for (key, value) in reqwest_resp.headers().iter() {
        hyper_headers.insert(key.clone(), value.clone());
    }

    let bytes = reqwest_resp.bytes().await?;
    let response_builder = Response::builder().status(status);
    let mut hyper_resp = response_builder.body(Full::new(Bytes::from(bytes)))?;
    *hyper_resp.headers_mut() = hyper_headers; // Set headers in the response

    Ok(hyper_resp)
}