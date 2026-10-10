//! Shared upstream proxy client.
//!
//! The old code built a fresh `reqwest::Client` per request — no connection
//! reuse, TLS handshake per request. One lazily-initialized client is now
//! shared by every upstream call.

use std::sync::OnceLock;

use reqwest::Client;

static CLIENT: OnceLock<Client> = OnceLock::new();

pub fn client() -> &'static Client {
    CLIENT.get_or_init(|| {
        Client::builder()
            .pool_max_idle_per_host(64)
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none()) // pass 3xx through, don't follow
            .build()
            .expect("failed to build upstream HTTP client")
    })
}
