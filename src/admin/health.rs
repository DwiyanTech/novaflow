//! Health-check probes for upstream virtual-server and domain-server targets.

use std::time::{Duration, Instant};

use serde::Serialize;

use crate::config::{DomainServer, VirtualServer};

/// Per-upstream probe result.
#[derive(Debug, Serialize, Clone)]
pub struct ProbeResult {
    pub name: String,
    pub target: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u128>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl ProbeResult {
    fn ok(name: String, target: String, latency_ms: u128) -> Self {
        Self {
            name,
            target,
            status: "ok".into(),
            latency_ms: Some(latency_ms),
            error: None,
        }
    }

    fn error(name: String, target: String, err: String) -> Self {
        Self {
            name,
            target,
            status: "error".into(),
            latency_ms: None,
            error: Some(err),
        }
    }
}

/// Probe every configured upstream with a short HTTP HEAD request.
///
/// Any 2xx/3xx response counts as healthy. Connection errors or timeouts
/// (5 s) count as unhealthy. The function returns immediately when all
/// probes finish; slow upstreams do not block longer than the timeout.
pub async fn probe_all(
    virtual_servers: &[VirtualServer],
    domain_servers: &[DomainServer],
) -> (Vec<ProbeResult>, Vec<ProbeResult>) {
    let client = crate::proxy::client();
    let timeout = Duration::from_secs(5);

    let vs_futures: Vec<_> = virtual_servers
        .iter()
        .map(|vs| probe_one(client, timeout, vs.name.clone(), vs.remote_address.clone()))
        .collect();

    let ds_futures: Vec<_> = domain_servers
        .iter()
        .map(|ds| probe_one(client, timeout, ds.name.clone(), ds.remote_address.clone()))
        .collect();

    let vs = futures::future::join_all(vs_futures).await;
    let ds = futures::future::join_all(ds_futures).await;
    (vs, ds)
}

async fn probe_one(
    client: &reqwest::Client,
    timeout: Duration,
    name: String,
    target: String,
) -> ProbeResult {
    let start = Instant::now();
    let result = tokio::time::timeout(timeout, client.head(&target).send()).await;

    match result {
        Ok(Ok(resp)) => {
            let latency = start.elapsed().as_millis();
            if resp.status().is_success() || resp.status().is_redirection() {
                ProbeResult::ok(name, target, latency)
            } else {
                ProbeResult::error(name, target, format!("upstream returned {}", resp.status()))
            }
        }
        Ok(Err(err)) => ProbeResult::error(name, target, err.to_string()),
        Err(_) => ProbeResult::error(name, target, "probe timed out".into()),
    }
}
