//! Rate limiting with pluggable backends (memory or Redis).
//!
//! Supports two rule types:
//!   - Token bucket (requests per second / minute)
//!   - Sliding-window anomaly score sum
//!
//! Actions:
//!   - alert: log the violation, allow the request
//!   - block: log the violation, return 403, and cache the block for TTL

use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use moka::future::Cache;

use crate::config::{
    RateLimitAction, RateLimitBackend, RateLimitConfig, RateLimitRule, RedisConfig,
};
use crate::geoip::GeoIpInfo;
use crate::request::RequestData;

// ------------------------------------------------------------------ public types

/// Decision returned by the rate limiter for a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Alert { rule: String, reason: String },
    Block { rule: String, reason: String },
}

impl Decision {
    pub fn rule_name(&self) -> Option<&str> {
        match self {
            Decision::Allow => None,
            Decision::Alert { rule, .. } | Decision::Block { rule, .. } => Some(rule),
        }
    }
}

// ------------------------------------------------------------------ storage trait

/// Async storage backend for rate-limit counters and blocks.
#[async_trait]
pub trait Store: Send + Sync + 'static {
    /// Try to consume `amount` tokens from a bucket. Returns `true` if allowed.
    async fn check_token_bucket(
        &self,
        key: &str,
        capacity: u32,
        refill_per_second: f64,
        amount: u32,
    ) -> Result<bool>;

    /// Increment a sliding-window counter and return the new total.
    async fn increment_window(&self, key: &str, window_seconds: u64, amount: u32) -> Result<u32>;

    /// Is this key currently blocked?
    async fn is_blocked(&self, key: &str) -> Result<bool>;

    /// Block this key for `ttl_seconds`.
    async fn block(&self, key: &str, ttl_seconds: u64) -> Result<()>;

    /// List currently blocked keys with remaining TTL in seconds.
    async fn blocked_entries(&self) -> Result<Vec<(String, u64)>>;
}

// ------------------------------------------------------------------ memory backend

#[derive(Clone)]
struct BucketState {
    tokens: f64,
    last_update_ms: u64,
}

#[derive(Clone)]
struct WindowState {
    count: u32,
    window_start_ms: u64,
}

#[derive(Clone)]
struct BlockState {
    expires_at_ms: u64,
}

/// In-memory store backed by `moka` caches with lazy TTL checks.
pub struct MemoryStore {
    buckets: Cache<String, BucketState>,
    windows: Cache<String, WindowState>,
    blocks: Cache<String, BlockState>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self {
            buckets: Cache::builder().build(),
            windows: Cache::builder().build(),
            blocks: Cache::builder().build(),
        }
    }

    fn now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }
}

#[async_trait]
impl Store for MemoryStore {
    async fn check_token_bucket(
        &self,
        key: &str,
        capacity: u32,
        refill_per_second: f64,
        amount: u32,
    ) -> Result<bool> {
        let capacity = capacity as f64;
        let amount = amount as f64;
        let now = Self::now_ms();

        let current = self.buckets.get(key).await.unwrap_or(BucketState {
            tokens: capacity,
            last_update_ms: now,
        });

        let elapsed_sec = (now.saturating_sub(current.last_update_ms)) as f64 / 1000.0;
        let tokens = (current.tokens + elapsed_sec * refill_per_second).min(capacity);

        let allowed = tokens >= amount;
        let new_tokens = if allowed { tokens - amount } else { tokens };

        self.buckets
            .insert(
                key.to_string(),
                BucketState {
                    tokens: new_tokens,
                    last_update_ms: now,
                },
            )
            .await;

        Ok(allowed)
    }

    async fn increment_window(&self, key: &str, window_seconds: u64, amount: u32) -> Result<u32> {
        let window_ms = window_seconds * 1000;
        let now = Self::now_ms();

        let current = self.windows.get(key).await.unwrap_or(WindowState {
            count: 0,
            window_start_ms: now,
        });

        let (new_count, new_start) = if now.saturating_sub(current.window_start_ms) > window_ms {
            (amount, now)
        } else {
            (
                current.count.saturating_add(amount),
                current.window_start_ms,
            )
        };

        self.windows
            .insert(
                key.to_string(),
                WindowState {
                    count: new_count,
                    window_start_ms: new_start,
                },
            )
            .await;

        Ok(new_count)
    }

    async fn is_blocked(&self, key: &str) -> Result<bool> {
        let now = Self::now_ms();
        if let Some(state) = self.blocks.get(key).await {
            if state.expires_at_ms > now {
                return Ok(true);
            }
            // Expired; remove lazily.
            self.blocks.remove(key).await;
        }
        Ok(false)
    }

    async fn block(&self, key: &str, ttl_seconds: u64) -> Result<()> {
        let expires_at_ms = Self::now_ms() + ttl_seconds * 1000;
        self.blocks
            .insert(key.to_string(), BlockState { expires_at_ms })
            .await;
        Ok(())
    }

    async fn blocked_entries(&self) -> Result<Vec<(String, u64)>> {
        let now = Self::now_ms();
        let mut entries = Vec::new();
        for (key, state) in self.blocks.iter() {
            if state.expires_at_ms > now {
                let ttl = (state.expires_at_ms - now).div_ceil(1000).max(1);
                entries.push(((*key).clone(), ttl));
            }
        }
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(entries)
    }
}

// ------------------------------------------------------------------ redis backend

pub struct RedisStore {
    client: redis::Client,
    timeout: std::time::Duration,
}

impl RedisStore {
    pub async fn new(cfg: &RedisConfig) -> Result<Self> {
        let client = redis::Client::open(cfg.url.clone())?;

        let mut conn = tokio::time::timeout(
            std::time::Duration::from_secs(cfg.connection_timeout_seconds),
            client.get_multiplexed_async_connection(),
        )
        .await
        .map_err(|_| anyhow!("redis connection timeout"))?
        .map_err(|e| anyhow!("redis connection failed: {e}"))?;

        let _: () = tokio::time::timeout(
            std::time::Duration::from_secs(cfg.timeout_seconds),
            redis::cmd("PING").query_async::<()>(&mut conn),
        )
        .await
        .map_err(|_| anyhow!("redis ping timeout"))??;

        Ok(Self {
            client,
            timeout: std::time::Duration::from_secs(cfg.timeout_seconds),
        })
    }

    async fn conn(&self) -> Result<redis::aio::MultiplexedConnection> {
        Ok(
            tokio::time::timeout(self.timeout, self.client.get_multiplexed_async_connection())
                .await
                .map_err(|_| anyhow!("redis connection timeout"))??,
        )
    }
}

#[async_trait]
impl Store for RedisStore {
    async fn check_token_bucket(
        &self,
        key: &str,
        capacity: u32,
        refill_per_second: f64,
        amount: u32,
    ) -> Result<bool> {
        let mut conn = self.conn().await?;
        let script = redis::Script::new(
            r#"
            local key = KEYS[1]
            local capacity = tonumber(ARGV[1])
            local refill = tonumber(ARGV[2])
            local amount = tonumber(ARGV[3])
            local now = tonumber(ARGV[4])

            local data = redis.call('HMGET', key, 'tokens', 'last_update')
            local tokens = tonumber(data[1]) or capacity
            local last_update = tonumber(data[2]) or now

            local elapsed = math.max(0, now - last_update) / 1000.0
            tokens = math.min(capacity, tokens + elapsed * refill)

            if tokens < amount then
                redis.call('HSET', key, 'tokens', tokens, 'last_update', now)
                redis.call('EXPIRE', key, 3600)
                return 0
            end

            tokens = tokens - amount
            redis.call('HSET', key, 'tokens', tokens, 'last_update', now)
            redis.call('EXPIRE', key, 3600)
            return 1
            "#,
        );

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let allowed: i32 = tokio::time::timeout(
            self.timeout,
            script
                .key(key)
                .arg(capacity)
                .arg(refill_per_second)
                .arg(amount)
                .arg(now)
                .invoke_async(&mut conn),
        )
        .await
        .map_err(|_| anyhow!("redis token bucket timeout"))??;

        Ok(allowed == 1)
    }

    async fn increment_window(&self, key: &str, window_seconds: u64, amount: u32) -> Result<u32> {
        let mut conn = self.conn().await?;
        // Approximate sliding window with a simple counter + TTL.
        // A true sliding window would need a sorted set of timestamps.
        let count: u32 = tokio::time::timeout(
            self.timeout,
            redis::cmd("INCRBY")
                .arg(key)
                .arg(amount)
                .query_async::<u32>(&mut conn),
        )
        .await
        .map_err(|_| anyhow!("redis window increment timeout"))??;

        let _ = tokio::time::timeout(
            self.timeout,
            redis::cmd("EXPIRE")
                .arg(key)
                .arg(window_seconds)
                .query_async::<()>(&mut conn),
        )
        .await;

        Ok(count)
    }

    async fn is_blocked(&self, key: &str) -> Result<bool> {
        let mut conn = self.conn().await?;
        let exists: bool = tokio::time::timeout(
            self.timeout,
            redis::cmd("EXISTS").arg(key).query_async::<i32>(&mut conn),
        )
        .await
        .map_err(|_| anyhow!("redis block check timeout"))??
            > 0;
        Ok(exists)
    }

    async fn block(&self, key: &str, ttl_seconds: u64) -> Result<()> {
        let mut conn = self.conn().await?;
        let _ = tokio::time::timeout(
            self.timeout,
            redis::cmd("SETEX")
                .arg(key)
                .arg(ttl_seconds)
                .arg(1)
                .query_async::<()>(&mut conn),
        )
        .await
        .map_err(|_| anyhow!("redis block timeout"))?;
        Ok(())
    }

    async fn blocked_entries(&self) -> Result<Vec<(String, u64)>> {
        let mut conn = self.conn().await?;
        let mut entries = Vec::new();
        let mut cursor: Option<u64> = None;

        loop {
            let (next_cursor, keys): (u64, Vec<String>) = tokio::time::timeout(
                self.timeout,
                redis::cmd("SCAN")
                    .arg(cursor.unwrap_or(0))
                    .arg("MATCH")
                    .arg("ratelimit:*")
                    .arg("COUNT")
                    .arg(100)
                    .query_async(&mut conn),
            )
            .await
            .map_err(|_| anyhow!("redis scan timeout"))??;

            for key in keys {
                let ttl: i64 = tokio::time::timeout(
                    self.timeout,
                    redis::cmd("TTL").arg(&key).query_async(&mut conn),
                )
                .await
                .map_err(|_| anyhow!("redis ttl timeout"))??;
                if ttl > 0 {
                    entries.push((key, ttl as u64));
                }
            }

            if next_cursor == 0 {
                break;
            }
            cursor = Some(next_cursor);
        }

        entries.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(entries)
    }
}

// ------------------------------------------------------------------ limiter

pub struct RateLimiter {
    store: Arc<dyn Store>,
    rules: Vec<RateLimitRule>,
}

impl RateLimiter {
    pub async fn new(config: &RateLimitConfig) -> Result<Self> {
        let store: Arc<dyn Store> = match config.backend {
            RateLimitBackend::Memory => Arc::new(MemoryStore::new()),
            RateLimitBackend::Redis => {
                let store = RedisStore::new(&config.redis).await?;
                Arc::new(store)
            }
        };

        Ok(Self {
            store,
            rules: config.rules.clone(),
        })
    }

    pub async fn blocked_entries(&self) -> Result<Vec<(String, u64)>> {
        self.store.blocked_entries().await
    }

    pub async fn check(
        &self,
        remote_addr: std::net::IpAddr,
        req: &RequestData,
        anomaly_score: u32,
        geo: &GeoIpInfo,
    ) -> Decision {
        // First check blocklist for any rule key that applies.
        for rule in &self.rules {
            if !rule.paths.is_empty() && !rule.paths.iter().any(|p| req.uri.starts_with(p)) {
                continue;
            }

            let key = build_key(rule, remote_addr, req, geo);

            if let Ok(true) = self.store.is_blocked(&key).await {
                return Decision::Block {
                    rule: rule.name.clone(),
                    reason: "previously blocked, TTL not expired".into(),
                };
            }
        }

        // Then evaluate rules.
        for rule in &self.rules {
            if !rule.paths.is_empty() && !rule.paths.iter().any(|p| req.uri.starts_with(p)) {
                continue;
            }

            let key = build_key(rule, remote_addr, req, geo);

            // Token-bucket rule.
            if let Some(rps) = rule.requests_per_second {
                let burst = rule.burst.unwrap_or(rps);
                match self
                    .store
                    .check_token_bucket(&key, burst, rps as f64, 1)
                    .await
                {
                    Ok(false) => {
                        return self.violation(rule, &key).await;
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "rate limit store error; allowing request");
                    }
                    _ => {}
                }
            }

            if let Some(rpm) = rule.requests_per_minute {
                let rps = rpm as f64 / 60.0;
                let burst = rule.burst.unwrap_or(rpm);
                match self.store.check_token_bucket(&key, burst, rps, 1).await {
                    Ok(false) => {
                        return self.violation(rule, &key).await;
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "rate limit store error; allowing request");
                    }
                    _ => {}
                }
            }

            // Anomaly-score sliding-window rule.
            if let (Some(window), Some(threshold)) = (rule.window_seconds, rule.anomaly_score) {
                match self
                    .store
                    .increment_window(&key, window, anomaly_score)
                    .await
                {
                    Ok(count) if count > threshold => {
                        return self.violation(rule, &key).await;
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "rate limit store error; allowing request");
                    }
                    _ => {}
                }
            }
        }

        Decision::Allow
    }

    async fn violation(&self, rule: &RateLimitRule, key: &str) -> Decision {
        if rule.action == RateLimitAction::Block {
            if let Err(e) = self.store.block(key, rule.block_ttl_seconds).await {
                tracing::warn!(error = %e, "failed to persist rate-limit block");
            }
            Decision::Block {
                rule: rule.name.clone(),
                reason: format!("rate limit exceeded (key: {key})"),
            }
        } else {
            Decision::Alert {
                rule: rule.name.clone(),
                reason: format!("rate limit exceeded (key: {key})"),
            }
        }
    }
}

fn build_key(
    rule: &RateLimitRule,
    remote_addr: std::net::IpAddr,
    req: &RequestData,
    geo: &GeoIpInfo,
) -> String {
    let mut parts = vec!["ratelimit".to_string(), rule.name.clone()];
    for by in &rule.by {
        match by.as_str() {
            "ip" => parts.push(remote_addr.to_string()),
            "path" => parts.push(req.uri.clone()),
            "host" => parts.push(req.host.clone()),
            "country" => parts.push(geo.country_code.clone().unwrap_or_default()),
            "asn" => parts.push(geo.asn.map(|n| n.to_string()).unwrap_or_default()),
            _ => parts.push(by.clone()),
        }
    }
    parts.join(":")
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use hyper::{body::Bytes, HeaderMap, Method};

    use super::*;
    use crate::request::RequestData;

    fn req(uri: &str) -> RequestData {
        RequestData {
            body: Bytes::new(),
            body_bytes: 0,
            headers: HeaderMap::new(),
            uri: uri.to_string(),
            query: None,
            method: Method::GET,
            host: "example.com".to_string(),
        }
    }

    #[tokio::test]
    async fn token_bucket_allows_under_limit() {
        let store = Arc::new(MemoryStore::new());
        let limiter = RateLimiter {
            store,
            rules: vec![RateLimitRule {
                name: "test".into(),
                by: vec!["ip".into()],
                paths: vec![],
                requests_per_second: Some(10),
                requests_per_minute: None,
                burst: Some(5),
                window_seconds: None,
                anomaly_score: None,
                action: RateLimitAction::Block,
                block_ttl_seconds: 1,
            }],
        };

        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let geo = GeoIpInfo::default();
        for _ in 0..5 {
            assert_eq!(limiter.check(ip, &req("/"), 0, &geo).await, Decision::Allow);
        }
    }

    #[tokio::test]
    async fn token_bucket_blocks_over_limit() {
        let store = Arc::new(MemoryStore::new());
        let limiter = RateLimiter {
            store,
            rules: vec![RateLimitRule {
                name: "test".into(),
                by: vec!["ip".into()],
                paths: vec![],
                requests_per_second: Some(10),
                requests_per_minute: None,
                burst: Some(2),
                window_seconds: None,
                anomaly_score: None,
                action: RateLimitAction::Block,
                block_ttl_seconds: 1,
            }],
        };

        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let geo = GeoIpInfo::default();
        assert_eq!(limiter.check(ip, &req("/"), 0, &geo).await, Decision::Allow);
        assert_eq!(limiter.check(ip, &req("/"), 0, &geo).await, Decision::Allow);
        let third = limiter.check(ip, &req("/"), 0, &geo).await;
        assert!(matches!(third, Decision::Block { .. }));
    }

    #[tokio::test]
    async fn alert_action_does_not_block() {
        let store = Arc::new(MemoryStore::new());
        let limiter = RateLimiter {
            store,
            rules: vec![RateLimitRule {
                name: "test".into(),
                by: vec!["ip".into()],
                paths: vec![],
                requests_per_second: Some(10),
                requests_per_minute: None,
                burst: Some(1),
                window_seconds: None,
                anomaly_score: None,
                action: RateLimitAction::Alert,
                block_ttl_seconds: 1,
            }],
        };

        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let geo = GeoIpInfo::default();
        assert_eq!(limiter.check(ip, &req("/"), 0, &geo).await, Decision::Allow);
        let second = limiter.check(ip, &req("/"), 0, &geo).await;
        assert!(matches!(second, Decision::Alert { .. }));
    }

    #[tokio::test]
    async fn anomaly_window_blocks_when_threshold_exceeded() {
        let store = Arc::new(MemoryStore::new());
        let limiter = RateLimiter {
            store,
            rules: vec![RateLimitRule {
                name: "scan".into(),
                by: vec!["ip".into()],
                paths: vec![],
                requests_per_second: None,
                requests_per_minute: None,
                burst: None,
                window_seconds: Some(60),
                anomaly_score: Some(5),
                action: RateLimitAction::Block,
                block_ttl_seconds: 1,
            }],
        };

        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let geo = GeoIpInfo::default();
        assert_eq!(limiter.check(ip, &req("/"), 3, &geo).await, Decision::Allow);
        let second = limiter.check(ip, &req("/"), 3, &geo).await;
        assert!(matches!(second, Decision::Block { .. }));
    }

    #[tokio::test]
    async fn block_ttl_releases_after_timeout() {
        let store = Arc::new(MemoryStore::new());
        let limiter = RateLimiter {
            store,
            rules: vec![RateLimitRule {
                name: "test".into(),
                by: vec!["ip".into()],
                paths: vec![],
                requests_per_second: Some(10),
                requests_per_minute: None,
                burst: Some(1),
                window_seconds: None,
                anomaly_score: None,
                action: RateLimitAction::Block,
                block_ttl_seconds: 1,
            }],
        };

        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let geo = GeoIpInfo::default();
        limiter.check(ip, &req("/"), 0, &geo).await;
        let blocked = limiter.check(ip, &req("/"), 0, &geo).await;
        assert!(matches!(blocked, Decision::Block { .. }));

        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        assert_eq!(limiter.check(ip, &req("/"), 0, &geo).await, Decision::Allow);
    }
}
