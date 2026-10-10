//! GeoIP lookup using MaxMind MMDB databases.
//!
//! Supports Country, City, and ASN lookups with an in-memory LRU cache.
//! Results are exposed via the admin API and embedded in request logs.

pub mod download;

use std::{net::IpAddr, sync::Arc};

use anyhow::{anyhow, Result};
use moka::future::Cache;
use serde::{Deserialize, Serialize};

use crate::config::{GeoIpConfig, GeoIpMode};

/// Resolved GeoIP information for an IP address.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GeoIpInfo {
    pub country_code: Option<String>,
    pub country_name: Option<String>,
    pub city: Option<String>,
    pub asn: Option<u32>,
    pub asn_organization: Option<String>,
    pub is_anonymous_proxy: bool,
    pub is_satellite_provider: bool,
}

/// Result of applying GeoIP allow/block policies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    Block { reason: String },
}

/// Shared GeoIP service.
pub struct GeoIpService {
    reader: Option<Arc<maxminddb::Reader<Vec<u8>>>>,
    cache: Cache<IpAddr, GeoIpInfo>,
    mode: GeoIpMode,
    allow_countries: Vec<String>,
    block_countries: Vec<String>,
    allow_asns: Vec<u32>,
    block_asns: Vec<u32>,
}

impl GeoIpService {
    pub fn new(config: &GeoIpConfig) -> Result<Self> {
        let reader = if config.enabled {
            if config.database_path.is_empty() {
                return Err(anyhow!("geoip.enabled is true but database_path is empty"));
            }
            let r = maxminddb::Reader::open_readfile(&config.database_path).map_err(|e| {
                anyhow!(
                    "failed to open GeoIP database {}: {e}",
                    config.database_path
                )
            })?;
            tracing::info!(database = config.database_path, "GeoIP database loaded");
            Some(Arc::new(r))
        } else {
            None
        };

        Ok(Self {
            reader,
            cache: Cache::builder().max_capacity(config.cache_size).build(),
            mode: config.mode,
            allow_countries: config.allow_countries.clone(),
            block_countries: config.block_countries.clone(),
            allow_asns: config.allow_asns.clone(),
            block_asns: config.block_asns.clone(),
        })
    }

    pub async fn lookup(&self, ip: IpAddr) -> GeoIpInfo {
        if self.reader.is_none() {
            return GeoIpInfo::default();
        }

        self.cache.get_with(ip, async { self.do_lookup(ip) }).await
    }

    fn do_lookup(&self, ip: IpAddr) -> GeoIpInfo {
        let reader = self.reader.as_ref().unwrap();

        let mut info = GeoIpInfo::default();

        // Try Country / City lookup.
        if let Ok(country) = reader.lookup::<maxminddb::geoip2::Country>(ip) {
            info.country_code = country
                .country
                .as_ref()
                .and_then(|c| c.iso_code.map(String::from));
            info.country_name = country
                .country
                .as_ref()
                .and_then(|c| c.names.as_ref())
                .and_then(|n| n.get("en").map(|s| s.to_string()));
            info.is_anonymous_proxy = country
                .traits
                .as_ref()
                .map(|t| t.is_anonymous_proxy.unwrap_or(false))
                .unwrap_or(false);
            info.is_satellite_provider = country
                .traits
                .as_ref()
                .map(|t| t.is_satellite_provider.unwrap_or(false))
                .unwrap_or(false);
        }

        if let Ok(city) = reader.lookup::<maxminddb::geoip2::City>(ip) {
            info.city = city
                .city
                .as_ref()
                .and_then(|c| c.names.as_ref())
                .and_then(|n| n.get("en").map(|s| s.to_string()));
            if info.country_code.is_none() {
                info.country_code = city
                    .country
                    .as_ref()
                    .and_then(|c| c.iso_code.map(String::from));
            }
            if info.country_name.is_none() {
                info.country_name = city
                    .country
                    .as_ref()
                    .and_then(|c| c.names.as_ref())
                    .and_then(|n| n.get("en").map(|s| s.to_string()));
            }
        }

        // ASN lookup requires a separate ASN database. If the current DB is an
        // ASN database, this succeeds; otherwise it fails silently.
        if let Ok(asn) = reader.lookup::<maxminddb::geoip2::Asn>(ip) {
            info.asn = asn.autonomous_system_number.map(|n| n as u32);
            info.asn_organization = asn.autonomous_system_organization.map(|s| s.to_string());
        }

        info
    }

    /// Apply country/ASN allow and block lists.
    pub async fn check_policy(&self, ip: IpAddr) -> PolicyDecision {
        if self.reader.is_none()
            && self.allow_countries.is_empty()
            && self.block_countries.is_empty()
            && self.allow_asns.is_empty()
            && self.block_asns.is_empty()
        {
            return PolicyDecision::Allow;
        }

        let info = self.lookup(ip).await;
        self.check_policy_info(&info)
    }

    fn check_policy_info(&self, info: &GeoIpInfo) -> PolicyDecision {
        match self.mode {
            GeoIpMode::Blacklist => {
                // Block only listed countries/ASNs; everything else passes.
                if let Some(asn) = info.asn {
                    if self.block_asns.contains(&asn) {
                        return PolicyDecision::Block {
                            reason: format!("ASN {asn} blacklisted"),
                        };
                    }
                }
                if let Some(country) = info.country_code.as_ref() {
                    let country = country.to_uppercase();
                    if self
                        .block_countries
                        .iter()
                        .any(|c| c.to_uppercase() == country)
                    {
                        return PolicyDecision::Block {
                            reason: format!("country {country} blacklisted"),
                        };
                    }
                }
                PolicyDecision::Allow
            }
            GeoIpMode::Whitelist => {
                // Allow only listed countries/ASNs; everything else is blocked.
                if let Some(asn) = info.asn {
                    if self.allow_asns.contains(&asn) {
                        return PolicyDecision::Allow;
                    }
                }
                if let Some(country) = info.country_code.as_ref() {
                    let country = country.to_uppercase();
                    if self
                        .allow_countries
                        .iter()
                        .any(|c| c.to_uppercase() == country)
                    {
                        return PolicyDecision::Allow;
                    }
                }
                if self.allow_asns.is_empty() && self.allow_countries.is_empty() {
                    // Whitelist mode with empty lists is a misconfiguration;
                    // allow everything to avoid self-lockout.
                    return PolicyDecision::Allow;
                }
                PolicyDecision::Block {
                    reason: "not in GeoIP whitelist".into(),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service(cfg: GeoIpConfig) -> GeoIpService {
        GeoIpService::new(&cfg).unwrap()
    }

    #[test]
    fn block_country() {
        let svc = service(GeoIpConfig {
            enabled: false,
            mode: GeoIpMode::Blacklist,
            block_countries: vec!["US".into()],
            ..Default::default()
        });
        let info = GeoIpInfo {
            country_code: Some("US".into()),
            ..Default::default()
        };
        assert_eq!(
            svc.check_policy_info(&info),
            PolicyDecision::Block {
                reason: "country US blacklisted".into()
            }
        );
    }

    #[test]
    fn whitelist_country_blocks_unknown() {
        let svc = service(GeoIpConfig {
            enabled: false,
            mode: GeoIpMode::Whitelist,
            allow_countries: vec!["US".into()],
            ..Default::default()
        });
        let info = GeoIpInfo {
            country_code: Some("GB".into()),
            ..Default::default()
        };
        assert!(matches!(
            svc.check_policy_info(&info),
            PolicyDecision::Block { .. }
        ));
    }

    #[test]
    fn whitelist_country_allows_known() {
        let svc = service(GeoIpConfig {
            enabled: false,
            mode: GeoIpMode::Whitelist,
            allow_countries: vec!["US".into()],
            ..Default::default()
        });
        let info = GeoIpInfo {
            country_code: Some("us".into()),
            ..Default::default()
        };
        assert_eq!(svc.check_policy_info(&info), PolicyDecision::Allow);
    }

    #[test]
    fn blacklist_asn() {
        let svc = service(GeoIpConfig {
            enabled: false,
            mode: GeoIpMode::Blacklist,
            block_asns: vec![12345],
            ..Default::default()
        });
        let info = GeoIpInfo {
            asn: Some(12345),
            ..Default::default()
        };
        assert_eq!(
            svc.check_policy_info(&info),
            PolicyDecision::Block {
                reason: "ASN 12345 blacklisted".into()
            }
        );
    }

    #[test]
    fn whitelist_asn() {
        let svc = service(GeoIpConfig {
            enabled: false,
            mode: GeoIpMode::Whitelist,
            allow_asns: vec![12345],
            ..Default::default()
        });
        let allowed = GeoIpInfo {
            asn: Some(12345),
            ..Default::default()
        };
        let blocked = GeoIpInfo {
            asn: Some(99999),
            ..Default::default()
        };
        assert_eq!(svc.check_policy_info(&allowed), PolicyDecision::Allow);
        assert!(matches!(
            svc.check_policy_info(&blocked),
            PolicyDecision::Block { .. }
        ));
    }

    #[test]
    fn disabled_with_no_lists_allows_everything() {
        let svc = service(GeoIpConfig::default());
        let info = GeoIpInfo::default();
        assert_eq!(svc.check_policy_info(&info), PolicyDecision::Allow);
    }
}
