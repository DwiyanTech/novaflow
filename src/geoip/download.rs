//! GeoIP MMDB database auto-download.
//!
//! Supports direct `.mmdb` downloads, `.mmdb.gz` downloads, and `.tar.gz`
//! archives (common for MaxMind GeoLite2). The downloaded file is written to
//! the configured output path and can be refreshed on a configurable schedule.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::config::GeoIpConfig;

/// Ensure a GeoIP database exists at the configured path, downloading it if
/// auto-download is enabled and the local file is missing or stale.
pub async fn ensure_database(config: &GeoIpConfig) -> Result<()> {
    if !config.enabled {
        return Ok(());
    }
    let download = &config.auto_download;
    if !download.enabled {
        return Ok(());
    }
    if download.url.is_empty() {
        bail!("geoip.auto_download.enabled is true but url is empty");
    }

    let output_path = resolve_output_path(config);
    if should_skip_download(&output_path, download.refresh_days).await {
        tracing::info!(
            path = %output_path.display(),
            "GeoIP database is fresh; skipping auto-download"
        );
        return Ok(());
    }

    tracing::info!(url = %download.url, output = %output_path.display(), "Downloading GeoIP database");

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(300))
        .build()
        .context("failed to build HTTP client for GeoIP download")?;

    let request = build_request(&client, download)?;
    let response = request
        .send()
        .await
        .context("GeoIP database download failed")?
        .error_for_status()
        .context("GeoIP database download returned an error")?;

    let bytes = response
        .bytes()
        .await
        .context("failed to read GeoIP download response")?;

    let temp_dir = tempfile_for(&output_path).await?;
    let temp_path = temp_dir.join("download");

    if download.url.ends_with(".tar.gz") || download.url.contains("suffix=tar.gz") {
        extract_mmdb_from_tar(&bytes, &temp_path).await?;
    } else if download.url.ends_with(".gz") {
        decompress_gz(&bytes, &temp_path).await?;
    } else {
        tokio::fs::write(&temp_path, &bytes)
            .await
            .context("failed to write GeoIP database")?;
    }

    if let Some(parent) = output_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .context("failed to create GeoIP database directory")?;
    }

    tokio::fs::rename(&temp_path, &output_path)
        .await
        .context("failed to move downloaded GeoIP database into place")?;

    tracing::info!(path = %output_path.display(), "GeoIP database downloaded successfully");
    Ok(())
}

fn resolve_output_path(config: &GeoIpConfig) -> PathBuf {
    let download = &config.auto_download;
    if !download.output_path.is_empty() {
        PathBuf::from(&download.output_path)
    } else {
        PathBuf::from(&config.database_path)
    }
}

async fn should_skip_download(path: &Path, refresh_days: u64) -> bool {
    if !path.exists() {
        return false;
    }
    if refresh_days == 0 {
        return true;
    }
    let metadata = match tokio::fs::metadata(path).await {
        Ok(m) => m,
        Err(_) => return false,
    };
    let modified = match metadata.modified() {
        Ok(t) => t,
        Err(_) => return false,
    };
    let age = std::time::SystemTime::now()
        .duration_since(modified)
        .unwrap_or_default();
    age.as_secs() < refresh_days * 24 * 60 * 60
}

fn build_request(
    client: &reqwest::Client,
    download: &crate::config::AutoDownloadConfig,
) -> Result<reqwest::RequestBuilder> {
    let mut url = download.url.clone();
    // Inject the license key into MaxMind-style URLs when it is provided as a
    // dedicated config field. This avoids putting secrets directly in the URL.
    if !download.license_key.is_empty() && url.contains("download.maxmind.com") {
        let key = urlencoding::encode(&download.license_key);
        if url.contains("license_key=") {
            url = regex::Regex::new(r"license_key=[^&]*")
                .unwrap()
                .replace_all(&url, format!("license_key={key}"))
                .to_string();
        } else {
            let separator = if url.contains('?') { "&" } else { "?" };
            url.push_str(&format!("{separator}license_key={key}"));
        }
    }
    Ok(client.get(&url))
}

async fn tempfile_for(output_path: &Path) -> Result<PathBuf> {
    let base = output_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let dir = base.join(".novaflow-geoip-download");
    tokio::fs::create_dir_all(&dir)
        .await
        .context("failed to create temporary download directory")?;
    Ok(dir)
}

async fn decompress_gz(bytes: &[u8], output: &Path) -> Result<()> {
    use std::io::Write;
    let mut decoder = flate2::read::GzDecoder::new(bytes);
    let mut file = std::fs::File::create(output)?;
    std::io::copy(&mut decoder, &mut file).context("failed to decompress .gz GeoIP database")?;
    file.flush()?;
    Ok(())
}

async fn extract_mmdb_from_tar(bytes: &[u8], output: &Path) -> Result<()> {
    let decoder = flate2::read::GzDecoder::new(bytes);
    let mut archive = tar::Archive::new(decoder);

    let mut found = false;
    for entry in archive.entries().context("failed to read tar.gz archive")? {
        let mut entry = entry.context("failed to read tar.gz entry")?;
        let path = entry.path().context("failed to read tar entry path")?;
        if path.to_string_lossy().ends_with(".mmdb") {
            entry
                .unpack(output)
                .context("failed to extract GeoIP database from tar.gz")?;
            found = true;
            break;
        }
    }

    if !found {
        bail!("no .mmdb file found in the downloaded tar.gz archive");
    }
    Ok(())
}
