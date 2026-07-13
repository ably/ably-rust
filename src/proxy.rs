//! Proxy session client for uts-proxy integration tests.
//!
//! The uts-proxy is a programmable HTTP/WebSocket proxy that sits between the
//! SDK and the Ably sandbox. This module provides:
//! - A client for creating and managing proxy sessions
//! - Auto-download of the proxy binary from GitHub releases
//! - Auto-spawn of the proxy process before tests

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Mutex;

const PROXY_VERSION: &str = "v0.1.0";
const PROXY_REPO: &str = "ably/uts-proxy";
const DEFAULT_CONTROL_PORT: u16 = 9100;

static NEXT_PORT: std::sync::OnceLock<AtomicU16> = std::sync::OnceLock::new();
static PROXY_PROCESS: Mutex<Option<Child>> = Mutex::new(None);
static PROXY_ENSURED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// SHA256 checksums for each platform binary.
fn checksum(asset: &str) -> Option<&'static str> {
    match asset {
        "uts-proxy_darwin_amd64.tar.gz" => {
            Some("eb8abf5eec7f7137cf9e7cb6ab6f45fd162303c242b4567ab9e354c4b9a4a4ff")
        }
        "uts-proxy_darwin_arm64.tar.gz" => {
            Some("845da80af7d5b1daacbdf30b34aff6ca1b2bb88c708065bdc5d9a636baf32a1f")
        }
        "uts-proxy_linux_amd64.tar.gz" => {
            Some("79f444c23362cc277d163deb243dc16063c74665ff63b8bd3e56789b9d9610c7")
        }
        "uts-proxy_linux_arm64.tar.gz" => {
            Some("7357e4605f19451d83bb419ee959537d6e95ca74b766721eae006d4171371030")
        }
        _ => None,
    }
}

fn asset_name() -> String {
    let platform = if cfg!(target_os = "macos") {
        "darwin"
    } else {
        "linux"
    };
    let arch = if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "amd64"
    };
    format!("uts-proxy_{}_{}.tar.gz", platform, arch)
}

fn cache_dir() -> PathBuf {
    let base = std::env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            // Walk up from the source file to find the project root
            let manifest = std::env::var("CARGO_MANIFEST_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("."));
            manifest.join("target")
        });
    base.join("uts-proxy").join(PROXY_VERSION)
}

fn proxy_bin_path() -> PathBuf {
    cache_dir().join("uts-proxy")
}

fn control_port() -> u16 {
    std::env::var("PROXY_CONTROL_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_CONTROL_PORT)
}

fn control_url() -> String {
    std::env::var("ABLY_PROXY_URL")
        .unwrap_or_else(|_| format!("http://localhost:{}", control_port()))
}

/// Allocate a unique port for a proxy session.
///
/// The base is randomized per process: the proxy daemon outlives test runs,
/// and sessions orphaned by panicked tests keep their port bound — a fixed
/// base would collide with them on every subsequent run.
pub fn allocate_port() -> u16 {
    let counter = NEXT_PORT.get_or_init(|| {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        AtomicU16::new(19100 + (nanos % 9900) as u16)
    });
    counter.fetch_add(1, Ordering::SeqCst)
}

/// Download the proxy binary if not already cached.
async fn download_proxy() -> Result<(), Box<dyn std::error::Error>> {
    let bin_path = proxy_bin_path();
    if bin_path.exists() {
        return Ok(());
    }

    let dir = cache_dir();
    std::fs::create_dir_all(&dir)?;

    let asset = asset_name();
    let expected_hash = checksum(&asset)
        .ok_or_else(|| format!("No checksum for {} — unsupported platform/arch", asset))?;

    let url = format!(
        "https://github.com/{}/releases/download/{}/{}",
        PROXY_REPO, PROXY_VERSION, asset
    );
    eprintln!("Downloading uts-proxy {} ({})...", PROXY_VERSION, asset);

    let resp = reqwest::get(&url).await?;
    if !resp.status().is_success() {
        return Err(format!("Failed to download {}: {}", url, resp.status()).into());
    }
    let bytes = resp.bytes().await?;

    // Verify SHA256
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let hash = format!("{:x}", hasher.finalize());
    if hash != expected_hash {
        return Err(format!(
            "Checksum mismatch for {}: expected {}, got {}",
            asset, expected_hash, hash
        )
        .into());
    }

    // Write tarball and extract
    let tarball_path = dir.join(&asset);
    std::fs::write(&tarball_path, &bytes)?;

    let status = Command::new("tar")
        .args(["xzf", &asset])
        .current_dir(&dir)
        .status()?;
    if !status.success() {
        return Err(format!("tar extraction failed for {}", asset).into());
    }

    // Make executable and clean up tarball
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&bin_path, std::fs::Permissions::from_mode(0o755))?;
    }
    let _ = std::fs::remove_file(&tarball_path);

    eprintln!(
        "uts-proxy {} ready at {}",
        PROXY_VERSION,
        bin_path.display()
    );
    Ok(())
}

/// Spawn the proxy process.
fn spawn_proxy() -> Result<Child, Box<dyn std::error::Error>> {
    let bin = proxy_bin_path();
    let port = control_port().to_string();

    // Null stdio: the daemon outlives the test process, and an inherited
    // stdout/stderr keeps any pipe attached to the test run open forever
    // (e.g. `cargo test | tail` never terminates).
    let child = Command::new(&bin)
        .args(["--port", &port])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;

    Ok(child)
}

/// Check if the proxy is healthy.
async fn proxy_is_healthy() -> bool {
    let url = format!("{}/health", control_url());
    match reqwest::get(&url).await {
        Ok(resp) => resp.status().is_success(),
        Err(_) => false,
    }
}

/// Ensure the proxy is running. Downloads and spawns if needed.
/// Safe to call multiple times — only starts the proxy once.
pub async fn ensure_proxy() -> Result<(), Box<dyn std::error::Error>> {
    if PROXY_ENSURED.load(std::sync::atomic::Ordering::SeqCst) {
        return Ok(());
    }

    // Check if proxy is already running (e.g. started externally)
    if proxy_is_healthy().await {
        PROXY_ENSURED.store(true, std::sync::atomic::Ordering::SeqCst);
        return Ok(());
    }

    // Download if needed
    download_proxy().await?;

    // Spawn
    let child = spawn_proxy()?;
    {
        let mut guard = PROXY_PROCESS.lock().unwrap();
        *guard = Some(child);
    }

    // Wait for healthy (up to 15 seconds)
    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(15);
    while start.elapsed() < timeout {
        if proxy_is_healthy().await {
            PROXY_ENSURED.store(true, std::sync::atomic::Ordering::SeqCst);
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }

    // Failed to start — kill the process
    {
        let mut guard = PROXY_PROCESS.lock().unwrap();
        if let Some(ref mut child) = *guard {
            let _ = child.kill();
        }
        *guard = None;
    }

    Err(format!("Proxy failed to start within {}s", timeout.as_secs()).into())
}

/// A rule that the proxy evaluates against traffic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    #[serde(rename = "match")]
    pub match_condition: serde_json::Value,
    pub action: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub times: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// A proxy session that mediates between the SDK and Ably sandbox.
pub struct ProxySession {
    pub session_id: String,
    #[allow(dead_code)]
    pub proxy_host: String,
    #[allow(dead_code)]
    pub proxy_port: u16,
    proxy_url: String,
    http_client: reqwest::Client,
}

#[derive(Debug, Deserialize)]
struct CreateSessionResponse {
    #[serde(rename = "sessionId")]
    session_id: String,
}

impl ProxySession {
    /// Create a new proxy session, ensuring the proxy is running first.
    pub async fn create(
        proxy_url: &str,
        endpoint: &str,
        port: u16,
        rules: Vec<Rule>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // Ensure proxy is running before creating a session
        ensure_proxy().await?;

        let http_client = reqwest::Client::new();

        let body = if endpoint == "nonprod:sandbox" {
            serde_json::json!({
                "target": {
                    "realtimeHost": "sandbox.realtime.ably-nonprod.net",
                    "restHost": "sandbox.realtime.ably-nonprod.net"
                },
                "port": port,
                "rules": rules,
            })
        } else {
            serde_json::json!({
                "endpoint": endpoint,
                "port": port,
                "rules": rules,
            })
        };

        let resp = http_client
            .post(format!("{}/sessions", proxy_url))
            .json(&body)
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(format!("Failed to create proxy session: {} {}", status, text).into());
        }

        let result: CreateSessionResponse = resp.json().await?;

        Ok(Self {
            session_id: result.session_id,
            proxy_host: "localhost".to_string(),
            proxy_port: port,
            proxy_url: proxy_url.to_string(),
            http_client,
        })
    }

    /// Add rules to the session.
    #[allow(dead_code)] // uts-proxy API surface
    pub async fn add_rules(
        &self,
        rules: Vec<Rule>,
        position: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let body = serde_json::json!({
            "rules": rules,
            "position": position,
        });

        let resp = self
            .http_client
            .post(format!(
                "{}/sessions/{}/rules",
                self.proxy_url, self.session_id
            ))
            .json(&body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(format!("Failed to add rules: {}", text).into());
        }

        Ok(())
    }

    /// Trigger an imperative action (disconnect, close, inject, etc.).
    #[allow(dead_code)] // uts-proxy API surface
    pub async fn trigger_action(
        &self,
        action: serde_json::Value,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let resp = self
            .http_client
            .post(format!(
                "{}/sessions/{}/actions",
                self.proxy_url, self.session_id
            ))
            .json(&action)
            .send()
            .await?;

        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(format!("Failed to trigger action: {}", text).into());
        }

        Ok(())
    }

    /// Get the event log for this session.
    pub async fn get_log(&self) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
        let resp = self
            .http_client
            .get(format!(
                "{}/sessions/{}/log",
                self.proxy_url, self.session_id
            ))
            .send()
            .await?;

        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(format!("Failed to get log: {}", text).into());
        }

        #[derive(Deserialize)]
        struct LogResponse {
            events: Vec<serde_json::Value>,
        }

        let result: LogResponse = resp.json().await?;
        Ok(result.events)
    }

    /// Close and clean up the proxy session.
    pub async fn close(&self) -> Result<(), Box<dyn std::error::Error>> {
        let resp = self
            .http_client
            .delete(format!("{}/sessions/{}", self.proxy_url, self.session_id))
            .send()
            .await?;

        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(format!("Failed to close session: {}", text).into());
        }

        Ok(())
    }

    /// Get the proxy control URL.
    pub fn proxy_base_url() -> String {
        control_url()
    }
}
