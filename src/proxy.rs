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
use std::sync::Mutex;

const PROXY_VERSION: &str = "v0.3.0";
/// PROXY_VERSION without the leading `v` — the release embeds it in asset names.
const PROXY_VERSION_NUM: &str = "0.3.0";
const PROXY_REPO: &str = "ably/uts-proxy";
const DEFAULT_CONTROL_PORT: u16 = 9100;

static PROXY_PROCESS: Mutex<Option<Child>> = Mutex::new(None);
static PROXY_ENSURED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// SHA256 checksums for each platform binary (from the PROXY_VERSION release's
/// checksums.txt).
fn checksum(asset: &str) -> Option<&'static str> {
    match asset {
        "uts-proxy_0.3.0_darwin_amd64.tar.gz" => {
            Some("1355526543c3022f87efb7f564f55200b78edc68d84c7dba2e49f63429e3b788")
        }
        "uts-proxy_0.3.0_darwin_arm64.tar.gz" => {
            Some("a948f99b7daf9b3bffff742f6405637d40a79947389309eed5f87e59026de9a5")
        }
        "uts-proxy_0.3.0_linux_amd64.tar.gz" => {
            Some("de741ba21f3630fea4f59714d00585638d565005599ecd84179931eba248f280")
        }
        "uts-proxy_0.3.0_linux_arm64.tar.gz" => {
            Some("15b5ca87c40c2c4ff350c94af1911cea0ad6be5a2d890ba41029bc4b8bc52c61")
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
    // v0.2.0+ embeds the version in the asset name.
    format!(
        "uts-proxy_{}_{}_{}.tar.gz",
        PROXY_VERSION_NUM, platform, arch
    )
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
    /// The port the proxy allocated for this session's listener; the SDK under
    /// test connects here.
    pub proxy_port: u16,
    proxy_url: String,
    http_client: reqwest::Client,
}

#[derive(Debug, Deserialize)]
struct CreateSessionResponse {
    #[serde(rename = "sessionId")]
    session_id: String,
    proxy: ProxyInfo,
}

/// The `proxy` object in a create-session response: the listener the proxy
/// bound for this session.
#[derive(Debug, Deserialize)]
struct ProxyInfo {
    host: String,
    port: u16,
}

impl ProxySession {
    /// Create a new proxy session, ensuring the proxy is running first.
    ///
    /// The proxy binds a free OS-assigned port for the session and reports it
    /// in the response; the allocated port is available as
    /// [`ProxySession::proxy_port`].
    pub async fn create(
        proxy_url: &str,
        endpoint: &str,
        rules: Vec<Rule>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // Ensure proxy is running before creating a session
        ensure_proxy().await?;

        let http_client = reqwest::Client::new();

        // `port` is omitted so the proxy auto-assigns a free port (uts-proxy
        // >= v0.2.0), avoiding the TOCTOU race of the caller guessing one.
        let body = if endpoint == "nonprod:sandbox" {
            serde_json::json!({
                "target": {
                    "realtimeHost": "sandbox.realtime.ably-nonprod.net",
                    "restHost": "sandbox.realtime.ably-nonprod.net"
                },
                "rules": rules,
            })
        } else {
            serde_json::json!({
                "endpoint": endpoint,
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
            proxy_host: result.proxy.host,
            proxy_port: result.proxy.port,
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
