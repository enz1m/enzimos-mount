//! Cloud drives: Google Drive, Microsoft OneDrive, Dropbox and Nextcloud,
//! mounted with `rclone`.
//!
//! Signing in happens in the person's browser: rclone's own sign-in for the
//! OAuth services (it listens on 127.0.0.1 for the browser's answer), and
//! Nextcloud's Login Flow v2, which hands back an app password after the
//! person approves the computer on their server. Nothing is typed into the
//! desktop but a Nextcloud server address.
//!
//! Each account keeps a private rclone configuration (mode 0600) in
//! `$XDG_CONFIG_HOME/enzimos-mount/cloud/<id>.conf`, so the tokens rclone
//! refreshes are kept. Google requires a registered sign-in client for its
//! Drive; it is offered only when the system provides one in
//! `/etc/enzimos-mount/google-drive.json` (`{"client_id": …, "client_secret": …}`).

use crate::error::{Error, Result};
use crate::process::Spec;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// How long the person has to finish signing in in the browser.
pub const SIGN_IN_TIMEOUT: Duration = Duration::from_secs(600);
/// Where a system-wide Google Drive sign-in client is configured.
pub const GOOGLE_CLIENT: &str = "/etc/enzimos-mount/google-drive.json";
/// Most cloud accounts kept.
pub const MAX_ACCOUNTS: usize = 32;

/// A cloud service.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provider {
    /// Google Drive (needs a system sign-in client).
    GoogleDrive,
    /// Microsoft OneDrive.
    OneDrive,
    /// Dropbox.
    Dropbox,
    /// A Nextcloud (or ownCloud-compatible) server.
    Nextcloud,
}

impl Provider {
    /// Every service, in the order they are offered.
    pub const ALL: [Self; 4] = [
        Self::GoogleDrive,
        Self::OneDrive,
        Self::Dropbox,
        Self::Nextcloud,
    ];

    /// The D-Bus name of the provider.
    #[must_use]
    pub fn key(self) -> &'static str {
        match self {
            Self::GoogleDrive => "google_drive",
            Self::OneDrive => "onedrive",
            Self::Dropbox => "dropbox",
            Self::Nextcloud => "nextcloud",
        }
    }

    /// The service with D-Bus name `key`.
    #[must_use]
    pub fn from_key(key: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.key() == key)
    }

    /// The service's own name.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::GoogleDrive => "Google Drive",
            Self::OneDrive => "OneDrive",
            Self::Dropbox => "Dropbox",
            Self::Nextcloud => "Nextcloud",
        }
    }

    fn backend(self) -> &'static str {
        match self {
            Self::GoogleDrive => "drive",
            Self::OneDrive => "onedrive",
            Self::Dropbox => "dropbox",
            Self::Nextcloud => "webdav",
        }
    }

    /// The service reports changes, so the folder listing can be kept long.
    fn polls(self) -> bool {
        self != Self::Nextcloud
    }
}

/// One signed-in account.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    /// `cloud-<hex>`.
    pub id: String,
    /// The service.
    pub provider: Provider,
    /// Display name, e.g. "OneDrive (sam@outlook.com)".
    pub label: String,
    /// The account's e-mail or login, when known.
    #[serde(default)]
    pub account: String,
    /// Nextcloud: the server address.
    #[serde(default)]
    pub server: String,
    /// Connected at login.
    #[serde(default = "yes")]
    pub auto_connect: bool,
}

fn yes() -> bool {
    true
}

#[derive(Serialize, Deserialize)]
struct File {
    version: u32,
    accounts: Vec<Account>,
}

fn config_home() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from("/nonexistent"))
        .join("enzimos-mount")
}

fn cache_home() -> PathBuf {
    std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
        .unwrap_or_else(|| PathBuf::from("/nonexistent"))
        .join("enzimos-mount/cloud")
}

/// An account's private rclone configuration.
#[must_use]
pub fn config_path(id: &str) -> PathBuf {
    config_home().join("cloud").join(format!("{id}.conf"))
}

/// A new account identity.
#[must_use]
pub fn new_id() -> String {
    format!("cloud-{}", crate::secret::random_hex(8))
}

/// Whether `id` names a cloud account (and is safe as a file name).
#[must_use]
pub fn valid_id(id: &str) -> bool {
    id.strip_prefix("cloud-")
        .is_some_and(|hex| hex.len() == 16 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Saved accounts.
#[must_use]
pub fn load() -> Vec<Account> {
    let Ok(bytes) = std::fs::read(config_home().join("clouds.json")) else {
        return Vec::new();
    };
    serde_json::from_slice::<File>(&bytes)
        .map(|file| {
            file.accounts
                .into_iter()
                .filter(|a| valid_id(&a.id) && config_path(&a.id).is_file())
                .take(MAX_ACCOUNTS)
                .collect()
        })
        .unwrap_or_default()
}

/// Persist the accounts atomically (mode 0600).
///
/// # Errors
/// I/O failures.
pub fn save(accounts: &[Account]) -> std::io::Result<()> {
    write_private(
        &config_home().join("clouds.json"),
        &serde_json::to_vec_pretty(&File {
            version: 1,
            accounts: accounts.to_vec(),
        })
        .map_err(std::io::Error::other)?,
    )
}

fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    let dir = path
        .parent()
        .ok_or_else(|| std::io::Error::other("no directory"))?;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    let tmp = dir.join(format!(".{}.tmp", crate::secret::random_hex(4)));
    let mut out = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    out.write_all(bytes)?;
    out.sync_all()?;
    drop(out);
    std::fs::rename(&tmp, path)
}

/// Remove an account's configuration and cached files.
pub fn forget(id: &str) {
    if valid_id(id) {
        let _ = std::fs::remove_file(config_path(id));
        let _ = std::fs::remove_dir_all(cache_home().join(id));
    }
}

#[derive(Deserialize)]
struct GoogleClient {
    client_id: String,
    client_secret: String,
}

fn google_client() -> Option<GoogleClient> {
    let bytes = std::fs::read(GOOGLE_CLIENT)
        .ok()
        .filter(|b| b.len() < 4096)?;
    serde_json::from_slice::<GoogleClient>(&bytes)
        .ok()
        .filter(|c| !c.client_id.is_empty() && !c.client_secret.is_empty())
}

/// The services this computer can connect to.
#[must_use]
pub fn available() -> Vec<Provider> {
    if crate::process::helper("rclone").is_none() {
        return Vec::new();
    }
    Provider::ALL
        .into_iter()
        .filter(|p| match p {
            Provider::GoogleDrive => google_client().is_some(),
            Provider::Nextcloud => crate::process::helper("curl").is_some(),
            _ => true,
        })
        .collect()
}

/// The session's desktop environment, so rclone and the sign-in page can
/// open the browser.
fn with_desktop(mut spec: Spec) -> Spec {
    for key in [
        "WAYLAND_DISPLAY",
        "DISPLAY",
        "XDG_CURRENT_DESKTOP",
        "XDG_DATA_DIRS",
        "BROWSER",
    ] {
        if let Some(value) = std::env::var_os(key) {
            spec = spec.env(key, value);
        }
    }
    spec
}

/// A non-interactive `rclone config` step's question.
#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
struct Step {
    state: String,
    option: Option<StepOption>,
    error: String,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
struct StepOption {
    name: String,
    default: serde_json::Value,
    examples: Vec<Example>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
struct Example {
    value: String,
}

/// The answer to a configuration question nobody needs to see: the first
/// offered choice (OneDrive's personal drive), "yes" to confirmations, else
/// rclone's default.
fn answer(option: &StepOption) -> String {
    if let Some(first) = option.examples.first() {
        return first.value.clone();
    }
    if option.name.ends_with("_ok") {
        return "true".into();
    }
    match &option.default {
        serde_json::Value::String(text) => text.clone(),
        serde_json::Value::Bool(value) => value.to_string(),
        serde_json::Value::Number(number) => number.to_string(),
        _ => String::new(),
    }
}

fn explain(stderr: &str) -> Error {
    let lower = stderr.to_lowercase();
    if lower.contains("access_denied") || lower.contains("denied") || lower.contains("cancel") {
        Error::AuthFailed(crate::tr!("error-cloud-denied"))
    } else if lower.contains("no such host")
        || lower.contains("dial tcp")
        || lower.contains("network")
        || lower.contains("timeout")
    {
        Error::Unreachable(crate::tr!("error-cloud-unreachable"))
    } else {
        Error::Failed(crate::tr!("error-cloud-failed"))
    }
}

/// Sign `id` in to an OAuth service through the browser and write its
/// configuration.
async fn oauth(helper: &Path, id: &str, provider: Provider) -> Result<()> {
    let config = config_path(id);
    write_private(&config, b"").map_err(|e| Error::Failed(e.to_string()))?;
    let mut first: Vec<String> = vec![
        "config".into(),
        "create".into(),
        id.into(),
        provider.backend().into(),
        "config_is_local=true".into(),
        "config_refresh_token=false".into(),
    ];
    match provider {
        Provider::GoogleDrive => {
            let client = google_client()
                .ok_or_else(|| Error::Unsupported(crate::tr!("error-cloud-google-unavailable")))?;
            first.push(format!("client_id={}", client.client_id));
            first.push(format!("client_secret={}", client.client_secret));
            first.push("scope=drive".into());
            first.push("config_change_team_drive=false".into());
        }
        Provider::OneDrive => first.push("config_type=onedrive".into()),
        _ => {}
    }
    let mut args = first;
    for _ in 0..8 {
        let spec = with_desktop(Spec::new(helper, SIGN_IN_TIMEOUT))
            .args(args.iter().map(String::as_str))
            .args(["--non-interactive", "--auto-confirm", "--config"])
            .arg(&config);
        let output = crate::process::run(spec).await.map_err(|e| match e {
            crate::process::RunError::Timeout => Error::Timeout(crate::tr!("error-cloud-timeout")),
            other => Error::Failed(other.to_string()),
        })?;
        if !output.success() {
            return Err(explain(&output.stderr));
        }
        let step: Step = output
            .stdout
            .lines()
            .rev()
            .find_map(|l| serde_json::from_str(l.trim()).ok())
            .unwrap_or_default();
        if !step.error.is_empty() {
            crate::log!(info, "cloud sign-in step for {id}: {}", step.error);
        }
        if step.state.is_empty() {
            return Ok(());
        }
        let reply = step.option.as_ref().map(answer).unwrap_or_default();
        args = vec![
            "config".into(),
            "update".into(),
            id.into(),
            "--continue".into(),
            "--state".into(),
            step.state,
            "--result".into(),
            reply,
        ];
    }
    Err(Error::Failed(crate::tr!("error-cloud-failed")))
}

/// The account's e-mail or name, as the service reports it.
async fn user_name(helper: &Path, id: &str) -> String {
    let spec = Spec::new(helper, Duration::from_secs(30))
        .args([
            "config",
            "userinfo",
            &format!("{id}:"),
            "--json",
            "--config",
        ])
        .arg(config_path(id));
    let Ok(output) = crate::process::run(spec).await else {
        return String::new();
    };
    let value: serde_json::Value = serde_json::from_str(&output.stdout).unwrap_or_default();
    ["Email", "Login", "UserName", "Name"]
        .iter()
        .find_map(|key| {
            value
                .get(*key)
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_default()
        .chars()
        .filter(|c| !c.is_control())
        .take(120)
        .collect()
}

/// A Nextcloud server address as typed, checked; `https://` is assumed and
/// plain HTTP is allowed only for local names.
///
/// # Errors
/// [`Error::Invalid`] for an address that cannot be a server.
pub fn nextcloud_base(server: &str) -> Result<String> {
    let text = server.trim().trim_end_matches('/');
    let with_scheme = if text.contains("://") {
        text.to_owned()
    } else {
        format!("https://{text}")
    };
    let url = url::Url::parse(&with_scheme)
        .map_err(|_| Error::Invalid(crate::tr!("error-cloud-server-invalid")))?;
    let host = url.host_str().unwrap_or_default();
    if !matches!(url.scheme(), "https" | "http")
        || host.is_empty()
        || !crate::uri::valid_host(host)
        || url.query().is_some()
        || url.username() != ""
        || url.password().is_some()
    {
        return Err(Error::Invalid(crate::tr!("error-cloud-server-invalid")));
    }
    if url.scheme() == "http"
        && !(host.ends_with(".local")
            || host == "localhost"
            || host.parse::<std::net::IpAddr>().is_ok_and(|ip| {
                ip.is_loopback()
                    || match ip {
                        std::net::IpAddr::V4(v4) => v4.is_private(),
                        std::net::IpAddr::V6(_) => false,
                    }
            }))
    {
        return Err(Error::Invalid(crate::tr!("error-cloud-server-https")));
    }
    Ok(url.as_str().trim_end_matches('/').to_owned())
}

async fn curl(
    helper: &Path,
    args: &[&str],
    stdin: Option<String>,
    deadline: Duration,
) -> Result<(String, u16)> {
    let mut spec = Spec::new(helper, deadline)
        .args([
            "--silent",
            "--show-error",
            "--max-time",
            &deadline.as_secs().to_string(),
            "--user-agent",
            "enzimOS Files",
            "--write-out",
            "\n%{http_code}",
        ])
        .args(args.iter().copied());
    spec.stdin = stdin.map(|s| zeroize::Zeroizing::new(s.into_bytes()));
    let output = crate::process::run(spec)
        .await
        .map_err(|_| Error::Unreachable(crate::tr!("error-cloud-unreachable")))?;
    let (body, code) = output
        .stdout
        .rsplit_once('\n')
        .unwrap_or((&output.stdout, "0"));
    Ok((body.to_owned(), code.trim().parse().unwrap_or(0)))
}

/// Nextcloud Login Flow v2: open the server's approval page in the browser,
/// wait for the app password, and write a WebDAV configuration.
async fn nextcloud(
    helper: &Path,
    curl_path: &Path,
    id: &str,
    server: &str,
) -> Result<(String, String)> {
    let base = nextcloud_base(server)?;
    let (body, code) = curl(
        curl_path,
        &["--request", "POST", &format!("{base}/index.php/login/v2")],
        None,
        Duration::from_secs(20),
    )
    .await?;
    if code != 200 {
        return Err(Error::Unreachable(crate::tr!("error-cloud-not-nextcloud")));
    }
    let start: serde_json::Value = serde_json::from_str(&body)
        .map_err(|_| Error::Unreachable(crate::tr!("error-cloud-not-nextcloud")))?;
    let (Some(login), Some(token), Some(endpoint)) = (
        start["login"].as_str(),
        start["poll"]["token"].as_str(),
        start["poll"]["endpoint"].as_str(),
    ) else {
        return Err(Error::Unreachable(crate::tr!("error-cloud-not-nextcloud")));
    };
    // Only the server the person named may receive the token.
    let same = |address: &str| {
        url::Url::parse(address)
            .ok()
            .and_then(|u| u.host_str().map(str::to_owned))
            == url::Url::parse(&base)
                .ok()
                .and_then(|u| u.host_str().map(str::to_owned))
    };
    if !same(login) || !same(endpoint) {
        return Err(Error::Failed(crate::tr!("error-cloud-not-nextcloud")));
    }
    let _ = crate::process::run(
        with_desktop(Spec::new(
            crate::process::helper("xdg-open").unwrap_or_else(|| PathBuf::from("xdg-open")),
            Duration::from_secs(20),
        ))
        .arg(login),
    )
    .await;
    let deadline = tokio::time::Instant::now() + SIGN_IN_TIMEOUT;
    let granted = loop {
        if tokio::time::Instant::now() >= deadline {
            return Err(Error::Timeout(crate::tr!("error-cloud-timeout")));
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
        let (body, code) = curl(
            curl_path,
            &["--request", "POST", "--data-binary", "@-", endpoint],
            Some(format!("token={token}")),
            Duration::from_secs(20),
        )
        .await?;
        if code == 200 {
            break serde_json::from_str::<serde_json::Value>(&body)
                .map_err(|_| Error::Failed(crate::tr!("error-cloud-failed")))?;
        }
    };
    let (Some(login_name), Some(password)) = (
        granted["loginName"].as_str(),
        granted["appPassword"].as_str(),
    ) else {
        return Err(Error::Failed(crate::tr!("error-cloud-failed")));
    };
    if !crate::uri::valid_name(login_name, 128) && !login_name.contains('@')
        || login_name.chars().any(char::is_control)
    {
        return Err(Error::Failed(crate::tr!("error-cloud-failed")));
    }
    // The WebDAV folder is named by the user id, which can differ from the login.
    let netrc = format!("user = \"{login_name}:{password}\"\n");
    let (body, _) = curl(
        curl_path,
        &[
            "--config",
            "-",
            "--header",
            "OCS-APIRequest: true",
            &format!("{base}/ocs/v2.php/cloud/user?format=json"),
        ],
        Some(netrc),
        Duration::from_secs(20),
    )
    .await?;
    let user_id = serde_json::from_str::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| v["ocs"]["data"]["id"].as_str().map(str::to_owned))
        .unwrap_or_else(|| login_name.to_owned());
    if user_id.is_empty() || user_id.contains(['/', '\\']) || user_id.chars().any(char::is_control)
    {
        return Err(Error::Failed(crate::tr!("error-cloud-failed")));
    }
    let mut obscure = Spec::new(helper, Duration::from_secs(10)).args(["obscure", "-"]);
    obscure.stdin = Some(zeroize::Zeroizing::new(password.as_bytes().to_vec()));
    let obscured = crate::process::run(obscure)
        .await
        .map_err(|e| Error::Failed(e.to_string()))?
        .stdout
        .trim()
        .to_owned();
    let encoded: String = url::form_urlencoded::byte_serialize(user_id.as_bytes())
        .collect::<String>()
        .replace('+', "%20");
    let config = format!(
        "[{id}]\ntype = webdav\nurl = {base}/remote.php/dav/files/{encoded}/\nvendor = nextcloud\nuser = {login_name}\npass = {obscured}\n"
    );
    write_private(&config_path(id), config.as_bytes()).map_err(|e| Error::Failed(e.to_string()))?;
    let host = url::Url::parse(&base)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
        .unwrap_or_default();
    Ok((login_name.to_owned(), host))
}

/// Sign in a new account; returns (account name, server).
///
/// # Errors
/// Refusals, cancellation, missing helpers or an unreachable service.
pub async fn sign_in(id: &str, provider: Provider, server: &str) -> Result<(String, String)> {
    let helper = crate::process::helper("rclone").ok_or_else(|| {
        Error::Unsupported(crate::tr!(
            "error-missing-helper",
            feature = crate::tr!("feature-cloud"),
            helper = "rclone"
        ))
    })?;
    let result = match provider {
        Provider::Nextcloud => {
            let curl_path = crate::process::helper("curl").ok_or_else(|| {
                Error::Unsupported(crate::tr!(
                    "error-missing-helper",
                    feature = crate::tr!("feature-cloud"),
                    helper = "curl"
                ))
            })?;
            nextcloud(&helper, &curl_path, id, server).await
        }
        _ => match oauth(&helper, id, provider).await {
            Ok(()) => Ok((user_name(&helper, id).await, String::new())),
            Err(error) => Err(error),
        },
    };
    if result.is_err() {
        forget(id);
    }
    result
}

/// The `rclone mount` of account `id` at `mount_point`.
#[must_use]
pub fn mount_spec(helper: PathBuf, account: &Account, mount_point: &Path) -> Spec {
    let cache = cache_home().join(&account.id);
    let mut spec = Spec::new(helper, Duration::ZERO)
        .args(["mount", "--config"])
        .arg(config_path(&account.id))
        .arg(format!("{}:", account.id))
        .arg(mount_point)
        .args(["--cache-dir"])
        .arg(cache)
        .args([
            // Files open like local ones and work offline once read.
            "--vfs-cache-mode=full",
            "--vfs-cache-max-size=10G",
            "--vfs-cache-max-age=720h",
            "--vfs-cache-min-free-space=5G",
            "--vfs-write-back=5s",
            "--contimeout=15s",
            "--timeout=60s",
            "--low-level-retries=3",
            "--attr-timeout=1s",
            "--log-level=ERROR",
        ])
        .arg(format!("--volname={}", account.label));
    spec = if account.provider.polls() {
        spec.args(["--dir-cache-time=1000h", "--poll-interval=1m"])
    } else {
        spec.args(["--dir-cache-time=1m"])
    };
    spec
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn questions_get_quiet_answers_and_servers_are_checked() {
        let option: StepOption = serde_json::from_str(r#"{"Name":"config_driveid","Default":"","Examples":[{"Value":"b!abc"},{"Value":"b!def"}]}"#).unwrap();
        assert_eq!(
            answer(&option),
            "b!abc",
            "the first drive is the personal one"
        );
        let option: StepOption =
            serde_json::from_str(r#"{"Name":"config_drive_ok","Default":true}"#).unwrap();
        assert_eq!(answer(&option), "true");
        assert_eq!(
            nextcloud_base("cloud.example.com/").unwrap(),
            "https://cloud.example.com"
        );
        assert_eq!(
            nextcloud_base("https://example.com/nextcloud").unwrap(),
            "https://example.com/nextcloud"
        );
        assert!(
            nextcloud_base("http://cloud.example.com").is_err(),
            "plain HTTP only on the local network"
        );
        assert!(nextcloud_base("http://192.168.1.5").is_ok());
        assert!(nextcloud_base("https://user:pw@example.com").is_err());
        assert!(nextcloud_base("ftp://example.com").is_err());
        assert!(
            valid_id("cloud-0123456789abcdef")
                && !valid_id("cloud-../x")
                && !valid_id("net-0123456789abcdef")
        );
    }
}
