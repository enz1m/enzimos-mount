//! Helper command lines and their failure messages.
//!
//! Hosts, users and paths reaching these command lines were validated by
//! [`crate::uri::NetUri::parse`]; passwords only ever travel on standard input
//! or (for rclone) in an obscured environment value of the helper itself.

use crate::error::Error;
use crate::process::Spec;
use crate::uri::{NetUri, Scheme};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Escape a FUSE `-o` option value (commas and backslashes).
#[must_use]
pub fn fuse_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace(',', "\\,")
}

/// `aft-mtp-mount` for the device matching `filter` (`vendor:product` or a
/// serial number).
#[must_use]
pub fn mtp(helper: PathBuf, filter: &str, mount_point: &Path) -> Spec {
    let mut spec = Spec::new(helper, Duration::ZERO).arg("-f");
    if !filter.is_empty() {
        spec = spec.args(["-D", filter]);
    }
    spec.args(["-o", "fsname=mtp,subtype=mtp"]).arg(mount_point)
}

/// Explain a failed `aft-mtp-mount` start.
#[must_use]
pub fn explain_mtp(_code: Option<i32>, stderr: &str) -> Error {
    let lower = stderr.to_lowercase();
    if lower.contains("no mtp device") || lower.contains("no device") || lower.contains("not found")
    {
        Error::Unreachable(crate::tr!("error-phone-no-files"))
    } else if lower.contains("claim") || lower.contains("busy") {
        Error::Busy(crate::tr!("error-phone-busy"))
    } else if lower.contains("permission") || lower.contains("access") {
        Error::NotAuthorized(crate::tr!("error-phone-not-allowed"))
    } else if lower.contains("locked") || lower.contains("no storage") {
        Error::DeviceLocked(crate::tr!("error-phone-locked"))
    } else {
        Error::Failed(crate::tr!("error-phone-failed", detail = last_line(stderr)))
    }
}

fn last_line(text: &str) -> String {
    text.lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("unknown error")
        .trim()
        .chars()
        .take(240)
        .collect()
}

/// Explain `idevicepair` output when pairing has not completed.
#[must_use]
pub fn explain_pairing(output: &str) -> Error {
    let lower = output.to_lowercase();
    if lower.contains("passcode")
        || lower.contains("trust")
        || lower.contains("pairing dialog")
        || lower.contains("user denied")
    {
        Error::DeviceLocked(crate::tr!("error-iphone-trust"))
    } else if lower.contains("no device") {
        Error::Unreachable(crate::tr!("error-iphone-gone"))
    } else if lower.contains("usbmuxd") {
        Error::Unsupported(crate::tr!("error-usbmuxd-missing"))
    } else {
        Error::Failed(crate::tr!(
            "error-iphone-pair-failed",
            detail = last_line(output)
        ))
    }
}

/// `ifuse` for the device `udid`.
#[must_use]
pub fn ifuse(helper: PathBuf, udid: &str, mount_point: &Path) -> Spec {
    Spec::new(helper, Duration::ZERO)
        .args(["-u", udid, "-f"])
        .arg(mount_point)
        .args(["-o", "fsname=ios"])
}

/// Explain a failed `ifuse` start.
#[must_use]
pub fn explain_ifuse(_code: Option<i32>, stderr: &str) -> Error {
    let lower = stderr.to_lowercase();
    if lower.contains("pair") || lower.contains("lockdown") || lower.contains("passcode") {
        Error::DeviceLocked(crate::tr!("error-iphone-trust"))
    } else {
        Error::Failed(crate::tr!(
            "error-iphone-failed",
            detail = last_line(stderr)
        ))
    }
}

/// Where trusted SFTP host keys are kept.
#[must_use]
pub fn known_hosts() -> PathBuf {
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
        .unwrap_or_else(|| PathBuf::from("/nonexistent"));
    base.join("enzimos-mount/known_hosts")
}

/// `host` or `[host]:port` as OpenSSH writes it in known_hosts.
#[must_use]
pub fn ssh_host_key_name(uri: &NetUri) -> String {
    match uri.port {
        Some(port) if port != 22 => format!("[{}]:{port}", uri.host),
        _ => uri.host.clone(),
    }
}

/// `sshfs` for `uri`; with `password`, password authentication is read from
/// standard input, otherwise keys and the SSH agent only.
#[must_use]
pub fn sshfs(helper: PathBuf, uri: &NetUri, mount_point: &Path, password: bool) -> Spec {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default();
    let global = format!(
        "/etc/ssh/ssh_known_hosts {}",
        home.join(".ssh/known_hosts").to_string_lossy()
    );
    let host = if uri.host.contains(':') {
        format!("[{}]", uri.host)
    } else {
        uri.host.clone()
    };
    let remote = match &uri.user {
        Some(user) => format!("{user}@{host}:/{}", uri.path),
        None => format!("{host}:/{}", uri.path),
    };
    // An empty path means the user's home directory.
    let remote = if uri.path.is_empty() {
        remote.trim_end_matches('/').to_owned()
    } else {
        remote
    };
    let mut options = vec![
        "reconnect".to_owned(),
        "ServerAliveInterval=10".to_owned(),
        "ServerAliveCountMax=3".to_owned(),
        "ConnectTimeout=10".to_owned(),
        "StrictHostKeyChecking=yes".to_owned(),
        format!(
            "UserKnownHostsFile={}",
            fuse_escape(&known_hosts().to_string_lossy())
        ),
        format!("GlobalKnownHostsFile={}", fuse_escape(&global)),
        "idmap=user".to_owned(),
        "dir_cache=yes".to_owned(),
        format!("fsname={}", fuse_escape(&uri.display())),
        "subtype=sftp".to_owned(),
    ];
    if let Some(port) = uri.port {
        options.push(format!("port={port}"));
    }
    if password {
        options.extend(
            [
                "password_stdin",
                "PreferredAuthentications=password\\,keyboard-interactive",
                "NumberOfPasswordPrompts=1",
                "PubkeyAuthentication=no",
            ]
            .map(str::to_owned),
        );
    } else {
        options.extend(
            [
                "BatchMode=yes",
                "PasswordAuthentication=no",
                "KbdInteractiveAuthentication=no",
            ]
            .map(str::to_owned),
        );
    }
    Spec::new(helper, Duration::ZERO)
        .arg("-f")
        .args(["-o", &options.join(",")])
        .arg(remote)
        .arg(mount_point)
}

/// What an SSH failure means.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SshFailure {
    /// Host key not yet trusted.
    UnknownHostKey,
    /// Host key differs from the trusted one.
    ChangedHostKey,
    /// Authentication refused.
    Auth,
    /// No connection.
    Unreachable,
    /// The remote folder does not exist.
    NoSuchPath,
    /// Anything else.
    Other,
}

/// Classify `sshfs`/`ssh` error output.
#[must_use]
pub fn classify_ssh(stderr: &str) -> SshFailure {
    let lower = stderr.to_lowercase();
    if lower.contains("remote host identification has changed")
        || lower.contains("host key for") && lower.contains("has changed")
    {
        SshFailure::ChangedHostKey
    } else if lower.contains("host key verification failed")
        || lower.contains("no matching host key")
        || lower.contains("host key is not known")
    {
        SshFailure::UnknownHostKey
    } else if lower.contains("permission denied")
        || lower.contains("authentication failed")
        || lower.contains("too many authentication failures")
    {
        SshFailure::Auth
    } else if lower.contains("no such file") {
        SshFailure::NoSuchPath
    } else if lower.contains("connection refused")
        || lower.contains("timed out")
        || lower.contains("no route")
        || lower.contains("could not resolve")
        || lower.contains("name or service not known")
        || lower.contains("network is unreachable")
        || lower.contains("connection reset")
        || lower.contains("connection closed")
    {
        SshFailure::Unreachable
    } else {
        SshFailure::Other
    }
}

/// The rclone backend name and environment for a WebDAV or FTP `uri`.
/// `obscured` is the rclone-obscured password, if any.
#[must_use]
pub fn rclone(
    helper: PathBuf,
    uri: &NetUri,
    mount_point: &Path,
    config: &Path,
    obscured: Option<&str>,
) -> Spec {
    let mut spec = Spec::new(helper, Duration::ZERO);
    let remote = match uri.scheme {
        Scheme::Dav | Scheme::Davs => {
            let scheme = if uri.scheme == Scheme::Davs {
                "https"
            } else {
                "http"
            };
            let host = if uri.host.contains(':') {
                format!("[{}]", uri.host)
            } else {
                uri.host.clone()
            };
            let port = uri.port.map(|p| format!(":{p}")).unwrap_or_default();
            let path: String = uri
                .path
                .split('/')
                .filter(|s| !s.is_empty())
                .map(|s| {
                    url::form_urlencoded::byte_serialize(s.as_bytes())
                        .collect::<String>()
                        .replace('+', "%20")
                })
                .collect::<Vec<_>>()
                .join("/");
            spec = spec.env(
                "RCLONE_WEBDAV_URL",
                format!("{scheme}://{host}{port}/{path}"),
            );
            if let Some(user) = &uri.user {
                spec = spec.env("RCLONE_WEBDAV_USER", user);
            }
            if let Some(pass) = obscured {
                spec = spec.env("RCLONE_WEBDAV_PASS", pass);
            }
            ":webdav:".to_owned()
        }
        _ => {
            spec = spec.env("RCLONE_FTP_HOST", &uri.host);
            if let Some(port) = uri.port {
                spec = spec.env("RCLONE_FTP_PORT", port.to_string());
            }
            spec = spec.env(
                "RCLONE_FTP_USER",
                uri.user.as_deref().unwrap_or("anonymous"),
            );
            if let Some(pass) = obscured {
                spec = spec.env("RCLONE_FTP_PASS", pass);
            }
            if uri.scheme == Scheme::Ftps {
                spec = spec.env("RCLONE_FTP_EXPLICIT_TLS", "true");
            }
            format!(":ftp:{}", uri.path)
        }
    };
    spec.args(["mount", "--config"])
        .arg(config)
        .arg(remote)
        .arg(mount_point)
        .args([
            "--contimeout=10s",
            "--timeout=30s",
            "--low-level-retries=2",
            "--retries=1",
            "--vfs-cache-mode=writes",
            // Upload as soon as a file is closed, so unmounting never strands data.
            "--vfs-write-back=0s",
            "--dir-cache-time=30s",
            "--attr-timeout=1s",
            "--log-level=ERROR",
        ])
        .arg(format!("--volname={}", uri.label()))
}

/// Explain an rclone failure.
#[must_use]
pub fn explain_rclone(code: Option<i32>, stderr: &str) -> Error {
    let lower = stderr.to_lowercase();
    if lower.contains("401")
        || lower.contains("unauthorized")
        || lower.contains("530")
        || lower.contains("login") && lower.contains("incorrect")
    {
        Error::AuthFailed(crate::tr!("error-login-refused"))
    } else if lower.contains("no such host")
        || lower.contains("connection refused")
        || lower.contains("timeout")
        || lower.contains("unreachable")
    {
        Error::Unreachable(crate::tr!("error-server-no-answer-unnamed"))
    } else if lower.contains("certificate") || lower.contains("x509") {
        Error::Failed(crate::tr!("error-certificate"))
    } else {
        Error::Failed(crate::tr!(
            "error-location-failed",
            code = code.unwrap_or(-1).to_string(),
            detail = last_line(stderr)
        ))
    }
}

/// `smbclient -L` share listing; the password, if any, goes in `PASSWD` of
/// that short-lived process only.
#[must_use]
pub fn smbclient_list(
    helper: PathBuf,
    uri: &NetUri,
    user: Option<&str>,
    domain: Option<&str>,
    has_password: bool,
) -> Spec {
    let mut spec = Spec::new(helper, Duration::from_secs(20))
        .args(["-g", "-t", "10", "-L"])
        .arg(format!("//{}", uri.host));
    if let Some(port) = uri.port {
        spec = spec.args(["-p", &port.to_string()]);
    }
    match user {
        Some(user) => {
            spec = spec.args(["-U", user]);
            if !has_password {
                spec = spec.arg("-N");
            }
        }
        None => spec = spec.arg("-N"),
    }
    if let Some(domain) = domain {
        spec = spec.args(["-W", domain]);
    }
    spec
}

/// Parse `smbclient -g -L` output into visible disk shares.
#[must_use]
pub fn parse_shares(output: &str, uri: &NetUri) -> Vec<crate::api::Share> {
    output
        .lines()
        .filter_map(|line| {
            let mut parts = line.splitn(3, '|');
            let (kind, name, comment) = (
                parts.next()?,
                parts.next()?,
                parts.next().unwrap_or_default(),
            );
            (kind == "Disk" && !name.ends_with('$') && crate::uri::valid_name(name, 80)).then(
                || {
                    let share = NetUri {
                        share: name.to_owned(),
                        path: String::new(),
                        ..uri.clone()
                    };
                    crate::api::Share {
                        name: name.to_owned(),
                        comment: comment.to_owned(),
                        uri: share.display(),
                    }
                },
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helper_command_lines_keep_secrets_and_addresses_contained() {
        let uri = NetUri::parse("sftp://bob@files.example:2222/srv/a,b").unwrap();
        let spec = sshfs(
            PathBuf::from("/usr/bin/sshfs"),
            &uri,
            Path::new("/run/media/bob/x"),
            true,
        );
        let args: Vec<String> = spec
            .args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let options = &args[2];
        assert!(
            options.contains("password_stdin") && !options.contains("BatchMode"),
            "password path"
        );
        assert!(
            options.contains("StrictHostKeyChecking=yes"),
            "never trust a host key silently"
        );
        assert!(
            options.contains("fsname=sftp://bob@files.example:2222/srv/a%2Cb"),
            "the display form carries no option separator"
        );
        assert_eq!(
            fuse_escape("a,b\\c"),
            "a\\,b\\\\c",
            "commas and backslashes escaped"
        );
        assert_eq!(
            args[3], "bob@files.example:/srv/a,b",
            "remote is one argument"
        );
        let keys = sshfs(
            PathBuf::from("/usr/bin/sshfs"),
            &uri,
            Path::new("/m"),
            false,
        );
        assert!(
            keys.args[2].to_string_lossy().contains("BatchMode=yes"),
            "key-only first attempt"
        );

        assert_eq!(
            classify_ssh("Host key verification failed.\nread: Connection reset by peer"),
            SshFailure::UnknownHostKey,
            "new host"
        );
        assert_eq!(
            classify_ssh("WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!"),
            SshFailure::ChangedHostKey,
            "changed host"
        );
        assert_eq!(
            classify_ssh("bob@h: Permission denied (publickey,password)."),
            SshFailure::Auth,
            "auth"
        );
        assert_eq!(
            classify_ssh("ssh: connect to host h port 22: Connection refused"),
            SshFailure::Unreachable,
            "down"
        );

        let dav = NetUri::parse("davs://alice@cloud.example/remote.php/dav/files/alice").unwrap();
        let spec = rclone(
            PathBuf::from("/usr/bin/rclone"),
            &dav,
            Path::new("/m"),
            Path::new("/c"),
            Some("OBSCURED"),
        );
        assert_eq!(
            spec.env.get("RCLONE_WEBDAV_URL").unwrap(),
            "https://cloud.example/remote.php/dav/files/alice",
            "dav url"
        );
        assert!(
            spec.args
                .iter()
                .all(|a| !a.to_string_lossy().contains("OBSCURED")),
            "password never in argv"
        );

        let server = NetUri::parse("smb://nas").unwrap();
        let shares = parse_shares(
            "Disk|photos|Family\nDisk|IPC$|\nIPC|IPC$|x\nDisk|bad,name|\nPrinter|hp|",
            &server,
        );
        assert_eq!(
            shares.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(),
            ["photos"],
            "visible disk shares only"
        );
        assert_eq!(shares[0].uri, "smb://nas/photos", "share address");
    }
}
