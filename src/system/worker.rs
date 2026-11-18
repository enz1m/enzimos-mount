//! The one-shot root worker: one kernel mount or unmount per process.
//!
//! The service runs this with a deadline. A mount system call waiting on an
//! unresponsive server is then the worker's problem: the service kills the
//! worker's process group, reports a timeout and stays responsive.
//!
//! Protocol: the request is one JSON line on standard input; for SMB the
//! password follows as the remaining standard-input bytes. The result is one
//! JSON line on standard output.

use rustix::fs::{Mode, OFlags};
use rustix::mount::{FsMountFlags, FsOpenFlags, MountAttrFlags, MoveMountFlags, UnmountFlags};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::ToSocketAddrs;
use std::path::PathBuf;

/// A kernel SMB mount request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CifsRequest {
    /// Server host name or address, already validated.
    pub host: String,
    /// TCP port, when not 445.
    pub port: Option<u16>,
    /// `share` or `share/sub/path`.
    pub share_path: String,
    /// User name; empty for guest access.
    pub username: String,
    /// Domain or workgroup.
    pub domain: Option<String>,
    /// Protocol dialect, e.g. `3.1.1`; `None` negotiates.
    pub version: Option<String>,
    /// Owner of every file.
    pub uid: u32,
    /// Group of every file.
    pub gid: u32,
    /// Prepared mount point.
    pub target: PathBuf,
}

/// The worker's answer.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WorkerResult {
    /// Success.
    pub ok: bool,
    /// Failure errno.
    pub errno: Option<i32>,
    /// Failure stage: `resolve`, `options`, `connect`, `attach`, `unmount`.
    pub stage: String,
    /// Kernel messages from the mount context.
    pub log: String,
}

/// SMB dialects accepted from users.
pub const SMB_VERSIONS: [&str; 6] = ["1.0", "2.0", "2.1", "3.0", "3.0.2", "3.1.1"];

fn fail(stage: &str, errno: Option<rustix::io::Errno>, log: String) -> WorkerResult {
    WorkerResult {
        ok: false,
        errno: errno.map(rustix::io::Errno::raw_os_error),
        stage: stage.to_owned(),
        log,
    }
}

fn drain_log(fs: &impl rustix::fd::AsFd) -> String {
    let mut log = String::new();
    let mut buffer = [0u8; 1024];
    for _ in 0..32 {
        match rustix::io::read(fs, &mut buffer) {
            Ok(n) if n > 0 => {
                log.push_str(&String::from_utf8_lossy(&buffer[..n]));
                log.push('\n');
            }
            _ => break,
        }
    }
    log
}

/// Resolve `host` to one address, preferring IPv4 like `mount.cifs`.
fn resolve(host: &str, port: u16) -> Option<std::net::IpAddr> {
    let addresses: Vec<_> = (host, port)
        .to_socket_addrs()
        .ok()?
        .map(|a| a.ip())
        .collect();
    addresses
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| addresses.first())
        .copied()
}

/// Make the SMB mount described by `request` with `password`.
#[must_use]
pub fn mount_cifs(request: &CifsRequest, password: &crate::secret::Secret) -> WorkerResult {
    let port = request.port.unwrap_or(445);
    let Some(address) = resolve(&request.host, port) else {
        return fail(
            "resolve",
            None,
            format!("could not resolve {}", request.host),
        );
    };
    let fs = match rustix::mount::fsopen("cifs", FsOpenFlags::FSOPEN_CLOEXEC) {
        Ok(fs) => fs,
        Err(e) => {
            return fail(
                "options",
                Some(e),
                "the kernel SMB client is unavailable".to_owned(),
            );
        }
    };
    let source = format!("//{}/{}", request.host, request.share_path);
    let uid = request.uid.to_string();
    let gid = request.gid.to_string();
    let address = address.to_string();
    let port_text = port.to_string();
    let mut strings: Vec<(&str, &str)> = vec![
        ("source", &source),
        ("ip", &address),
        ("port", &port_text),
        ("uid", &uid),
        ("gid", &gid),
        ("file_mode", "0600"),
        ("dir_mode", "0700"),
        ("echo_interval", "10"),
        ("iocharset", "utf8"),
    ];
    if let Some(version) = request.version.as_deref() {
        if !SMB_VERSIONS.contains(&version) {
            return fail("options", None, "unsupported SMB version".to_owned());
        }
        strings.push(("vers", version));
    }
    // SMB1 Unix extensions would let the server choose file modes; the
    // fixed modes above stay in force without them.
    if request.version.as_deref() == Some("1.0")
        && let Err(e) = rustix::mount::fsconfig_set_flag(&fs, "nounix")
    {
        return fail(
            "options",
            Some(e),
            format!("option nounix: {}", drain_log(&fs)),
        );
    }
    if request.username.is_empty() {
        strings.push(("sec", "none"));
    } else {
        strings.push(("username", &request.username));
        if let Some(domain) = request.domain.as_deref() {
            strings.push(("domain", domain));
        }
    }
    for (key, value) in strings {
        if let Err(e) = rustix::mount::fsconfig_set_string(&fs, key, value) {
            return fail(
                "options",
                Some(e),
                format!("option {key}: {}", drain_log(&fs)),
            );
        }
    }
    if !request.username.is_empty() {
        let text = match password.as_text() {
            Ok(text) => text,
            Err(e) => return fail("options", None, e),
        };
        if let Err(e) = rustix::mount::fsconfig_set_string(&fs, "password", text) {
            return fail("options", Some(e), drain_log(&fs));
        }
    }
    for flag in ["forceuid", "forcegid", "soft"] {
        if let Err(e) = rustix::mount::fsconfig_set_flag(&fs, flag) {
            return fail(
                "options",
                Some(e),
                format!("option {flag}: {}", drain_log(&fs)),
            );
        }
    }
    if let Err(e) = rustix::mount::fsconfig_create(&fs) {
        return fail("connect", Some(e), drain_log(&fs));
    }
    let mount = match rustix::mount::fsmount(
        &fs,
        FsMountFlags::FSMOUNT_CLOEXEC,
        MountAttrFlags::MOUNT_ATTR_NOSUID | MountAttrFlags::MOUNT_ATTR_NODEV,
    ) {
        Ok(mount) => mount,
        Err(e) => return fail("attach", Some(e), drain_log(&fs)),
    };
    attach(&mount, request)
}

fn attach(mount: &impl rustix::fd::AsFd, request: &CifsRequest) -> WorkerResult {
    let target = match rustix::fs::open(
        &request.target,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(target) => target,
        Err(e) => return fail("attach", Some(e), "mount point vanished".to_owned()),
    };
    match rustix::mount::move_mount(
        mount,
        "",
        &target,
        "",
        MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH | MoveMountFlags::MOVE_MOUNT_T_EMPTY_PATH,
    ) {
        Ok(()) => WorkerResult {
            ok: true,
            ..WorkerResult::default()
        },
        Err(e) => fail("attach", Some(e), String::new()),
    }
}

/// How hard to unmount.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnmountMode {
    /// A plain unmount; open files make it fail.
    Normal,
    /// A plain unmount (which flushes cached writes); if that fails, abort
    /// outstanding requests and detach. A server that stalls the teardown
    /// runs into the worker's deadline, after which the service asks for
    /// [`UnmountMode::Detach`].
    Force,
    /// Only a lazy detach, which never waits for the server.
    Detach,
}

/// Unmount `target`.
#[must_use]
pub fn unmount(target: &std::path::Path, mode: UnmountMode) -> WorkerResult {
    if mode != UnmountMode::Detach {
        match rustix::mount::unmount(target, UnmountFlags::NOFOLLOW) {
            Ok(()) => {
                return WorkerResult {
                    ok: true,
                    ..WorkerResult::default()
                };
            }
            Err(rustix::io::Errno::INVAL) => {
                return fail(
                    "unmount",
                    Some(rustix::io::Errno::INVAL),
                    "not a mount point".to_owned(),
                );
            }
            Err(e) if mode == UnmountMode::Normal => {
                return fail("unmount", Some(e), String::new());
            }
            Err(_) => {}
        }
    }
    if mode == UnmountMode::Force {
        let _ = rustix::mount::unmount(target, UnmountFlags::FORCE | UnmountFlags::NOFOLLOW);
    }
    match rustix::mount::unmount(target, UnmountFlags::DETACH | UnmountFlags::NOFOLLOW) {
        Ok(()) | Err(rustix::io::Errno::INVAL) => WorkerResult {
            ok: true,
            ..WorkerResult::default()
        },
        Err(e) => fail("unmount", Some(e), String::new()),
    }
}

/// Worker entry point; returns the process exit code.
#[must_use]
pub fn main(args: &[String]) -> i32 {
    let result = match args.get(1).map(String::as_str) {
        Some("cifs") => {
            let mut input = zeroize::Zeroizing::new(Vec::new());
            if std::io::stdin()
                .take(64 * 1024)
                .read_to_end(&mut input)
                .is_err()
            {
                return 2;
            }
            let Some(split) = input.iter().position(|b| *b == b'\n') else {
                return 2;
            };
            let Ok(request) = serde_json::from_slice::<CifsRequest>(&input[..split]) else {
                return 2;
            };
            let password = crate::secret::Secret::new(input[split + 1..].to_vec());
            mount_cifs(&request, &password)
        }
        Some("unmount") => {
            let mode = match args.get(3).map(String::as_str) {
                Some("0") => UnmountMode::Normal,
                Some("1") => UnmountMode::Force,
                Some("detach") => UnmountMode::Detach,
                _ => return 2,
            };
            let Some(target) = args.get(2) else { return 2 };
            unmount(std::path::Path::new(target), mode)
        }
        _ => return 2,
    };
    let mut stdout = std::io::stdout();
    let _ = serde_json::to_writer(&mut stdout, &result);
    let _ = stdout.write_all(b"\n");
    i32::from(!result.ok)
}
