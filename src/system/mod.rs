//! The root service `org.enzimos.MountSystem1`.
//!
//! It is D-Bus activated, exits after a minute without work, and does three
//! things for an authorized local user: kernel SMB and NFS mounts owned by
//! that user, mount points for the user's own FUSE mounts, and unmounting what
//! it created for that same user. Authorization is the polkit action
//! `org.enzimos.mount.user-mount` (active local sessions by default). Every
//! kernel call runs in a killable worker with a deadline.

pub mod boot;
pub mod mountpoint;
pub mod worker;

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::Semaphore;
use zbus::{OwnedFd, OwnedVariant, Variant};

/// Polkit action guarding every method.
pub const ACTION: &str = "org.enzimos.mount.user-mount";
/// Polkit action for storing a share to mount at startup (administrator).
pub const BOOT_ACTION: &str = "org.enzimos.mount.boot-mount";
/// Polkit action for the first SMB1 mount of a server by a user (administrator).
pub const SMB1_ACTION: &str = "org.enzimos.mount.smb1";
/// Deadline for one kernel SMB mount.
pub const MOUNT_TIMEOUT: Duration = Duration::from_secs(45);
/// Deadline for one unmount.
pub const UNMOUNT_TIMEOUT: Duration = Duration::from_secs(15);
/// Deadline for a lazy detach after a forced unmount timed out.
pub const DETACH_TIMEOUT: Duration = Duration::from_secs(5);
/// Exit after this long without requests.
pub const IDLE_EXIT: Duration = Duration::from_secs(60);
/// Prepared FUSE mount points unused for this long are cleaned up.
pub const STALE_PREPARED: Duration = Duration::from_secs(600);
/// Most registered mounts per user.
pub const MAX_PER_USER: usize = 64;
/// Most mounts one user may have in progress at once.
pub const MAX_PENDING_PER_USER: usize = 4;
/// Longest accepted label (bytes).
pub const MAX_LABEL: usize = 255;
/// Longest accepted path inside a share or export (bytes).
pub const MAX_PATH: usize = 1024;
/// Largest registry file read; anything bigger is not ours.
const MAX_REGISTRY: u64 = 1024 * 1024;
/// How long to wait for the registry lock (only root processes take it).
#[cfg(not(test))]
const LOCK_WAIT: Duration = Duration::from_secs(10);
#[cfg(test)]
const LOCK_WAIT: Duration = Duration::from_millis(300);

/// What the service created.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    /// A kernel mount this service made.
    Kernel,
    /// A mount point handed to the user for a FUSE mount.
    Fuse,
}

/// One mount point the service is responsible for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// Owning user.
    pub uid: u32,
    /// Mount point.
    pub path: PathBuf,
    /// Kind.
    pub kind: EntryKind,
    /// `smb`, `nfs` or `fuse`.
    pub protocol: String,
    /// Source as mounted, e.g. `//nas/share`.
    pub source: String,
    /// Creation time, seconds since the epoch.
    pub created: u64,
    /// Mounted at startup from a stored boot entry.
    #[serde(default)]
    pub boot: bool,
    /// A kernel mount in progress: reserved before the mount system call so
    /// a mount that attaches late (or a crash) cannot leave it untracked.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub pending: bool,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn state_dir() -> PathBuf {
    std::env::var_os("ENZIMOS_MOUNT_STATE_DIR")
        .map_or_else(|| PathBuf::from("/run/enzimos-mount"), PathBuf::from)
}

fn worker_path() -> PathBuf {
    std::env::var_os("ENZIMOS_MOUNT_WORKER").map_or_else(
        || PathBuf::from("/usr/lib/enzimos-mount/enzimos-mount-worker"),
        PathBuf::from,
    )
}

/// Load the registry, dropping entries whose mounts are gone.
///
/// # Errors
/// When the registry cannot be locked or read.
pub fn load_registry() -> Result<Vec<Entry>> {
    with_registry(|entries| entries.clone())
}

fn registry_error(what: &str, error: impl std::fmt::Display) -> Error {
    crate::log!(err, "mount registry {what}: {error}");
    Error::Failed(crate::tr!("error-registry"))
}

/// The root-only state directory and its exclusive lock. Only root can open
/// the lock, so nobody else can hold it.
fn lock_registry(dir: &Path) -> Result<std::fs::File> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
    match std::fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(registry_error("directory", e)),
    }
    let meta = std::fs::symlink_metadata(dir).map_err(|e| registry_error("directory", e))?;
    if !meta.is_dir() || meta.uid() != rustix::process::geteuid().as_raw() {
        return Err(registry_error(
            "directory",
            "not a directory owned by this service",
        ));
    }
    if meta.mode() & 0o077 != 0 {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| registry_error("directory", e))?;
    }
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits().cast_signed())
        .open(dir.join("registry.lock"))
        .map_err(|e| registry_error("lock", e))?;
    let deadline = Instant::now() + LOCK_WAIT;
    loop {
        match rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => return Ok(file),
            Err(rustix::io::Errno::WOULDBLOCK | rustix::io::Errno::INTR)
                if Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => return Err(registry_error("lock", e)),
        }
    }
}

/// Run `change` on the registry under an exclusive lock shared by the D-Bus
/// service and the boot service, then save it. Entries whose mounts are gone
/// (and stale prepared FUSE folders and reservations) are dropped first.
///
/// # Errors
/// When the registry cannot be locked, or exists but cannot be read: the
/// service then refuses to work rather than lose track of mounts.
pub fn with_registry<T>(change: impl FnOnce(&mut Vec<Entry>) -> T) -> Result<T> {
    with_registry_in(&state_dir(), change)
}

fn with_registry_in<T>(dir: &Path, change: impl FnOnce(&mut Vec<Entry>) -> T) -> Result<T> {
    let _lock = lock_registry(dir)?;
    let path = dir.join("registry.json");
    let entries: Vec<Entry> = match std::fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(registry_error("read", e)),
        Ok(meta) if !meta.is_file() || meta.len() > MAX_REGISTRY => {
            return Err(registry_error("read", "unexpected file"));
        }
        Ok(_) => {
            let bytes = std::fs::read(&path).map_err(|e| registry_error("read", e))?;
            serde_json::from_slice(&bytes).map_err(|e| registry_error("parse", e))?
        }
    };
    // Without a readable mount table nothing is known to be gone, so nothing is pruned.
    let mounts = crate::mountinfo::current().ok();
    let mut entries: Vec<Entry> = entries
        .into_iter()
        .filter(|entry| {
            let Some(mounts) = &mounts else {
                return true;
            };
            let mounted = crate::mountinfo::at(mounts, &entry.path).is_some();
            let fresh = now().saturating_sub(entry.created) < STALE_PREPARED.as_secs();
            let keep = mounted || ((entry.kind == EntryKind::Fuse || entry.pending) && fresh);
            if !keep {
                let _ = std::fs::remove_dir(&entry.path);
            }
            keep
        })
        .collect();
    let result = change(&mut entries);
    save_registry(dir, &entries)?;
    Ok(result)
}

fn save_registry(dir: &Path, entries: &[Entry]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = dir.join(".registry.json.tmp");
    let bytes = serde_json::to_vec(entries).map_err(|e| registry_error("save", e))?;
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits().cast_signed())
        .open(&tmp)
        .and_then(|mut f| std::io::Write::write_all(&mut f, &bytes))
        .and_then(|()| std::fs::rename(&tmp, dir.join("registry.json")))
        .map_err(|e| registry_error("save", e))
}

fn mount_table_error(_: std::io::Error) -> Error {
    Error::Failed(crate::tr!("error-mount-table"))
}

/// After a mount attempt: keep the entry for `path` if something is mounted
/// there (even a mount that attached after its deadline), drop it otherwise.
/// Without a readable mount table, a failed attempt stays a reservation.
fn settle(uid: u32, path: &Path, succeeded: bool) {
    let mounted = match crate::mountinfo::current() {
        Ok(table) => Some(crate::mountinfo::at(&table, path).is_some()),
        Err(_) => succeeded.then_some(true),
    };
    let _ = with_registry(|registry| match mounted {
        Some(true) => {
            for entry in registry
                .iter_mut()
                .filter(|e| e.uid == uid && e.path == path)
            {
                entry.pending = false;
            }
        }
        Some(false) => registry.retain(|e| !(e.uid == uid && e.path == path)),
        None => {}
    });
}

/// File of servers each user may reach with SMB1 (approved once by an administrator).
fn smb1_file() -> PathBuf {
    boot::dir()
        .parent()
        .map_or_else(
            || PathBuf::from("/var/lib/enzimos-mount"),
            Path::to_path_buf,
        )
        .join("smb1-allowed.json")
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Smb1Allowed {
    uid: u32,
    host: String,
}

fn smb1_allowed(uid: u32, host: &str) -> bool {
    std::fs::read(smb1_file())
        .ok()
        .and_then(|b| serde_json::from_slice::<Vec<Smb1Allowed>>(&b).ok())
        .is_some_and(|list| {
            list.iter()
                .any(|a| a.uid == uid && a.host.eq_ignore_ascii_case(host))
        })
}

fn allow_smb1(uid: u32, host: &str) {
    use std::os::unix::fs::OpenOptionsExt;
    let path = smb1_file();
    let mut list: Vec<Smb1Allowed> = std::fs::read(&path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    list.retain(|a| !(a.uid == uid && a.host.eq_ignore_ascii_case(host)));
    list.push(Smb1Allowed {
        uid,
        host: host.to_ascii_lowercase(),
    });
    let excess = list.len().saturating_sub(256);
    list.drain(..excess);
    let Some(dir) = path.parent() else { return };
    let _ = std::fs::create_dir_all(dir);
    let tmp = dir.join(".smb1-allowed.json.tmp");
    let written = serde_json::to_vec(&list).ok().is_some_and(|bytes| {
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits().cast_signed())
            .open(&tmp)
            .and_then(|mut f| std::io::Write::write_all(&mut f, &bytes))
            .is_ok()
    });
    if written {
        let _ = std::fs::rename(&tmp, &path);
    }
}

/// Map a failed worker to a user-presentable error.
#[must_use]
pub fn classify(result: &worker::WorkerResult, host: &str, share: &str, had_user: bool) -> Error {
    const EPERM: i32 = 1;
    const ENOENT: i32 = 2;
    const ENXIO: i32 = 6;
    const EACCES: i32 = 13;
    const ENODEV: i32 = 19;
    const EPROTONOSUPPORT: i32 = 93;
    const EOPNOTSUPP: i32 = 95;
    const ENETUNREACH: i32 = 101;
    const ECONNRESET: i32 = 104;
    const EALREADY: i32 = 114;
    const EINPROGRESS: i32 = 115;
    const ETIMEDOUT: i32 = 110;
    const ECONNREFUSED: i32 = 111;
    const EHOSTDOWN: i32 = 112;
    const EHOSTUNREACH: i32 = 113;
    const EKEYEXPIRED: i32 = 127;
    const EKEYREJECTED: i32 = 129;
    if result.stage == "resolve" {
        return Error::Unreachable(crate::tr!("error-server-not-found", host = host));
    }
    match result.errno {
        Some(EACCES | EPERM | EKEYREJECTED | EKEYEXPIRED) if result.stage == "connect" => {
            if had_user {
                Error::AuthFailed(crate::tr!("error-login-refused"))
            } else {
                Error::NeedsCredentials(String::new())
            }
        }
        Some(ENOENT | ENXIO) if result.stage == "connect" => {
            Error::Failed(crate::tr!("error-no-such-share", share = share))
        }
        Some(ENODEV) => Error::Unsupported(crate::tr!("error-no-cifs")),
        Some(EOPNOTSUPP | EPROTONOSUPPORT) => {
            Error::ProtocolMismatch(crate::tr!("error-smb1-only", host = host))
        }
        Some(
            ENETUNREACH | ECONNRESET | ETIMEDOUT | ECONNREFUSED | EHOSTDOWN | EHOSTUNREACH
            | EALREADY | EINPROGRESS,
        ) => Error::Unreachable(crate::tr!("error-server-no-answer", host = host)),
        Some(errno) => Error::Failed(crate::tr!(
            "error-share-failed",
            detail = std::io::Error::from_raw_os_error(errno).to_string()
        )),
        None => Error::Failed(crate::tr!("error-share-failed", detail = result.log.trim())),
    }
}

/// Validated NFS parameters from a request.
#[derive(Debug, PartialEq, Eq)]
pub struct NfsParams {
    /// Server.
    pub host: String,
    /// Port.
    pub port: Option<u16>,
    /// Export path without leading slash.
    pub path: String,
    /// Mount folder label.
    pub label: String,
}

/// Validate a `MountNfs` parameter dictionary.
///
/// # Errors
/// [`Error::Invalid`] naming the bad field.
pub fn nfs_params(params: &HashMap<String, OwnedVariant>) -> Result<NfsParams> {
    let host = string(params, "host")
        .filter(|h| crate::uri::valid_host(h))
        .ok_or_else(|| Error::Invalid(crate::tr!("error-invalid-field", field = "host")))?;
    let path = string(params, "path").unwrap_or_default();
    if path.len() > MAX_PATH
        || path
            .split('/')
            .any(|s| s == ".." || s.chars().any(char::is_control) || s.contains(','))
    {
        return Err(Error::Invalid(crate::tr!(
            "error-invalid-field",
            field = "path"
        )));
    }
    let port = params
        .get("port")
        .and_then(|v| u16::try_from(v.clone()).ok())
        .filter(|p| *p != 0);
    let label = string(params, "label").unwrap_or_else(|| host.clone());
    if label.len() > MAX_LABEL {
        return Err(Error::Invalid(crate::tr!(
            "error-invalid-field",
            field = "label"
        )));
    }
    Ok(NfsParams {
        host,
        port,
        path,
        label,
    })
}

/// Validated SMB parameters from a request.
#[derive(Debug, PartialEq, Eq)]
pub struct SmbParams {
    /// Server.
    pub host: String,
    /// Port.
    pub port: Option<u16>,
    /// Share.
    pub share: String,
    /// Sub-path inside the share.
    pub path: String,
    /// User; empty for guest.
    pub username: String,
    /// Domain.
    pub domain: Option<String>,
    /// Dialect.
    pub version: Option<String>,
    /// Mount folder label.
    pub label: String,
}

pub(crate) fn string(params: &HashMap<String, OwnedVariant>, key: &str) -> Option<String> {
    params
        .get(key)
        .and_then(|v| String::try_from(v.clone()).ok())
        .filter(|s| !s.is_empty())
}

/// Validate a `MountSmb` parameter dictionary.
///
/// # Errors
/// [`Error::Invalid`] naming the bad field.
pub fn smb_params(params: &HashMap<String, OwnedVariant>) -> Result<SmbParams> {
    let invalid = |what: &str| Error::Invalid(crate::tr!("error-invalid-field", field = what));
    let host = string(params, "host")
        .filter(|h| crate::uri::valid_host(h))
        .ok_or_else(|| invalid("server"))?;
    let share = string(params, "share")
        .filter(|s| crate::uri::valid_name(s, 80))
        .ok_or_else(|| invalid("share"))?;
    let path = string(params, "path").unwrap_or_default();
    if path.len() > MAX_PATH
        || path.split('/').any(|s| {
            s == ".." || s == "." || s.chars().any(char::is_control) || s.contains(['\\', ','])
        })
    {
        return Err(invalid("folder path"));
    }
    let username = string(params, "username").unwrap_or_default();
    if !username.is_empty() && !crate::uri::valid_name(&username, 128) {
        return Err(invalid("user name"));
    }
    let domain = string(params, "domain");
    if domain
        .as_deref()
        .is_some_and(|d| !crate::uri::valid_name(d, 64))
    {
        return Err(invalid("domain"));
    }
    let version = string(params, "version");
    if version
        .as_deref()
        .is_some_and(|v| !worker::SMB_VERSIONS.contains(&v))
    {
        return Err(invalid("SMB version"));
    }
    let port = params
        .get("port")
        .and_then(|v| u16::try_from(v.clone()).ok())
        .filter(|p| *p != 0);
    let label = string(params, "label").unwrap_or_else(|| format!("{share} on {host}"));
    if label.len() > MAX_LABEL {
        return Err(invalid("label"));
    }
    Ok(SmbParams {
        host,
        port,
        share,
        path,
        username,
        domain,
        version,
        label,
    })
}

/// The user a mount is made for.
pub struct Caller {
    uid: u32,
    gid: u32,
    name: String,
}

impl Caller {
    /// Look up a local user.
    ///
    /// # Errors
    /// When the user does not exist.
    pub fn from_uid(uid: u32) -> Result<Self> {
        let user = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
            .ok()
            .flatten()
            .ok_or_else(|| Error::NotAuthorized(crate::tr!("error-unknown-user")))?;
        Ok(Self {
            uid,
            gid: user.gid.as_raw(),
            name: user.name,
        })
    }
}

/// The service object.
pub struct Service {
    active: Arc<AtomicUsize>,
    last: Arc<std::sync::Mutex<Instant>>,
    /// Mount workers and helpers running at once.
    mounts: Semaphore,
    /// Unmount workers, separate so stuck mounts cannot starve unmounting.
    unmounts: Semaphore,
    /// Mounts in progress per user.
    pending: Arc<std::sync::Mutex<HashMap<u32, usize>>>,
}

/// One user's mount in progress; released on drop.
struct PendingSlot {
    pending: Arc<std::sync::Mutex<HashMap<u32, usize>>>,
    uid: u32,
}

impl Drop for PendingSlot {
    fn drop(&mut self) {
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(count) = pending.get_mut(&self.uid) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                pending.remove(&self.uid);
            }
        }
    }
}

struct Busy {
    active: Arc<AtomicUsize>,
    last: Arc<std::sync::Mutex<Instant>>,
}

impl Drop for Busy {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::SeqCst);
        *self
            .last
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Instant::now();
    }
}

impl Service {
    /// A service with no activity yet.
    #[must_use]
    pub fn new() -> Self {
        Self {
            active: Arc::new(AtomicUsize::new(0)),
            last: Arc::new(std::sync::Mutex::new(Instant::now())),
            mounts: Semaphore::new(8),
            unmounts: Semaphore::new(8),
            pending: Arc::new(std::sync::Mutex::new(HashMap::new())),
        }
    }

    fn pending_slot(&self, uid: u32) -> Result<PendingSlot> {
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let count = pending.entry(uid).or_insert(0);
        if *count >= MAX_PENDING_PER_USER {
            return Err(Error::Busy(crate::tr!("error-too-many-pending")));
        }
        *count += 1;
        Ok(PendingSlot {
            pending: Arc::clone(&self.pending),
            uid,
        })
    }

    fn busy(&self) -> Busy {
        self.active.fetch_add(1, Ordering::SeqCst);
        Busy {
            active: Arc::clone(&self.active),
            last: Arc::clone(&self.last),
        }
    }

    async fn caller(
        &self,
        header: &zbus::message::Header<'_>,
        connection: &zbus::Connection,
    ) -> Result<Caller> {
        self.authorized(header, connection, ACTION, &[]).await
    }

    /// Check `action` for the sender. `details` are shown in the polkit
    /// dialog (the action's message names them as `$(key)`).
    async fn authorized(
        &self,
        header: &zbus::message::Header<'_>,
        connection: &zbus::Connection,
        action: &str,
        details: &[(&str, &str)],
    ) -> Result<Caller> {
        let sender = header
            .sender()
            .ok_or_else(|| Error::NotAuthorized(crate::tr!("error-unknown-caller")))?
            .to_owned();
        let dbus = zbus::fdo::DBusProxy::new(connection).await?;
        let uid = dbus
            .get_connection_unix_user(zbus::names::BusName::Unique(sender.clone()))
            .await
            .map_err(|e| Error::NotAuthorized(e.to_string()))?;
        let authority = zbus::Proxy::new(
            connection,
            "org.freedesktop.PolicyKit1",
            "/org/freedesktop/PolicyKit1/Authority",
            "org.freedesktop.PolicyKit1.Authority",
        )
        .await?;
        let mut subject_details: HashMap<&str, Variant<'_>> = HashMap::new();
        subject_details.insert("name", Variant::from(sender.as_str()));
        let subject = ("system-bus-name", subject_details);
        let details: HashMap<&str, &str> = details.iter().copied().collect();
        let body = (subject, action, details, 1u32, "");
        let call = authority
            .call::<_, _, (bool, bool, HashMap<String, String>)>("CheckAuthorization", &body);
        let (authorized, _, _) = tokio::time::timeout(Duration::from_secs(120), call)
            .await
            .map_err(|_| Error::NotAuthorized(crate::tr!("error-authorization-timeout")))?
            .map_err(|e| {
                Error::NotAuthorized(crate::tr!(
                    "error-authorization-failed",
                    error = e.to_string()
                ))
            })?;
        if !authorized {
            return Err(Error::NotAuthorized(crate::tr!("error-not-allowed")));
        }
        Caller::from_uid(uid)
    }

    /// Record `entry` (kernel mounts as a reservation before mounting),
    /// within the per-user limit.
    fn register(entry: Entry) -> Result<()> {
        with_registry(|registry| {
            if registry.iter().filter(|e| e.uid == entry.uid).count() >= MAX_PER_USER {
                return Err(Error::Failed(crate::tr!("error-too-many-mounts")));
            }
            registry.push(entry);
            Ok(())
        })?
    }

    async fn run_worker(
        &self,
        args: &[&str],
        stdin: Option<zeroize::Zeroizing<Vec<u8>>>,
        timeout: Duration,
    ) -> Result<worker::WorkerResult> {
        let pool = if args.first() == Some(&"unmount") {
            &self.unmounts
        } else {
            &self.mounts
        };
        let _permit = tokio::time::timeout(MOUNT_TIMEOUT, pool.acquire())
            .await
            .map_err(|_| Error::Busy(crate::tr!("error-service-busy")))?
            .map_err(|_| Error::Failed(crate::tr!("error-shutting-down")))?;
        let mut spec = crate::process::Spec::new(worker_path(), timeout).args(args.iter().copied());
        spec.stdin = stdin;
        match crate::process::run(spec).await {
            Ok(output) => serde_json::from_str(output.stdout.trim()).map_err(|_| {
                Error::Failed(crate::tr!(
                    "error-worker-failed",
                    detail = output.stderr.trim()
                ))
            }),
            Err(crate::process::RunError::Timeout) => {
                Err(Error::Timeout(crate::tr!("error-server-timeout")))
            }
            Err(e) => Err(Error::Failed(e.to_string())),
        }
    }

    /// Make a kernel SMB mount for `caller`.
    ///
    /// # Errors
    /// Classified mount failures.
    pub async fn do_mount_smb(
        &self,
        caller: &Caller,
        params: &SmbParams,
        password: &crate::secret::Secret,
        boot: bool,
    ) -> Result<PathBuf> {
        let _slot = self.pending_slot(caller.uid)?;
        let (dir, dir_path) =
            mountpoint::user_dir(&caller.name, caller.uid).map_err(Error::Failed)?;
        let target =
            mountpoint::create(&dir, &dir_path, &params.label, None).map_err(Error::Failed)?;
        let share_path = if params.path.is_empty() {
            params.share.clone()
        } else {
            format!("{}/{}", params.share, params.path)
        };
        let name = target
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let reserved = Self::register(Entry {
            uid: caller.uid,
            path: target.clone(),
            kind: EntryKind::Kernel,
            protocol: "smb".to_owned(),
            source: format!("//{}/{share_path}", params.host),
            created: now(),
            boot,
            pending: true,
        });
        if let Err(error) = reserved {
            let _ = mountpoint::remove(&dir, &name);
            return Err(error);
        }
        let request = worker::CifsRequest {
            host: params.host.clone(),
            port: params.port,
            share_path: share_path.clone(),
            username: params.username.clone(),
            domain: params.domain.clone(),
            version: params.version.clone(),
            uid: caller.uid,
            gid: caller.gid,
            target: target.clone(),
        };
        let mut input = zeroize::Zeroizing::new(
            serde_json::to_vec(&request).map_err(|e| Error::Failed(e.to_string()))?,
        );
        input.push(b'\n');
        input.extend_from_slice(password.expose());
        let outcome = self.run_worker(&["cifs"], Some(input), MOUNT_TIMEOUT).await;
        let outcome = match outcome {
            Ok(result) if result.ok => Ok(()),
            Ok(result) => {
                crate::log!(
                    info,
                    "smb mount of //{}/{} for uid {} failed: {:?} {}",
                    params.host,
                    share_path,
                    caller.uid,
                    result.errno,
                    result.log.trim()
                );
                Err(classify(
                    &result,
                    &params.host,
                    &params.share,
                    !params.username.is_empty(),
                ))
            }
            Err(error) => {
                // A timed-out worker may still attach the mount later; detach it.
                let _ = self.unmount_path(&target, true).await;
                Err(error)
            }
        };
        if outcome.is_err() {
            let _ = mountpoint::remove(&dir, &name);
        }
        // Whatever happened, the registry now tracks exactly what is mounted.
        settle(caller.uid, &target, outcome.is_ok());
        outcome?;
        crate::log!(
            info,
            "mounted //{}/{} for uid {} at {}",
            params.host,
            share_path,
            caller.uid,
            target.display()
        );
        Ok(target)
    }

    /// Make a kernel NFS mount for `caller`.
    ///
    /// # Errors
    /// Classified mount failures.
    pub async fn do_mount_nfs(
        &self,
        caller: &Caller,
        params: &NfsParams,
        boot: bool,
    ) -> Result<PathBuf> {
        let helper = crate::process::helper("mount.nfs")
            .ok_or_else(|| Error::Unsupported(crate::tr!("error-nfs-missing")))?;
        let _slot = self.pending_slot(caller.uid)?;
        let (dir, dir_path) =
            mountpoint::user_dir(&caller.name, caller.uid).map_err(Error::Failed)?;
        let target =
            mountpoint::create(&dir, &dir_path, &params.label, None).map_err(Error::Failed)?;
        let name = target
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let host = &params.host;
        let export = &params.path;
        let source = if host.contains(':') {
            format!("[{host}]:/{export}")
        } else {
            format!("{host}:/{export}")
        };
        let reserved = Self::register(Entry {
            uid: caller.uid,
            path: target.clone(),
            kind: EntryKind::Kernel,
            protocol: "nfs".to_owned(),
            source: source.clone(),
            created: now(),
            boot,
            pending: true,
        });
        if let Err(error) = reserved {
            let _ = mountpoint::remove(&dir, &name);
            return Err(error);
        }
        let mut options = "nosuid,nodev,soft,timeo=100,retrans=2".to_owned();
        if let Some(port) = params.port {
            options = format!("{options},port={port}");
        }
        let spec = crate::process::Spec::new(helper, MOUNT_TIMEOUT)
            .arg(&source)
            .arg(&target)
            .args(["-o", &options]);
        let output = match tokio::time::timeout(MOUNT_TIMEOUT, self.mounts.acquire()).await {
            Ok(Ok(_permit)) => Some(crate::process::run(spec).await),
            _ => None,
        };
        let outcome = match output {
            None => Err(Error::Busy(crate::tr!("error-service-busy"))),
            Some(Ok(output)) if output.success() => Ok(()),
            Some(Ok(output)) => {
                let text = output.stderr.trim().to_owned();
                Err(
                    if text.contains("access denied") || text.contains("Permission denied") {
                        Error::NotAuthorized(crate::tr!("error-export-refused"))
                    } else if text.contains("No route")
                        || text.contains("timed out")
                        || text.contains("refused")
                    {
                        Error::Unreachable(crate::tr!("error-server-no-answer", host = host))
                    } else {
                        Error::Failed(crate::tr!("error-export-failed", detail = text))
                    },
                )
            }
            Some(Err(error)) => {
                let _ = self.unmount_path(&target, true).await;
                Err(match error {
                    crate::process::RunError::Timeout => {
                        Error::Timeout(crate::tr!("error-server-timeout"))
                    }
                    other => Error::Failed(other.to_string()),
                })
            }
        };
        if outcome.is_err() {
            let _ = mountpoint::remove(&dir, &name);
        }
        settle(caller.uid, &target, outcome.is_ok());
        outcome?;
        Ok(target)
    }

    async fn unix_user(
        &self,
        header: &zbus::message::Header<'_>,
        connection: &zbus::Connection,
    ) -> Result<u32> {
        let sender = header
            .sender()
            .ok_or_else(|| Error::NotAuthorized(crate::tr!("error-unknown-caller")))?
            .to_owned();
        let dbus = zbus::fdo::DBusProxy::new(connection).await?;
        dbus.get_connection_unix_user(zbus::names::BusName::Unique(sender))
            .await
            .map_err(|e| Error::NotAuthorized(e.to_string()))
    }

    pub(crate) async fn unmount_path(&self, path: &Path, force: bool) -> Result<()> {
        let text = path.to_string_lossy().into_owned();
        let result = match self
            .run_worker(
                &["unmount", &text, if force { "1" } else { "0" }],
                None,
                UNMOUNT_TIMEOUT,
            )
            .await
        {
            // A server can stall even the forced teardown; a lazy detach
            // alone never waits for it.
            Err(Error::Timeout(_)) if force => {
                self.run_worker(&["unmount", &text, "detach"], None, DETACH_TIMEOUT)
                    .await?
            }
            other => other?,
        };
        if result.ok || result.errno == Some(22) {
            return Ok(());
        }
        if result.errno == Some(16) {
            return Err(Error::Busy(if force {
                crate::tr!("error-detach-failed")
            } else {
                crate::tr!("error-unmount-busy")
            }));
        }
        Err(Error::Failed(crate::tr!(
            "error-unmount-failed",
            detail =
                std::io::Error::from_raw_os_error(result.errno.unwrap_or_default()).to_string()
        )))
    }
}

#[zbus::interface(name = "org.enzimos.MountSystem1")]
impl Service {
    /// Mount an SMB share for the caller with the in-kernel client.
    async fn mount_smb(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        params: HashMap<String, OwnedVariant>,
        secret: OwnedFd,
    ) -> Result<String> {
        let _busy = self.busy();
        let caller = self.caller(&header, connection).await?;
        let params = smb_params(&params)?;
        let password = crate::secret::from_fd(&secret).map_err(Error::Invalid)?;
        if params.version.as_deref() == Some("1.0") && !smb1_allowed(caller.uid, &params.host) {
            // The old protocol exposes the kernel to more of what a server
            // sends; an administrator allows it once per user and server.
            self.authorized(
                &header,
                connection,
                SMB1_ACTION,
                &[("server", params.host.as_str())],
            )
            .await?;
            allow_smb1(caller.uid, &params.host);
        }
        self.do_mount_smb(&caller, &params, &password, false)
            .await
            .map(|p| p.to_string_lossy().into_owned())
    }

    /// Mount an NFS export for the caller.
    async fn mount_nfs(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        params: HashMap<String, OwnedVariant>,
    ) -> Result<String> {
        let _busy = self.busy();
        let caller = self.caller(&header, connection).await?;
        let params = nfs_params(&params)?;
        self.do_mount_nfs(&caller, &params, false)
            .await
            .map(|p| p.to_string_lossy().into_owned())
    }

    /// Store (or, with `enabled` false, remove) a share the caller wants
    /// mounted at startup. Storing needs administrator approval; the password
    /// is encrypted at rest with `systemd-creds` (host key or TPM).
    async fn set_boot_mount(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        params: HashMap<String, OwnedVariant>,
        secret: OwnedFd,
        enabled: bool,
    ) -> Result<()> {
        let _busy = self.busy();
        let id = string(&params, "id")
            .filter(|i| boot::valid_id(i))
            .ok_or_else(|| Error::Invalid(crate::tr!("error-invalid-field", field = "id")))?;
        if !enabled {
            let caller = self.caller(&header, connection).await?;
            boot::remove(caller.uid, &id);
            return Ok(());
        }
        // The owner may refresh the password of an entry an administrator
        // already approved; anything new or changed needs approval again.
        let uid = self.unix_user(&header, connection).await?;
        let entry = boot::BootEntry::from_params(&id, uid, &params)?;
        let unchanged = boot::list().contains(&entry);
        let (server, share) = entry.describe();
        let details = [("server", server.as_str()), ("share", share.as_str())];
        let caller = if unchanged {
            self.authorized(&header, connection, ACTION, &[]).await?
        } else {
            self.authorized(&header, connection, BOOT_ACTION, &details)
                .await?
        };
        if caller.uid != uid {
            return Err(Error::NotAuthorized(crate::tr!("error-unknown-caller")));
        }
        let password = crate::secret::from_fd(&secret).map_err(Error::Invalid)?;
        boot::store(&entry, &password).await
    }

    /// The caller's startup shares as JSON (`[{id, label, protocol}]`).
    async fn boot_mounts(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> Result<String> {
        let _busy = self.busy();
        let uid = self.unix_user(&header, connection).await?;
        let mine: Vec<serde_json::Value> = boot::list()
            .into_iter()
            .filter(|e| e.uid == uid)
            .map(|e| serde_json::json!({"id": e.id, "label": e.label, "protocol": e.protocol}))
            .collect();
        serde_json::to_string(&mine).map_err(|e| Error::Failed(e.to_string()))
    }

    /// Create a mount point owned by the caller for a FUSE mount.
    async fn prepare_mountpoint(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        label: String,
    ) -> Result<String> {
        let _busy = self.busy();
        let caller = self.caller(&header, connection).await?;
        if label.len() > MAX_LABEL {
            return Err(Error::Invalid(crate::tr!(
                "error-invalid-field",
                field = "label"
            )));
        }
        let (dir, dir_path) =
            mountpoint::user_dir(&caller.name, caller.uid).map_err(Error::Failed)?;
        let target = mountpoint::create(&dir, &dir_path, &label, Some((caller.uid, caller.gid)))
            .map_err(Error::Failed)?;
        let entry = Entry {
            uid: caller.uid,
            path: target.clone(),
            kind: EntryKind::Fuse,
            protocol: "fuse".to_owned(),
            source: target
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
            created: now(),
            boot: false,
            pending: false,
        };
        if let Err(error) = Self::register(entry) {
            let _ = std::fs::remove_dir(&target);
            return Err(error);
        }
        Ok(target.to_string_lossy().into_owned())
    }

    /// Remove a mount point the caller no longer uses, unmounting a kernel
    /// mount first. `force` aborts outstanding requests on an unresponsive
    /// server and detaches the mount; it also detaches a stuck FUSE mount.
    async fn unmount(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        path: String,
        force: bool,
    ) -> Result<()> {
        let _busy = self.busy();
        let caller = self.caller(&header, connection).await?;
        let path = PathBuf::from(path);
        let name = mountpoint::split_owned(&path, &caller.name)
            .ok_or_else(|| Error::NotFound(crate::tr!("error-not-your-mount")))?;
        let entry = with_registry(|registry| {
            registry
                .iter()
                .find(|e| e.uid == caller.uid && e.path == path)
                .cloned()
        })?
        .ok_or_else(|| Error::NotFound(crate::tr!("error-not-your-mount")))?;
        if entry.pending {
            return Err(Error::Busy(crate::tr!("error-item-busy")));
        }
        // Unmount until nothing is mounted at the folder: the user may have
        // stacked a mount of their own on top of the kernel mount.
        for round in 0.. {
            let table = crate::mountinfo::current().map_err(mount_table_error)?;
            if crate::mountinfo::at(&table, &path).is_none() {
                break;
            }
            if entry.kind == EntryKind::Fuse && !force {
                return Err(Error::Busy(crate::tr!("error-files-open")));
            }
            if round == 4 {
                return Err(Error::Busy(crate::tr!("error-unmount-busy")));
            }
            self.unmount_path(&path, force).await?;
        }
        let (dir, _) = mountpoint::user_dir(&caller.name, caller.uid).map_err(Error::Failed)?;
        let _ = mountpoint::remove(&dir, &name);
        with_registry(|registry| registry.retain(|e| !(e.uid == caller.uid && e.path == path)))?;
        Ok(())
    }

    /// The caller's registered mounts as JSON (`[Entry]` plus `mounted`).
    async fn list(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> Result<String> {
        let _busy = self.busy();
        let sender = header
            .sender()
            .ok_or_else(|| Error::NotAuthorized(crate::tr!("error-unknown-caller")))?
            .to_owned();
        let dbus = zbus::fdo::DBusProxy::new(connection).await?;
        let uid = dbus
            .get_connection_unix_user(zbus::names::BusName::Unique(sender))
            .await
            .map_err(|e| Error::NotAuthorized(e.to_string()))?;
        let mounts = crate::mountinfo::current().map_err(mount_table_error)?;
        let registry = load_registry()?;
        let mine: Vec<serde_json::Value> = registry
            .iter()
            .filter(|e| e.uid == uid)
            .map(|e| {
                let mut value = serde_json::to_value(e).unwrap_or_default();
                value["mounted"] =
                    serde_json::Value::Bool(crate::mountinfo::at(&mounts, &e.path).is_some());
                value
            })
            .collect();
        serde_json::to_string(&mine).map_err(|e| Error::Failed(e.to_string()))
    }

    /// Which kernel mount types this system supports.
    fn capabilities(&self) -> HashMap<String, bool> {
        let _busy = self.busy();
        HashMap::from([
            ("smb".to_owned(), kernel_has("cifs")),
            (
                "nfs".to_owned(),
                crate::process::helper("mount.nfs").is_some(),
            ),
        ])
    }
}

impl Default for Service {
    fn default() -> Self {
        Self::new()
    }
}

/// Whether the running kernel has or can load file system `name`.
#[must_use]
pub fn kernel_has(name: &str) -> bool {
    if std::fs::read_to_string("/proc/filesystems")
        .is_ok_and(|t| t.lines().any(|l| l.split_whitespace().last() == Some(name)))
    {
        return true;
    }
    let release = rustix::system::uname()
        .release()
        .to_string_lossy()
        .into_owned();
    let alias = format!("alias fs-{name} ");
    std::fs::read_to_string(format!("/usr/lib/modules/{release}/modules.alias"))
        .is_ok_and(|t| t.lines().any(|l| l.starts_with(&alias)))
}

/// Run the root service until idle.
///
/// # Errors
/// D-Bus connection failures.
pub async fn serve() -> zbus::Result<()> {
    let service = Service::new();
    let active = Arc::clone(&service.active);
    let last = Arc::clone(&service.last);
    let _connection = zbus::connection::Builder::system()
        .serve_at(crate::api::SYSTEM_OBJECT_PATH, service)
        .name(crate::api::SYSTEM_BUS_NAME)
        .build()
        .await?;
    crate::log!(info, "enzimos-mount-system ready");
    loop {
        tokio::time::sleep(Duration::from_secs(10)).await;
        let idle = last
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .elapsed();
        if active.load(Ordering::SeqCst) == 0 && idle >= IDLE_EXIT {
            crate::log!(info, "idle; exiting");
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smb_requests_are_validated_and_failures_explained() {
        let mut params: HashMap<String, OwnedVariant> = HashMap::new();
        let put = |p: &mut HashMap<String, OwnedVariant>, k: &str, v: &str| {
            p.insert(
                k.to_owned(),
                OwnedVariant::try_from(Variant::from(v)).unwrap(),
            );
        };
        put(&mut params, "host", "nas.local");
        put(&mut params, "share", "photos");
        put(&mut params, "username", "alice");
        let parsed = smb_params(&params).unwrap();
        assert_eq!(
            (parsed.label.as_str(), parsed.version),
            ("photos on nas.local", None),
            "defaults"
        );
        for (key, bad) in [
            ("host", "-oevil"),
            ("share", "a,uid=0"),
            ("username", "bob,uid=0"),
            ("path", "../../etc"),
            ("version", "9.9"),
            ("domain", "x=y"),
        ] {
            let mut p = params.clone();
            put(&mut p, key, bad);
            assert!(smb_params(&p).is_err(), "{key}={bad} refused");
        }

        let failed = |stage: &str, errno: i32| worker::WorkerResult {
            ok: false,
            errno: Some(errno),
            stage: stage.to_owned(),
            log: String::new(),
        };
        assert!(
            matches!(
                classify(&failed("connect", 13), "nas", "s", true),
                Error::AuthFailed(_)
            ),
            "bad password"
        );
        assert!(
            matches!(
                classify(&failed("connect", 13), "nas", "s", false),
                Error::NeedsCredentials(_)
            ),
            "guest refused"
        );
        assert!(
            matches!(
                classify(&failed("connect", 113), "nas", "s", true),
                Error::Unreachable(_)
            ),
            "no route"
        );
        assert!(
            matches!(classify(&failed("connect", 2), "nas", "s", true), Error::Failed(m) if m.contains("no share")),
            "missing share"
        );
        let unresolved = worker::WorkerResult {
            stage: "resolve".to_owned(),
            ..worker::WorkerResult::default()
        };
        assert!(
            matches!(
                classify(&unresolved, "nas", "s", true),
                Error::Unreachable(_)
            ),
            "unknown host"
        );

        for (key, len) in [("label", MAX_LABEL + 1), ("path", MAX_PATH + 1)] {
            let mut p = params.clone();
            put(&mut p, key, &"a".repeat(len));
            assert!(smb_params(&p).is_err(), "oversized {key} refused");
        }
    }

    #[test]
    fn the_registry_is_private_tracks_reservations_and_refuses_foreign_files() {
        use std::os::unix::fs::PermissionsExt;
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("state");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let entry = |path: &str, created: u64| Entry {
            uid: 1000,
            path: base.path().join(path),
            kind: EntryKind::Kernel,
            protocol: "smb".to_owned(),
            source: "//nas/s".to_owned(),
            created,
            boot: false,
            pending: true,
        };
        with_registry_in(&dir, |r| {
            r.extend([entry("fresh", now()), entry("stale", 0)])
        })
        .unwrap();
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "state directory tightened");
        let kept: Vec<PathBuf> =
            with_registry_in(&dir, |r| r.iter().map(|e| e.path.clone()).collect()).unwrap();
        assert_eq!(
            kept,
            vec![base.path().join("fresh")],
            "an unmounted reservation lives only while fresh"
        );
        let held = lock_registry(&dir).unwrap();
        let started = Instant::now();
        assert!(
            with_registry_in(&dir, |_| ()).is_err(),
            "a held lock is waited for, then refused"
        );
        assert!(started.elapsed() >= LOCK_WAIT, "bounded wait");
        drop(held);
        std::fs::write(dir.join("registry.json"), b"not json").unwrap();
        assert!(
            with_registry_in(&dir, |_| ()).is_err(),
            "an unreadable registry is not silently emptied"
        );
        std::fs::write(
            dir.join("registry.json"),
            vec![b' '; usize::try_from(MAX_REGISTRY).unwrap() + 1],
        )
        .unwrap();
        assert!(
            with_registry_in(&dir, |_| ()).is_err(),
            "an oversized registry is refused"
        );
    }
}
