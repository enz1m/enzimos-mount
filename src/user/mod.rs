//! The session service `org.enzimos.Mount1`.

pub mod backends;
pub mod cloud;
pub mod discovery;
pub mod fuse;
pub mod keyring;
pub mod locations;
pub mod notify;
pub mod udisks;
pub mod usb;

use crate::api::{
    self, Capabilities, CredentialRequest, HostKeyRequest, Item, Kind, Snapshot, State,
};
use crate::error::{Error, Result};
use crate::process::Spec;
use crate::secret::Secret;
use crate::uri::{NetUri, Scheme};
use futures_util::StreamExt;
use locations::Location;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};
use zbus::{OwnedFd, OwnedObjectPath, OwnedVariant, Variant};

/// Interval between health probes of network and phone mounts.
pub const PROBE_INTERVAL: Duration = Duration::from_secs(15);
/// A probe that does not return within this marks the mount not responding.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(8);
/// Deadline for calls to the root service.
pub const SYSTEM_TIMEOUT: Duration = Duration::from_secs(180);
/// How long suspend waits for network shares to be released. logind stops
/// waiting for delay inhibitors after five seconds by default.
pub const SLEEP_RELEASE_TIMEOUT: Duration = Duration::from_secs(4);
/// Failed reconnections of a share released for suspend before the user is
/// told it is gone.
const RESTORE_ATTEMPTS: u32 = 4;
/// `NM_STATE_ASLEEP`: networking is off because the system is suspending.
const NM_STATE_ASLEEP: u32 = 10;
/// Longest wait between automatic reconnection attempts.
pub const MAX_BACKOFF: Duration = Duration::from_secs(600);

/// Credentials supplied with a mount.
#[derive(Debug, Default, Clone)]
pub struct Credentials {
    /// User name.
    pub username: Option<String>,
    /// SMB domain.
    pub domain: Option<String>,
    /// Password.
    pub secret: Option<Secret>,
    /// Keep the password in the keyring.
    pub remember: bool,
}

#[derive(Debug)]
struct Active {
    path: PathBuf,
    kernel: bool,
    fuse: Option<fuse::FuseMount>,
    probing: bool,
    /// Read once at mount time; the mount table is not re-read per snapshot.
    read_only: bool,
    /// From the last health probe.
    space: Option<(u64, u64)>,
}

impl Active {
    fn new(path: PathBuf, kernel: bool, fuse: Option<fuse::FuseMount>) -> Self {
        let read_only = crate::mountinfo::current()
            .ok()
            .and_then(|table| crate::mountinfo::at(&table, &path))
            .is_some_and(|m| m.read_only());
        Self {
            path,
            kernel,
            fuse,
            probing: false,
            read_only,
            space: None,
        }
    }

    fn kernel(path: PathBuf) -> Self {
        Self::new(path, true, None)
    }
}

#[derive(Debug, Default)]
struct Retry {
    failures: u32,
    next: Option<Instant>,
    needs_user: bool,
    paused: bool,
}

#[derive(Default)]
struct Inner {
    drives: Vec<Item>,
    usb: Vec<usb::UsbDevice>,
    locations: Vec<Location>,
    locations_writable: bool,
    mounts: HashMap<String, Active>,
    overlay: HashMap<String, State>,
    caps: Capabilities,
    busy: HashSet<String>,
    retry: HashMap<String, Retry>,
    /// Between logind's suspend announcement and resume.
    sleeping: bool,
    /// Network shares released for suspend, reconnected after resume.
    restore: HashSet<String>,
    clouds: Vec<cloud::Account>,
    /// Cloud accounts whose sign-in is under way: provider and the task.
    signing: HashMap<String, (cloud::Provider, tokio::task::AbortHandle)>,
}

/// Shared daemon state.
pub struct Daemon {
    inner: Mutex<Inner>,
    notify: tokio::sync::Notify,
    /// Wakes the health loop when it sleeps with nothing to watch.
    wake: tokio::sync::Notify,
    generation: AtomicU64,
    system: Option<zbus::Connection>,
    me: Weak<Daemon>,
    notifier: std::sync::OnceLock<notify::Notifier>,
}

struct BusyGuard {
    daemon: Arc<Daemon>,
    id: String,
}

impl Drop for BusyGuard {
    fn drop(&mut self) {
        self.daemon.lock().busy.remove(&self.id);
    }
}

fn json_error<T: serde::Serialize>(make: fn(String) -> Error, value: &T) -> Error {
    make(serde_json::to_string(value).unwrap_or_default())
}

fn login_name() -> String {
    std::env::var("USER")
        .ok()
        .filter(|u| crate::uri::valid_name(u, 128))
        .unwrap_or_default()
}

impl Daemon {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn arc(&self) -> Arc<Daemon> {
        self.me
            .upgrade()
            .unwrap_or_else(|| unreachable!("daemon alive while serving"))
    }

    fn changed(&self) {
        self.notify.notify_one();
        self.wake.notify_one();
    }

    fn set_overlay(&self, id: &str, state: Option<State>) {
        let mut inner = self.lock();
        match state {
            Some(state) => inner.overlay.insert(id.to_owned(), state),
            None => inner.overlay.remove(id),
        };
        drop(inner);
        self.changed();
    }

    fn begin(&self, id: &str) -> Result<BusyGuard> {
        if !self.lock().busy.insert(id.to_owned()) {
            return Err(Error::Busy(crate::tr!("error-item-busy")));
        }
        Ok(BusyGuard {
            daemon: self.arc(),
            id: id.to_owned(),
        })
    }

    /// The current snapshot.
    pub fn snapshot(&self) -> Snapshot {
        let inner = self.lock();
        let mut items = Vec::new();
        for drive in &inner.drives {
            let mut item = drive.clone();
            if let Some(state) = inner.overlay.get(&item.id)
                && !(item.state == State::Mounted && matches!(state, State::Mounting))
            {
                item.state = state.clone();
            }
            items.push(item);
        }
        for device in &inner.usb {
            let id = device.id();
            let mut item = Item::new(&id, device.kind, &device.label);
            item.detail = match device.kind {
                Kind::Ios => crate::tr!("label-ios-detail"),
                Kind::Camera => crate::tr!("label-camera"),
                _ => crate::tr!("label-phone"),
            };
            item.can_mount = match device.kind {
                Kind::Ios => inner.caps.ios,
                _ => inner.caps.mtp,
            };
            apply_active(&mut item, inner.mounts.get(&id), inner.overlay.get(&id));
            item.can_eject = item.can_unmount;
            items.push(item);
        }
        for location in &inner.locations {
            let mut item = Item::new(&location.id, Kind::Network, &location.label);
            let uri = location.net_uri().ok();
            item.uri = Some(location.uri.clone());
            item.detail = uri
                .as_ref()
                .map(|u| {
                    let target = if u.share.is_empty() {
                        u.path.clone()
                    } else {
                        u.share.clone()
                    };
                    if target.is_empty() {
                        u.host.clone()
                    } else {
                        format!(
                            "{} on {}",
                            target.rsplit('/').next().unwrap_or(&target),
                            u.host
                        )
                    }
                })
                .unwrap_or_default();
            item.saved = location.saved;
            item.auto_connect = location.auto_connect;
            item.mount_at_boot = location.mount_at_boot;
            item.can_mount_at_boot = uri.as_ref().is_some_and(|u| {
                matches!(u.scheme, Scheme::Smb | Scheme::Nfs) && !u.share.is_empty()
                    || u.scheme == Scheme::Nfs
            });
            item.can_mount = uri.is_some_and(|u| supported(&inner.caps, u.scheme));
            apply_active(
                &mut item,
                inner.mounts.get(&location.id),
                inner.overlay.get(&location.id),
            );
            items.push(item);
        }
        for account in &inner.clouds {
            let mut item = Item::new(&account.id, Kind::Cloud, &account.label);
            item.detail = if account.server.is_empty() {
                account.provider.name().to_owned()
            } else {
                format!("{} · {}", account.provider.name(), account.server)
            };
            item.saved = true;
            item.auto_connect = account.auto_connect;
            item.can_mount = inner.caps.webdav_ftp;
            apply_active(
                &mut item,
                inner.mounts.get(&account.id),
                inner.overlay.get(&account.id),
            );
            item.can_eject = item.can_unmount;
            items.push(item);
        }
        let mut signing: Vec<(&String, &cloud::Provider)> = inner
            .signing
            .iter()
            .map(|(id, (provider, _))| (id, provider))
            .collect();
        signing.sort_by_key(|(id, _)| *id);
        for (id, provider) in signing {
            let mut item = Item::new(id, Kind::Cloud, provider.name());
            item.detail = crate::tr!("cloud-signing-in-detail");
            item.state = State::SigningIn;
            items.push(item);
        }
        Snapshot {
            version: api::SCHEMA_VERSION,
            generation: self.generation.load(Ordering::SeqCst),
            capabilities: inner.caps.clone(),
            items,
        }
    }

    async fn system_proxy(&self) -> Result<zbus::Proxy<'static>> {
        let connection = self
            .system
            .clone()
            .ok_or_else(|| Error::Unsupported(crate::tr!("error-no-system-bus")))?;
        Ok(zbus::Proxy::new_owned(
            connection,
            api::SYSTEM_BUS_NAME,
            api::SYSTEM_OBJECT_PATH,
            api::SYSTEM_BUS_NAME,
        )
        .await?)
    }

    async fn system_call<B, R>(&self, method: &str, body: &B) -> Result<R>
    where
        B: serde::Serialize + zbus::DynamicType,
        R: for<'d> serde::Deserialize<'d> + zbus::Type,
    {
        let proxy = self.system_proxy().await?;
        tokio::time::timeout(SYSTEM_TIMEOUT, proxy.call::<_, B, R>(method, body))
            .await
            .map_err(|_| Error::Timeout(crate::tr!("error-system-service-timeout")))?
            .map_err(Error::from_remote)
    }

    /// A mount point for a FUSE mount: from the root service when installed,
    /// otherwise below the runtime directory.
    async fn prepare_mountpoint(&self, label: &str) -> Result<PathBuf> {
        match self
            .system_call::<_, String>("PrepareMountpoint", &(label,))
            .await
        {
            Ok(path) => Ok(PathBuf::from(path)),
            Err(Error::Unsupported(_)) => {
                let runtime = std::env::var_os("XDG_RUNTIME_DIR")
                    .map(PathBuf::from)
                    .ok_or_else(|| Error::Failed("No runtime directory".to_owned()))?;
                let dir = runtime.join("enzimos-mount");
                std::fs::create_dir_all(&dir).map_err(|e| Error::Failed(e.to_string()))?;
                let fd = rustix::fs::open(
                    &dir,
                    rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
                    rustix::fs::Mode::empty(),
                )
                .map_err(|e| Error::Failed(e.to_string()))?;
                crate::system::mountpoint::create(&fd, &dir, label, None).map_err(Error::Failed)
            }
            Err(error) => Err(error),
        }
    }

    async fn release_mountpoint(&self, path: &Path, force: bool) {
        if self
            .system_call::<_, ()>("Unmount", &(path.to_string_lossy().as_ref(), force))
            .await
            .is_err()
        {
            let _ = std::fs::remove_dir(path);
        }
    }

    // ----- mounting -----

    /// Mount item `id`.
    ///
    /// # Errors
    /// Mapped failures; credential and host-key requests carry JSON.
    pub async fn mount(&self, id: &str, credentials: Credentials) -> Result<PathBuf> {
        if id.starts_with("block:") {
            return self.mount_drive(id).await;
        }
        if id.starts_with("drive:") {
            return Err(Error::Invalid(crate::tr!("error-no-disc")));
        }
        let _guard = self.begin(id)?;
        let existing = self.lock().mounts.get(id).map(|a| a.path.clone());
        if let Some(path) = existing {
            if credentials.remember {
                self.remember_later(id, credentials);
            }
            return Ok(path);
        }
        self.set_overlay(id, Some(State::Mounting));
        let result = if id.starts_with("mtp:") || id.starts_with("ios:") {
            self.mount_phone(id).await
        } else if id.starts_with("net-") {
            self.mount_network(id, credentials).await
        } else if cloud::valid_id(id) {
            self.mount_cloud(id).await
        } else {
            Err(Error::NotFound(crate::tr!("error-no-such-item")))
        };
        match &result {
            Ok(_) => {
                self.set_overlay(id, None);
                self.lock().retry.remove(id);
            }
            Err(
                Error::NeedsCredentials(_)
                | Error::HostKeyUnknown(_)
                | Error::HostKeyChanged(_)
                | Error::NotFound(_),
            ) => {
                self.set_overlay(id, None);
            }
            Err(error) => self.set_overlay(
                id,
                Some(State::Failed {
                    reason: error.message(),
                }),
            ),
        }
        result
    }

    fn udisks(&self) -> Result<udisks::Udisks> {
        self.system
            .clone()
            .map(udisks::Udisks::new)
            .ok_or_else(|| Error::Unsupported(crate::tr!("error-no-system-bus")))
    }

    async fn mount_drive(&self, id: &str) -> Result<PathBuf> {
        let item = self
            .snapshot()
            .items
            .into_iter()
            .find(|i| i.id == id)
            .ok_or_else(|| Error::NotFound(crate::tr!("error-drive-gone")))?;
        if let Some(path) = item.mount_path {
            return Ok(path);
        }
        if item.state == State::Locked {
            return Err(Error::Invalid(crate::tr!("error-unlock-first")));
        }
        let path = udisks::object_path(id)
            .ok_or_else(|| Error::NotFound(crate::tr!("error-drive-gone")))?;
        let _guard = self.begin(id)?;
        self.set_overlay(id, Some(State::Mounting));
        let result = self.udisks()?.mount(&path).await;
        match &result {
            Ok(_) => self.set_overlay(id, None),
            Err(e) => self.set_overlay(
                id,
                Some(State::Failed {
                    reason: e.message(),
                }),
            ),
        }
        self.refresh_drives().await;
        result
    }

    /// Unlock an encrypted drive with `passphrase`, then mount it.
    ///
    /// # Errors
    /// [`Error::AuthFailed`] for a wrong passphrase.
    pub async fn unlock(&self, id: &str, passphrase: &Secret) -> Result<PathBuf> {
        let path = udisks::object_path(id)
            .filter(|_| id.starts_with("block:"))
            .ok_or_else(|| Error::NotFound(crate::tr!("error-drive-gone")))?;
        let _guard = self.begin(id)?;
        let udisks = self.udisks()?;
        let cleartext = udisks.unlock(&path, passphrase).await?;
        // The file system interface can appear a moment after unlocking.
        let mut last = Error::Failed(crate::tr!("error-no-filesystem"));
        for _ in 0..20 {
            match udisks.mount(&cleartext).await {
                Ok(point) => {
                    self.refresh_drives().await;
                    return Ok(point);
                }
                Err(error) => last = error,
            }
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
        Err(last)
    }

    async fn mount_phone(&self, id: &str) -> Result<PathBuf> {
        let device = self
            .lock()
            .usb
            .iter()
            .find(|d| d.id() == id)
            .cloned()
            .ok_or_else(|| Error::NotFound(crate::tr!("error-phone-gone")))?;
        if device.kind == Kind::Ios {
            let helper = crate::process::helper("ifuse").ok_or_else(|| {
                Error::Unsupported("iPhone support (ifuse) is not installed".to_owned())
            })?;
            let udid = self.ios_ready(&device).await?;
            let path = self.prepare_mountpoint(&device.label).await?;
            self.start_fuse(
                id,
                backends::ifuse(helper, &udid, &path),
                path,
                backends::explain_ifuse,
            )
            .await
        } else {
            let helper = crate::process::helper("aft-mtp-mount").ok_or_else(|| {
                Error::Unsupported(crate::tr!(
                    "error-missing-helper",
                    feature = crate::tr!("feature-phones"),
                    helper = "aft-mtp-mount"
                ))
            })?;
            // aft matches `vendor:product` exactly, or a substring of the
            // serial the phone reports over MTP (not always its USB serial).
            // The USB ID is unambiguous unless two such phones are attached.
            let same_model = self
                .lock()
                .usb
                .iter()
                .filter(|d| d.usb_id == device.usb_id)
                .count();
            let filter = if same_model == 1 && device.usb_id.len() == 9 {
                device.usb_id.clone()
            } else {
                device.serial.clone()
            };
            let path = self.prepare_mountpoint(&device.label).await?;
            self.start_fuse(
                id,
                backends::mtp(helper, &filter, &path),
                path,
                backends::explain_mtp,
            )
            .await
        }
    }

    async fn start_fuse(
        &self,
        id: &str,
        spec: Spec,
        path: PathBuf,
        explain: fn(Option<i32>, &str) -> Error,
    ) -> Result<PathBuf> {
        let weak = Weak::clone(&self.me);
        let on_exit = move |(id, code, tail): fuse::ExitReport| {
            crate::log!(
                info,
                "helper for {id} exited ({code:?}): {}",
                tail.lines().last().unwrap_or_default()
            );
            if let Some(daemon) = weak.upgrade() {
                tokio::spawn(async move { daemon.helper_died(&id).await });
            }
        };
        match fuse::start(id.to_owned(), spec, path.clone(), explain, on_exit).await {
            Ok(mount) => {
                self.lock()
                    .mounts
                    .insert(id.to_owned(), Active::new(path.clone(), false, Some(mount)));
                self.changed();
                Ok(path)
            }
            Err(error) => {
                self.release_mountpoint(&path, false).await;
                Err(error)
            }
        }
    }

    /// Drop a mount that ended outside our control.
    /// A FUSE helper exited without being asked to: drop its mount and, if the
    /// device or location is still there, say so.
    async fn helper_died(&self, id: &str) {
        self.forget_mount(id, true).await;
        let still_there = id.starts_with("net-") || self.lock().usb.iter().any(|d| d.id() == id);
        if still_there {
            let label = self.label(id);
            self.notify(notify::Note {
                item: id,
                summary: crate::tr!("notify-disconnected", device = &label),
                body: crate::tr!("notify-disconnected-body"),
                icon: if id.starts_with("net-") {
                    "network-server"
                } else {
                    "phone"
                },
                actions: &[(notify::Action::Retry, crate::tr!("action-reconnect"))],
                lasting: true,
                category: "device.error",
            })
            .await;
        }
    }

    fn label(&self, id: &str) -> String {
        self.snapshot()
            .items
            .into_iter()
            .find(|i| i.id == id)
            .map_or_else(|| id.to_owned(), |i| i.label)
    }

    async fn notify(&self, note: notify::Note<'_>) {
        if let Some(notifier) = self.notifier.get() {
            notifier.show(&note).await;
        }
    }

    async fn unnotify(&self, id: &str) {
        if let Some(notifier) = self.notifier.get() {
            notifier.close(id).await;
        }
    }

    /// Carry out a notification button.
    async fn on_action(self: Arc<Self>, id: String, action: notify::Action) {
        match action {
            notify::Action::Open | notify::Action::Retry => {
                self.unnotify(&id).await;
                match self.mount(&id, Credentials::default()).await {
                    Ok(path) => notify::open_folder(&path).await,
                    Err(
                        error @ (Error::NeedsCredentials(_)
                        | Error::HostKeyUnknown(_)
                        | Error::HostKeyChanged(_)),
                    ) => {
                        let label = self.label(&id);
                        let body = if matches!(error, Error::NeedsCredentials(_)) {
                            crate::tr!("notify-attention-sign-in")
                        } else {
                            crate::tr!("notify-attention-identity")
                        };
                        self.notify(notify::Note {
                            item: &id,
                            summary: crate::tr!("notify-attention", device = &label),
                            body,
                            icon: "dialog-password",
                            actions: &[],
                            lasting: true,
                            category: "device",
                        })
                        .await;
                    }
                    Err(error) => {
                        let label = self.label(&id);
                        self.notify(notify::Note {
                            item: &id,
                            summary: crate::tr!("notify-open-failed", device = &label),
                            body: error.message(),
                            icon: "dialog-warning",
                            actions: &[(notify::Action::Retry, crate::tr!("action-try-again"))],
                            lasting: true,
                            category: "device.error",
                        })
                        .await;
                    }
                }
            }
            notify::Action::Disconnect => {
                self.unnotify(&id).await;
                if let Err(error) = self.unmount(&id, true).await {
                    crate::log!(
                        warn,
                        "forced disconnect of {id} failed: {}",
                        error.message()
                    );
                }
            }
        }
    }

    async fn watch_notifications(self: Arc<Self>) {
        let Some(notifier) = self.notifier.get() else {
            return;
        };
        let Ok(mut stream) = notifier.actions().await else {
            return;
        };
        while let Some(message) = stream.next().await {
            let Ok(message) = message else { continue };
            if let Some((id, action)) = notifier.interpret(&message).await {
                tokio::spawn(Arc::clone(&self).on_action(id, action));
            }
        }
    }

    async fn forget_mount(&self, id: &str, release: bool) {
        let active = self.lock().mounts.remove(id);
        if let Some(active) = active
            && release
        {
            self.release_mountpoint(&active.path, active.kernel).await;
        }
        self.changed();
    }

    async fn ios_ready(&self, device: &usb::UsbDevice) -> Result<String> {
        let (Some(list), Some(pair)) = (
            crate::process::helper("idevice_id"),
            crate::process::helper("idevicepair"),
        ) else {
            return Err(Error::Unsupported(
                "iPhone support (libimobiledevice) is not installed".to_owned(),
            ));
        };
        let normalize = |s: &str| s.replace('-', "").to_ascii_lowercase();
        let wanted = normalize(&device.serial);
        let mut udid = None;
        for _ in 0..10 {
            let output = crate::process::run(Spec::new(&list, Duration::from_secs(10)).arg("-l"))
                .await
                .map_err(|e| Error::Failed(e.to_string()))?;
            udid = output
                .stdout
                .lines()
                .map(str::trim)
                .find(|l| !l.is_empty() && (wanted.is_empty() || normalize(l) == wanted))
                .map(str::to_owned);
            if udid.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        let udid = udid
            .filter(|u| u.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
            .ok_or_else(|| Error::DeviceLocked(crate::tr!("error-iphone-not-ready")))?;
        let validate = crate::process::run(
            Spec::new(&pair, Duration::from_secs(15)).args(["-u", &udid, "validate"]),
        )
        .await;
        if validate.as_ref().is_ok_and(crate::process::Output::success) {
            return Ok(udid);
        }
        // Pairing needs the user to unlock the phone and tap "Trust": ask once,
        // tell them, and keep checking for a minute instead of failing at once.
        let mut asked = false;
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let paired = crate::process::run(
                Spec::new(&pair, Duration::from_secs(30)).args(["-u", &udid, "pair"]),
            )
            .await
            .map_err(|e| Error::Failed(e.to_string()))?;
            if paired.success() {
                self.unnotify(&device.id()).await;
                return Ok(udid);
            }
            let error = backends::explain_pairing(&format!("{}\n{}", paired.stdout, paired.stderr));
            if !matches!(error, Error::DeviceLocked(_)) || Instant::now() >= deadline {
                self.unnotify(&device.id()).await;
                return Err(error);
            }
            if !asked {
                asked = true;
                self.notify(notify::Note {
                    item: &device.id(),
                    summary: crate::tr!("notify-trust", device = &device.label),
                    body: crate::tr!("notify-trust-body"),
                    icon: "phone-apple-iphone",
                    actions: &[],
                    lasting: true,
                    category: "device",
                })
                .await;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    async fn mount_network(&self, id: &str, credentials: Credentials) -> Result<PathBuf> {
        let location = self
            .lock()
            .locations
            .iter()
            .find(|l| l.id == id)
            .cloned()
            .ok_or_else(|| Error::NotFound(crate::tr!("error-no-such-location")))?;
        let uri = location.net_uri().map_err(|e| Error::Invalid(e.0))?;
        let explicit = credentials.secret.is_some();
        // People type Windows accounts as DOMAIN\user or user@domain.
        let (typed_user, typed_domain) = split_account(
            credentials.username.as_deref().unwrap_or_default(),
            uri.scheme,
        );
        let username = typed_user.or_else(|| uri.user.clone());
        let domain = credentials
            .domain
            .clone()
            .filter(|d| !d.is_empty())
            .or(typed_domain)
            .or_else(|| uri.domain.clone());
        if username
            .as_deref()
            .is_some_and(|u| !crate::uri::valid_name(u, 128))
            || domain
                .as_deref()
                .is_some_and(|d| !crate::uri::valid_name(d, 64))
        {
            return Err(Error::Invalid(crate::tr!("uri-bad-user")));
        }
        let account_user = username.clone().unwrap_or_else(login_name);
        let account = keyring::Account {
            id,
            protocol: uri.scheme.as_str(),
            server: &uri.host,
            user: &account_user,
        };
        let stored = if explicit || username.is_none() && uri.scheme != Scheme::Sftp {
            None
        } else {
            keyring::lookup(&account).await
        };
        let secret = credentials.secret.clone().or_else(|| stored.clone());
        let from_keyring = !explicit && secret.is_some();
        let ask = |retry: bool| {
            json_error(
                Error::NeedsCredentials,
                &CredentialRequest {
                    id: id.to_owned(),
                    username: username.clone().unwrap_or_else(login_name),
                    domain: domain.clone(),
                    can_remember: self.lock().caps.keyring,
                    retry,
                },
            )
        };
        let refused = |error: Error| match error {
            Error::AuthFailed(_) | Error::NeedsCredentials(_) if !explicit => ask(from_keyring),
            other => other,
        };
        let uri = uri.with_user(username.clone(), domain.clone());
        let result = match uri.scheme {
            Scheme::Smb => {
                if username.is_some() && secret.is_none() {
                    return Err(ask(false));
                }
                if uri.share.is_empty() {
                    // A server address: offer its shares instead of failing.
                    let shares = self
                        .list_shares(
                            &uri.display(),
                            username.as_deref().unwrap_or_default(),
                            domain.as_deref().unwrap_or_default(),
                            secret.clone(),
                        )
                        .await
                        .map_err(|error| match error {
                            Error::NeedsCredentials(_) => ask(from_keyring),
                            other => other,
                        })?;
                    return Err(json_error(
                        Error::ChooseShare,
                        &api::ShareChoice {
                            id: id.to_owned(),
                            shares,
                        },
                    ));
                }
                let mut params: HashMap<&str, Variant<'_>> = HashMap::new();
                params.insert("host", Variant::from(uri.host.as_str()));
                params.insert("share", Variant::from(uri.share.as_str()));
                params.insert("path", Variant::from(uri.path.as_str()));
                params.insert("label", Variant::from(location.label.as_str()));
                if let Some(port) = uri.port {
                    params.insert("port", Variant::from(port));
                }
                if let Some(user) = &username {
                    params.insert("username", Variant::from(user.as_str()));
                }
                if let Some(domain) = &domain {
                    params.insert("domain", Variant::from(domain.as_str()));
                }
                if let Some(version) = &location.smb_version {
                    params.insert("version", Variant::from(version.as_str()));
                }
                let fd = crate::secret::to_memfd(&secret.clone().unwrap_or_default())
                    .map_err(|e| Error::Failed(e.to_string()))?;
                let path: String = self
                    .system_call("MountSmb", &(params, zbus::Fd::from(&fd)))
                    .await
                    .map_err(refused)?;
                let path = PathBuf::from(path);
                self.lock()
                    .mounts
                    .insert(id.to_owned(), Active::kernel(path.clone()));
                Ok(path)
            }
            Scheme::Nfs => {
                let mut params: HashMap<&str, Variant<'_>> = HashMap::new();
                params.insert("host", Variant::from(uri.host.as_str()));
                params.insert("path", Variant::from(uri.path.as_str()));
                params.insert("label", Variant::from(location.label.as_str()));
                if let Some(port) = uri.port {
                    params.insert("port", Variant::from(port));
                }
                let path = PathBuf::from(
                    self.system_call::<_, String>("MountNfs", &(params,))
                        .await?,
                );
                self.lock()
                    .mounts
                    .insert(id.to_owned(), Active::kernel(path.clone()));
                Ok(path)
            }
            Scheme::Sftp => {
                self.mount_sftp(
                    id,
                    &location,
                    &uri,
                    secret.as_ref(),
                    explicit,
                    from_keyring,
                    &ask,
                )
                .await
            }
            Scheme::Dav | Scheme::Davs | Scheme::Ftp | Scheme::Ftps => {
                if username.is_some() && secret.is_none() {
                    return Err(ask(false));
                }
                self.mount_rclone(id, &location, &uri, secret.as_ref())
                    .await
                    .map_err(refused)
            }
        };
        let path = result?;
        self.changed();
        if username != uri_user(&location) {
            forget_other_users(id, account_user);
        }
        if credentials.remember {
            self.update_location_user(id, &uri, true);
            self.remember_later(id, credentials);
        } else if username != uri_user(&location) {
            self.update_location_user(id, &uri, false);
        }
        Ok(path)
    }

    /// Store a password without delaying the mount reply: the keyring may be
    /// locked and show an unlock prompt. The location is saved either way;
    /// if storing fails, the next mount asks again.
    fn remember_later(&self, id: &str, credentials: Credentials) {
        let Some(secret) = credentials.secret else {
            return;
        };
        let Some(location) = self.lock().locations.iter().find(|l| l.id == id).cloned() else {
            return;
        };
        let Ok(uri) = location.net_uri() else { return };
        let daemon = self.arc();
        let id = id.to_owned();
        tokio::spawn(async move {
            let user = uri.user.clone().unwrap_or_else(login_name);
            let account = keyring::Account {
                id: &id,
                protocol: uri.scheme.as_str(),
                server: &uri.host,
                user: &user,
            };
            if let Err(error) =
                keyring::store(&account, &location.uri, &location.label, &secret).await
            {
                crate::log!(warn, "could not remember the password for {id}: {error}");
            }
            // A share mounted at startup keeps its own encrypted copy: refresh it.
            if location.mount_at_boot
                && let Err(error) = daemon.store_boot(&location, &uri, &secret).await
            {
                crate::log!(
                    warn,
                    "could not update the startup password for {id}: {}",
                    error.message()
                );
            }
        });
    }

    fn update_location_user(&self, id: &str, uri: &NetUri, save: bool) {
        let mut inner = self.lock();
        if let Some(location) = inner.locations.iter_mut().find(|l| l.id == id) {
            location.uri = uri.display();
            location.saved |= save;
        }
        persist(&inner);
        drop(inner);
        self.changed();
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "one SFTP attempt needs all of these"
    )]
    async fn mount_sftp(
        &self,
        id: &str,
        location: &Location,
        uri: &NetUri,
        secret: Option<&Secret>,
        explicit: bool,
        from_keyring: bool,
        ask: &(dyn Fn(bool) -> Error + Send + Sync),
    ) -> Result<PathBuf> {
        let helper = crate::process::helper("sshfs").ok_or_else(|| {
            Error::Unsupported(crate::tr!(
                "error-missing-helper",
                feature = crate::tr!("feature-sftp"),
                helper = "sshfs"
            ))
        })?;
        let path = self.prepare_mountpoint(&location.label).await?;
        let mut spec = backends::sshfs(helper, uri, &path, secret.is_some());
        if let Some(secret) = secret {
            let mut input = zeroize::Zeroizing::new(secret.expose().to_vec());
            input.push(b'\n');
            spec.stdin = Some(input);
        }
        let failure = std::sync::Arc::new(Mutex::new(None));
        let seen = std::sync::Arc::clone(&failure);
        let explain = move |_code: Option<i32>, stderr: &str| -> Error {
            *seen
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) =
                Some(backends::classify_ssh(stderr));
            Error::Failed(
                stderr
                    .lines()
                    .rev()
                    .find(|l| !l.trim().is_empty())
                    .map_or_else(|| crate::tr!("error-sftp-failed"), |l| l.trim().to_owned()),
            )
        };
        let weak = Weak::clone(&self.me);
        let on_exit = move |(id, code, tail): fuse::ExitReport| {
            crate::log!(
                info,
                "sshfs for {id} exited ({code:?}): {}",
                tail.lines().last().unwrap_or_default()
            );
            if let Some(daemon) = weak.upgrade() {
                tokio::spawn(async move { daemon.helper_died(&id).await });
            }
        };
        match fuse::start(id.to_owned(), spec, path.clone(), explain, on_exit).await {
            Ok(mount) => {
                self.lock()
                    .mounts
                    .insert(id.to_owned(), Active::new(path.clone(), false, Some(mount)));
                Ok(path)
            }
            Err(error) => {
                self.release_mountpoint(&path, false).await;
                let kind = *failure
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                Err(match kind {
                    Some(
                        backends::SshFailure::UnknownHostKey | backends::SshFailure::ChangedHostKey,
                    ) => {
                        let changed = kind == Some(backends::SshFailure::ChangedHostKey);
                        let request = HostKeyRequest {
                            id: id.to_owned(),
                            host: backends::ssh_host_key_name(uri),
                            fingerprints: scan_host_keys(uri)
                                .await
                                .into_iter()
                                .map(|(fp, _)| fp)
                                .collect(),
                        };
                        json_error(
                            if changed {
                                Error::HostKeyChanged
                            } else {
                                Error::HostKeyUnknown
                            },
                            &request,
                        )
                    }
                    Some(backends::SshFailure::Auth) if explicit => {
                        Error::AuthFailed(crate::tr!("error-login-refused"))
                    }
                    Some(backends::SshFailure::Auth) => ask(from_keyring),
                    Some(backends::SshFailure::Unreachable) => {
                        Error::Unreachable(crate::tr!("error-server-no-answer", host = &uri.host))
                    }
                    Some(backends::SshFailure::NoSuchPath) => {
                        Error::Failed(crate::tr!("error-no-such-folder"))
                    }
                    _ => error,
                })
            }
        }
    }

    async fn mount_cloud(&self, id: &str) -> Result<PathBuf> {
        let helper = crate::process::helper("rclone").ok_or_else(|| {
            Error::Unsupported(crate::tr!(
                "error-missing-helper",
                feature = crate::tr!("feature-cloud"),
                helper = "rclone"
            ))
        })?;
        let account = self
            .lock()
            .clouds
            .iter()
            .find(|a| a.id == id)
            .cloned()
            .ok_or_else(|| Error::NotFound(crate::tr!("error-no-such-location")))?;
        let path = self.prepare_mountpoint(&account.label).await?;
        let spec = cloud::mount_spec(helper, &account, &path);
        self.start_fuse(id, spec, path, backends::explain_rclone)
            .await
    }

    /// Start adding a cloud account: the sign-in opens in the browser and
    /// the item shows `signing_in` until it ends. Returns the new identity.
    ///
    /// # Errors
    /// [`Error::Unsupported`] for a service this computer cannot reach.
    pub fn add_cloud(&self, provider: &str, server: &str) -> Result<String> {
        let provider = cloud::Provider::from_key(provider)
            .ok_or_else(|| Error::Invalid(crate::tr!("error-invalid-field", field = "provider")))?;
        if !cloud::available().contains(&provider) {
            return Err(Error::Unsupported(crate::tr!(
                "error-cloud-unavailable",
                service = provider.name()
            )));
        }
        if provider == cloud::Provider::Nextcloud {
            cloud::nextcloud_base(server)?;
        }
        {
            let inner = self.lock();
            if inner.clouds.len() + inner.signing.len() >= cloud::MAX_ACCOUNTS {
                return Err(Error::Invalid(crate::tr!("error-too-many-locations")));
            }
            if !inner.signing.is_empty() {
                return Err(Error::Busy(crate::tr!("error-cloud-one-at-a-time")));
            }
        }
        let id = cloud::new_id();
        let daemon = self.arc();
        let (task_id, server) = (id.clone(), server.trim().to_owned());
        let task = tokio::spawn(async move {
            let result = cloud::sign_in(&task_id, provider, &server).await;
            daemon.cloud_signed_in(&task_id, provider, result).await;
        });
        self.lock()
            .signing
            .insert(id.clone(), (provider, task.abort_handle()));
        self.changed();
        Ok(id)
    }

    async fn cloud_signed_in(
        &self,
        id: &str,
        provider: cloud::Provider,
        result: Result<(String, String)>,
    ) {
        let removed = self.lock().signing.remove(id).is_none();
        if removed {
            // Cancelled meanwhile.
            cloud::forget(id);
            return;
        }
        match result {
            Ok((account, server)) => {
                let label = if account.is_empty() {
                    provider.name().to_owned()
                } else {
                    format!("{} ({account})", provider.name())
                };
                let entry = cloud::Account {
                    id: id.to_owned(),
                    provider,
                    label,
                    account,
                    server,
                    auto_connect: true,
                };
                {
                    let mut inner = self.lock();
                    inner.clouds.push(entry);
                    if let Err(error) = cloud::save(&inner.clouds) {
                        crate::log!(warn, "cloud accounts not saved: {error}");
                    }
                }
                self.changed();
                if let Err(error) = self.mount(id, Credentials::default()).await {
                    crate::log!(
                        info,
                        "new cloud account {id} did not mount: {}",
                        error.message()
                    );
                }
            }
            Err(error) => {
                crate::log!(info, "cloud sign-in {id} ended: {}", error.message());
                self.notify(notify::Note {
                    item: id,
                    summary: crate::tr!("notify-cloud-failed", service = provider.name()),
                    body: error.message(),
                    icon: "dialog-warning",
                    actions: &[],
                    lasting: false,
                    category: "network.error",
                })
                .await;
                self.changed();
            }
        }
    }

    async fn mount_rclone(
        &self,
        id: &str,
        location: &Location,
        uri: &NetUri,
        secret: Option<&Secret>,
    ) -> Result<PathBuf> {
        let helper = crate::process::helper("rclone").ok_or_else(|| {
            Error::Unsupported(crate::tr!(
                "error-missing-helper",
                feature = crate::tr!("feature-webdav-ftp"),
                helper = "rclone"
            ))
        })?;
        let obscured = match secret {
            Some(secret) => {
                let mut spec = Spec::new(&helper, Duration::from_secs(10)).args(["obscure", "-"]);
                spec.stdin = Some(zeroize::Zeroizing::new(secret.expose().to_vec()));
                let output = crate::process::run(spec)
                    .await
                    .map_err(|e| Error::Failed(e.to_string()))?;
                Some(zeroize::Zeroizing::new(output.stdout.trim().to_owned()))
            }
            None => None,
        };
        let runtime = std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .ok_or_else(|| Error::Failed("No runtime directory".to_owned()))?;
        let config = runtime.join("enzimos-mount/rclone.conf");
        if let Some(parent) = config.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(&config, b"");
        let path = self.prepare_mountpoint(&location.label).await?;
        let spec = backends::rclone(
            helper,
            uri,
            &path,
            &config,
            obscured.as_deref().map(String::as_str),
        );

        self.start_fuse(id, spec, path, backends::explain_rclone)
            .await
    }

    /// The root service's parameters for a kernel location.
    fn boot_params<'a>(
        location: &'a Location,
        uri: &'a NetUri,
    ) -> Result<HashMap<&'static str, Variant<'a>>> {
        let mut params: HashMap<&'static str, Variant<'a>> = HashMap::new();
        params.insert("id", Variant::from(location.id.as_str()));
        params.insert("label", Variant::from(location.label.as_str()));
        params.insert("host", Variant::from(uri.host.as_str()));
        params.insert("path", Variant::from(uri.path.as_str()));
        if let Some(port) = uri.port {
            params.insert("port", Variant::from(port));
        }
        match uri.scheme {
            Scheme::Smb => {
                if uri.share.is_empty() {
                    return Err(Error::Invalid(crate::tr!("error-choose-share")));
                }
                params.insert("protocol", Variant::from("smb"));
                params.insert("share", Variant::from(uri.share.as_str()));
                if let Some(user) = &uri.user {
                    params.insert("username", Variant::from(user.as_str()));
                }
                if let Some(domain) = &uri.domain {
                    params.insert("domain", Variant::from(domain.as_str()));
                }
                if let Some(version) = &location.smb_version {
                    params.insert("version", Variant::from(version.as_str()));
                }
            }
            Scheme::Nfs => {
                params.insert("protocol", Variant::from("nfs"));
            }
            _ => return Err(Error::Unsupported(crate::tr!("error-startup-protocol"))),
        }
        Ok(params)
    }

    async fn store_boot(&self, location: &Location, uri: &NetUri, secret: &Secret) -> Result<()> {
        let params = Self::boot_params(location, uri)?;
        let fd = crate::secret::to_memfd(secret).map_err(|e| Error::Failed(e.to_string()))?;
        self.system_call::<_, ()>("SetBootMount", &(params, zbus::Fd::from(&fd), true))
            .await
    }

    /// Mount a location at startup (or stop). Uses `secret`, or the
    /// remembered password; asks for one when the share needs it.
    ///
    /// # Errors
    /// [`Error::NeedsCredentials`] without a usable password,
    /// [`Error::NotAuthorized`] when administrator approval is refused.
    pub async fn set_mount_at_boot(
        &self,
        id: &str,
        enabled: bool,
        secret: Option<Secret>,
    ) -> Result<()> {
        let location = self
            .lock()
            .locations
            .iter()
            .find(|l| l.id == id)
            .cloned()
            .ok_or_else(|| Error::NotFound(crate::tr!("error-no-such-location")))?;
        let uri = location.net_uri().map_err(|e| Error::Invalid(e.0))?;
        if enabled {
            let secret = match secret.filter(|s| !s.is_empty()) {
                Some(secret) => Some(secret),
                None if uri.scheme == Scheme::Smb && uri.user.is_some() => {
                    let user = uri.user.clone().unwrap_or_default();
                    keyring::lookup(&keyring::Account {
                        id,
                        protocol: "smb",
                        server: &uri.host,
                        user: &user,
                    })
                    .await
                }
                None => Some(Secret::default()),
            };
            let Some(secret) = secret else {
                return Err(json_error(
                    Error::NeedsCredentials,
                    &CredentialRequest {
                        id: id.to_owned(),
                        username: uri.user.clone().unwrap_or_else(login_name),
                        domain: uri.domain.clone(),
                        can_remember: true,
                        retry: false,
                    },
                ));
            };
            self.store_boot(&location, &uri, &secret).await?;
        } else {
            let mut params: HashMap<&str, Variant<'_>> = HashMap::new();
            params.insert("id", Variant::from(id));
            let fd = crate::secret::to_memfd(&Secret::default())
                .map_err(|e| Error::Failed(e.to_string()))?;
            self.system_call::<_, ()>("SetBootMount", &(params, zbus::Fd::from(&fd), false))
                .await?;
        }
        let mut inner = self.lock();
        if let Some(location) = inner.locations.iter_mut().find(|l| l.id == id) {
            location.mount_at_boot = enabled;
            if enabled {
                // Within a session it reconnects like any automatic location.
                location.saved = true;
                location.auto_connect = true;
            }
        }
        persist(&inner);
        drop(inner);
        self.changed();
        Ok(())
    }

    // ----- unmounting -----

    /// Unmount item `id`.
    ///
    /// # Errors
    /// [`Error::Busy`] while files are open (unless `force`).
    pub async fn unmount(&self, id: &str, force: bool) -> Result<()> {
        let _guard = self.begin(id)?;
        if id.starts_with("block:") {
            return self.unmount_block(id, force).await;
        }
        // A location the user disconnects stays disconnected until they
        // connect it again (or log in again), even if it auto-connects.
        if id.starts_with("net-") || cloud::valid_id(id) {
            let mut inner = self.lock();
            inner.retry.entry(id.to_owned()).or_default().paused = true;
            inner.restore.remove(id);
        }
        let active = self.lock().mounts.remove(id);
        let Some(mut active) = active else {
            if !self.snapshot().items.iter().any(|i| i.id == id) {
                return Err(Error::NotFound(crate::tr!("error-no-such-item")));
            }
            self.set_overlay(id, None);
            return Ok(());
        };
        self.set_overlay(id, Some(State::Unmounting));
        let result = if active.kernel {
            self.system_call::<_, ()>("Unmount", &(active.path.to_string_lossy().as_ref(), force))
                .await
        } else if let Some(mount) = active.fuse.as_mut() {
            match mount.unmount(force).await {
                Ok(()) => {
                    self.release_mountpoint(&active.path, false).await;
                    Ok(())
                }
                Err(error) => Err(error),
            }
        } else {
            Ok(())
        };
        let result = match result {
            Err(Error::Busy(message)) => {
                Err(Error::Busy(busy_message(&active.path, &message).await))
            }
            other => other,
        };
        if result.is_err() {
            self.lock().mounts.insert(id.to_owned(), active);
        }
        self.set_overlay(id, None);
        result
    }

    async fn unmount_block(&self, id: &str, force: bool) -> Result<()> {
        let path = self
            .lock()
            .drives
            .iter()
            .find(|d| d.id == id)
            .and_then(|d| d.mount_path.clone());
        let result = match (self.unmount_block_inner(id, force).await, path) {
            (Err(Error::Busy(message)), Some(path)) => {
                Err(Error::Busy(busy_message(&path, &message).await))
            }
            (other, _) => other,
        };
        self.refresh_drives().await;
        result
    }

    async fn unmount_block_inner(&self, id: &str, force: bool) -> Result<()> {
        let udisks = self.udisks()?;
        let path = udisks::object_path(id)
            .ok_or_else(|| Error::NotFound(crate::tr!("error-drive-gone")))?;
        let objects = udisks.objects().await?;
        let key = zbus::OwnedObjectPath::try_from(path.as_str())
            .map_err(|e| Error::Invalid(e.to_string()))?;
        let o = objects
            .get(&key)
            .ok_or_else(|| Error::NotFound(crate::tr!("error-drive-gone")))?;
        if o.contains_key("org.freedesktop.UDisks2.Encrypted") {
            if let Some(clear) = o
                .get("org.freedesktop.UDisks2.Encrypted")
                .and_then(|p| p.get("CleartextDevice"))
                .and_then(|v| zbus::OwnedObjectPath::try_from(v.try_clone().ok()?).ok())
                .filter(|p| p.as_str() != "/")
            {
                udisks.unmount(clear.as_str(), force).await?;
                return udisks.lock(&path).await;
            }
            return Ok(());
        }
        udisks.unmount(&path, force).await?;
        if o.contains_key("org.freedesktop.UDisks2.Loop") {
            // A disk image is detached once nothing is mounted from it.
            let _ = udisks.loop_delete(&path).await;
        }
        Ok(())
    }

    /// Eject (or, with `power_off`, safely remove) the drive holding `id`.
    ///
    /// # Errors
    /// [`Error::Busy`] while files are open on any of its volumes.
    pub async fn eject(&self, id: &str, power_off: bool) -> Result<()> {
        if id.starts_with("mtp:") || id.starts_with("ios:") || id.starts_with("net-") {
            self.unmount(id, false).await?;
            if !id.starts_with("net-") {
                let label = self.label(id);
                self.notify(notify::Note {
                    item: id,
                    summary: crate::tr!("notify-unplug", device = &label),
                    body: crate::tr!("notify-unplug-body"),
                    icon: "phone",
                    actions: &[],
                    lasting: false,
                    category: "device.removed",
                })
                .await;
            }
            return Ok(());
        }
        let snapshot = self.snapshot();
        let item = snapshot
            .items
            .iter()
            .find(|i| i.id == id)
            .ok_or_else(|| Error::NotFound(crate::tr!("error-drive-gone")))?;
        let drive = item
            .drive
            .clone()
            .ok_or_else(|| Error::Invalid(crate::tr!("error-not-removable")))?;
        for sibling in snapshot
            .items
            .iter()
            .filter(|i| i.drive.as_deref() == Some(drive.as_str()) && i.id.starts_with("block:"))
        {
            if sibling.mount_path.is_some() || sibling.state == State::Mounted {
                self.unmount(&sibling.id, false).await?;
            } else if sibling.state != State::Locked {
                // An unlocked but unmounted encrypted volume is locked by unmount_block.
                let _ = self.unmount(&sibling.id, false).await;
            }
        }
        let udisks = self.udisks()?;
        let drive_path = udisks::object_path(&drive)
            .ok_or_else(|| Error::NotFound(crate::tr!("error-drive-gone")))?;
        // USB sticks and disks have no media to eject: powering the drive
        // off is what "eject" means for them. Without either, unmounting
        // every volume is all that can be done.
        let result = if item.can_eject && !(power_off && item.can_power_off) {
            udisks.eject(&drive_path).await
        } else if item.can_power_off {
            udisks.power_off(&drive_path).await
        } else {
            Ok(())
        };
        self.refresh_drives().await;
        result
    }

    /// Quick-format a removable drive's volume, or with `whole_drive` erase
    /// the whole drive and give it one new volume. Options: `type` (`exfat`,
    /// `vfat`, `ntfs` or `ext4`), `label`, `whole_drive`. Returns the new
    /// volume's identity.
    ///
    /// # Errors
    /// [`Error::Busy`] while files are open, [`Error::Invalid`] for a drive
    /// that cannot be formatted here or a bad option.
    pub async fn format(
        &self,
        id: &str,
        options: &HashMap<String, OwnedVariant>,
    ) -> Result<String> {
        let text = |key: &str| {
            options
                .get(key)
                .and_then(|v| String::try_from(v.clone()).ok())
                .unwrap_or_default()
        };
        let fs = text("type");
        let label = text("label");
        let whole = options
            .get("whole_drive")
            .and_then(|v| bool::try_from(v).ok())
            .unwrap_or(false);
        if !udisks::FORMATS.iter().any(|(name, _)| *name == fs) {
            return Err(Error::Invalid(crate::tr!(
                "error-invalid-field",
                field = "type"
            )));
        }
        if !udisks::valid_label(&fs, &label) {
            return Err(Error::Invalid(crate::tr!("error-format-label")));
        }
        let snapshot = self.snapshot();
        let item = snapshot
            .items
            .iter()
            .find(|i| i.id == id)
            .ok_or_else(|| Error::NotFound(crate::tr!("error-drive-gone")))?;
        if !item.can_format {
            return Err(Error::Invalid(crate::tr!("error-not-formattable")));
        }
        let drive = item
            .drive
            .clone()
            .ok_or_else(|| Error::Invalid(crate::tr!("error-not-formattable")))?;
        // Close what is open first (unmounting locks unlocked encrypted
        // volumes too), so open files give a Busy naming the programs.
        let affected: Vec<&Item> = snapshot
            .items
            .iter()
            .filter(|i| {
                if whole {
                    i.drive.as_deref() == Some(drive.as_str())
                } else {
                    i.id == id
                }
            })
            .collect();
        for volume in &affected {
            if volume.mount_path.is_some() || volume.state == State::Mounted {
                self.unmount(&volume.id, false).await?;
            } else if volume.state != State::Locked
                && volume.filesystem.as_deref() == Some("crypto_LUKS")
            {
                let _ = self.unmount(&volume.id, false).await;
            }
        }
        let _guard = self.begin(id)?;
        self.set_overlay(id, Some(State::Formatting));
        let udisks = self.udisks()?;
        let result = async {
            if whole {
                let drive_path = udisks::object_path(&drive)
                    .ok_or_else(|| Error::NotFound(crate::tr!("error-drive-gone")))?;
                let objects = udisks.objects().await?;
                let disk = udisks::whole_disk(&objects, &drive_path)
                    .ok_or_else(|| Error::NotFound(crate::tr!("error-drive-gone")))?;
                let created = udisks.format_drive(&disk, &fs, &label).await?;
                Ok(udisks::block_id(
                    &OwnedObjectPath::try_from(created)
                        .map_err(|e| Error::Failed(e.to_string()))?,
                ))
            } else {
                let path = udisks::object_path(id)
                    .ok_or_else(|| Error::NotFound(crate::tr!("error-drive-gone")))?;
                udisks
                    .format_volume(&path, &fs, &label)
                    .await
                    .map(|()| id.to_owned())
            }
        }
        .await;
        self.set_overlay(id, None);
        self.refresh_drives().await;
        if let Err(error) = &result {
            crate::log!(info, "format of {id} failed: {}", error.message());
        }
        result
    }

    // ----- locations -----

    /// Add (or find) a location; returns its id.
    ///
    /// # Errors
    /// [`Error::Invalid`] for a bad address.
    pub fn add_location(
        &self,
        uri: &str,
        label: &str,
        options: &HashMap<String, OwnedVariant>,
    ) -> Result<String> {
        let parsed = NetUri::parse(uri).map_err(|e| Error::Invalid(e.0))?;
        let display = parsed.display();
        let mut inner = self.lock();
        if inner.locations.len() >= locations::MAX_LOCATIONS {
            return Err(Error::Invalid(crate::tr!("error-too-many-locations")));
        }
        let id = if let Some(existing) = inner.locations.iter_mut().find(|l| l.uri == display) {
            apply_options(existing, options)?;
            existing.id.clone()
        } else {
            let mut location = Location {
                id: locations::new_id(),
                uri: display,
                label: if label.trim().is_empty() {
                    parsed.label()
                } else {
                    label.trim().chars().take(120).collect()
                },
                saved: false,
                auto_connect: false,
                mount_at_boot: false,
                smb_version: None,
            };
            apply_options(&mut location, options)?;
            let id = location.id.clone();
            inner.locations.push(location);
            id
        };
        persist(&inner);
        drop(inner);
        self.changed();
        Ok(id)
    }

    /// Change a location's options.
    ///
    /// # Errors
    /// [`Error::NotFound`] or [`Error::Invalid`].
    pub fn update_location(&self, id: &str, options: &HashMap<String, OwnedVariant>) -> Result<()> {
        let mut inner = self.lock();
        let location = inner
            .locations
            .iter_mut()
            .find(|l| l.id == id)
            .ok_or_else(|| Error::NotFound(crate::tr!("error-no-such-location")))?;
        let previous_user = uri_user(location);
        apply_options(location, options)?;
        let user = uri_user(location);
        if user != previous_user {
            forget_other_users(id, user.unwrap_or_else(login_name));
        }
        inner.retry.remove(id);
        persist(&inner);
        drop(inner);
        if options
            .get("forget_password")
            .is_some_and(|v| v.downcast_ref::<bool>().unwrap_or(false))
        {
            let id = id.to_owned();
            tokio::spawn(async move { keyring::forget(&id).await });
        }
        self.changed();
        Ok(())
    }

    /// Remove a location, its saved password and, if mounted, its mount.
    ///
    /// # Errors
    /// [`Error::Busy`] when its mount is in use.
    pub async fn remove_location(&self, id: &str) -> Result<()> {
        if cloud::valid_id(id) {
            return self.remove_cloud(id).await;
        }
        if !self.lock().locations.iter().any(|l| l.id == id) {
            return Err(Error::NotFound(crate::tr!("error-no-such-location")));
        }
        let was_mounted = self.lock().mounts.contains_key(id);
        if was_mounted {
            self.unmount(id, false).await?;
        }
        if self
            .lock()
            .locations
            .iter()
            .any(|l| l.id == id && l.mount_at_boot)
        {
            let _ = self.set_mount_at_boot(id, false, None).await;
        }
        keyring::forget(id).await;
        let mut inner = self.lock();
        inner.locations.retain(|l| l.id != id);
        inner.overlay.remove(id);
        inner.retry.remove(id);
        persist(&inner);
        drop(inner);
        self.changed();
        Ok(())
    }

    async fn remove_cloud(&self, id: &str) -> Result<()> {
        let signing = self.lock().signing.remove(id);
        if let Some((_, task)) = signing {
            task.abort();
            cloud::forget(id);
            self.changed();
            return Ok(());
        }
        if !self.lock().clouds.iter().any(|a| a.id == id) {
            return Err(Error::NotFound(crate::tr!("error-no-such-location")));
        }
        if self.lock().mounts.contains_key(id) {
            self.unmount(id, false).await?;
        }
        cloud::forget(id);
        let mut inner = self.lock();
        inner.clouds.retain(|a| a.id != id);
        inner.overlay.remove(id);
        let _ = cloud::save(&inner.clouds);
        drop(inner);
        self.changed();
        Ok(())
    }

    /// Trust the given SFTP host key fingerprints for location `id`.
    ///
    /// # Errors
    /// When none of the server's current keys match.
    pub async fn trust_host_key(&self, id: &str, fingerprints: &[String]) -> Result<()> {
        let location = self
            .lock()
            .locations
            .iter()
            .find(|l| l.id == id)
            .cloned()
            .ok_or_else(|| Error::NotFound(crate::tr!("error-no-such-location")))?;
        let uri = location.net_uri().map_err(|e| Error::Invalid(e.0))?;
        if uri.scheme != Scheme::Sftp {
            return Err(Error::Invalid(crate::tr!("error-not-sftp")));
        }
        let keys: Vec<String> = scan_host_keys(&uri)
            .await
            .into_iter()
            .filter(|(fp, _)| fingerprints.contains(fp))
            .map(|(_, line)| line)
            .collect();
        if keys.is_empty() {
            return Err(Error::Failed(crate::tr!("error-host-key-moved")));
        }
        let file = backends::known_hosts();
        if let Some(parent) = file.parent() {
            std::fs::create_dir_all(parent).map_err(|e| Error::Failed(e.to_string()))?;
        }
        let host = backends::ssh_host_key_name(&uri);
        let existing = std::fs::read_to_string(&file).unwrap_or_default();
        // Replace any previous keys for this host (the user confirmed a change).
        let mut lines: Vec<String> = existing
            .lines()
            .filter(|l| l.split(' ').next() != Some(host.as_str()))
            .map(str::to_owned)
            .collect();
        lines.extend(keys);
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let tmp = file.with_extension("tmp");
        let mut out = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| Error::Failed(e.to_string()))?;
        out.write_all((lines.join("\n") + "\n").as_bytes())
            .map_err(|e| Error::Failed(e.to_string()))?;
        std::fs::rename(&tmp, &file).map_err(|e| Error::Failed(e.to_string()))?;
        self.lock().retry.remove(id);
        Ok(())
    }

    /// List the shares of an SMB server.
    ///
    /// # Errors
    /// [`Error::NeedsCredentials`] when the server wants a login.
    pub async fn list_shares(
        &self,
        uri: &str,
        username: &str,
        domain: &str,
        secret: Option<Secret>,
    ) -> Result<Vec<api::Share>> {
        let parsed = NetUri::parse(uri).map_err(|e| Error::Invalid(e.0))?;
        if parsed.scheme != Scheme::Smb {
            return Err(Error::Invalid(crate::tr!("error-not-smb")));
        }
        let helper = crate::process::helper("smbclient").ok_or_else(|| {
            Error::Unsupported(crate::tr!(
                "error-missing-helper",
                feature = crate::tr!("feature-share-browsing"),
                helper = "smbclient"
            ))
        })?;
        let user = Some(username)
            .filter(|u| !u.is_empty())
            .map(str::to_owned)
            .or_else(|| parsed.user.clone());
        let domain = Some(domain)
            .filter(|d| !d.is_empty())
            .map(str::to_owned)
            .or_else(|| parsed.domain.clone());
        if user
            .as_deref()
            .is_some_and(|u| !crate::uri::valid_name(u, 128))
            || domain
                .as_deref()
                .is_some_and(|d| !crate::uri::valid_name(d, 64))
        {
            return Err(Error::Invalid(crate::tr!("uri-bad-user")));
        }
        let has_password = secret.as_ref().is_some_and(|s| !s.is_empty());
        let mut spec = backends::smbclient_list(
            helper,
            &parsed,
            user.as_deref(),
            domain.as_deref(),
            has_password,
        );
        if let Some(secret) = &secret {
            spec = spec.env("PASSWD", secret.as_text().map_err(Error::Invalid)?);
        }
        let output = crate::process::run(spec).await.map_err(|e| match e {
            crate::process::RunError::Timeout => Error::Timeout(crate::tr!("error-server-timeout")),
            other => Error::Failed(other.to_string()),
        })?;
        let text = format!("{}\n{}", output.stdout, output.stderr);
        if text.contains("NT_STATUS_ACCESS_DENIED") || text.contains("NT_STATUS_LOGON_FAILURE") {
            return Err(json_error(
                Error::NeedsCredentials,
                &CredentialRequest {
                    id: String::new(),
                    username: user.unwrap_or_else(login_name),
                    domain,
                    can_remember: false,
                    retry: has_password,
                },
            ));
        }
        if text.contains("NT_STATUS_HOST_UNREACHABLE")
            || text.contains("NT_STATUS_IO_TIMEOUT")
            || text.contains("NT_STATUS_CONNECTION_REFUSED")
            || text.contains("NT_STATUS_UNSUCCESSFUL")
        {
            return Err(Error::Unreachable(crate::tr!(
                "error-server-no-answer",
                host = &parsed.host
            )));
        }
        Ok(backends::parse_shares(&output.stdout, &parsed))
    }

    /// Attach a disk image read-only and mount it.
    ///
    /// # Errors
    /// When the image cannot be opened or has no mountable file system.
    pub async fn mount_image(&self, path: &Path) -> Result<PathBuf> {
        let file = std::fs::File::open(path)
            .map_err(|e| Error::Invalid(crate::tr!("error-image-open", error = e.to_string())))?;
        if !file.metadata().is_ok_and(|m| m.is_file()) {
            return Err(Error::Invalid(crate::tr!("error-not-image")));
        }
        let udisks = self.udisks()?;
        let block = udisks.loop_setup(std::os::fd::OwnedFd::from(file)).await?;
        let mut last = Error::Failed(crate::tr!("error-image-no-filesystem"));
        for _ in 0..30 {
            let objects = udisks.objects().await?;
            // The image itself, or its first partition with a file system.
            let candidates: Vec<String> = objects
                .iter()
                .filter(|(p, o)| {
                    o.contains_key("org.freedesktop.UDisks2.Filesystem")
                        && (p.as_str() == block || p.as_str().starts_with(&format!("{block}p")))
                })
                .map(|(p, _)| p.to_string())
                .collect();
            if let Some(target) = candidates.iter().min() {
                match udisks.mount(target).await {
                    Ok(point) => {
                        self.refresh_drives().await;
                        return Ok(point);
                    }
                    Err(error) => last = error,
                }
            }
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
        let _ = udisks.loop_delete(&block).await;
        Err(last)
    }

    // ----- background work -----

    /// Work out what this system supports without starting anything: the
    /// root service is only checked for being installed (activatable), and the
    /// keyring only for being available.
    async fn refresh_caps(&self, session: &zbus::Connection) {
        let system_service = match &self.system {
            Some(system) => match zbus::fdo::DBusProxy::new(system).await {
                Ok(dbus) => dbus
                    .list_activatable_names()
                    .await
                    .is_ok_and(|names| names.iter().any(|n| n.as_str() == api::SYSTEM_BUS_NAME)),
                Err(_) => false,
            },
            None => false,
        };
        let mut caps = Capabilities {
            sftp: crate::process::helper("sshfs").is_some(),
            webdav_ftp: crate::process::helper("rclone").is_some(),
            mtp: crate::process::helper("aft-mtp-mount").is_some(),
            ios: crate::process::helper("ifuse").is_some()
                && crate::process::helper("idevicepair").is_some(),
            smb_browse: crate::process::helper("smbclient").is_some(),
            cloud: cloud::available()
                .iter()
                .map(|p| p.key().to_owned())
                .collect(),
            keyring: keyring::available(session).await,
            smb: system_service && crate::system::kernel_has("cifs"),
            nfs: system_service && crate::process::helper("mount.nfs").is_some(),
            ..Capabilities::default()
        };
        let mut inner = self.lock();
        caps.drives = inner.caps.drives;
        inner.caps = caps;
        drop(inner);
        self.changed();
    }

    /// Re-read UDisks2 so a snapshot right after an action is current.
    async fn refresh_drives(&self) {
        let Some(system) = self.system.clone() else {
            return;
        };
        let udisks = udisks::Udisks::new(system);
        match udisks.objects().await {
            Ok(objects) => {
                let mut items = udisks::items(&objects, rustix::process::getuid().as_raw());
                // Free space of mounted local volumes (fast, but still bounded).
                let paths: Vec<(usize, PathBuf)> = items
                    .iter()
                    .enumerate()
                    .filter_map(|(i, item)| item.mount_path.clone().map(|p| (i, p)))
                    .collect();
                let spaces = tokio::time::timeout(
                    Duration::from_secs(2),
                    tokio::task::spawn_blocking(move || {
                        paths
                            .into_iter()
                            .filter_map(|(i, p)| {
                                rustix::fs::statvfs(&p).ok().map(|v| {
                                    (
                                        i,
                                        v.f_bavail.saturating_mul(v.f_frsize),
                                        v.f_blocks.saturating_mul(v.f_frsize),
                                    )
                                })
                            })
                            .collect::<Vec<_>>()
                    }),
                )
                .await;
                if let Ok(Ok(spaces)) = spaces {
                    for (i, free, capacity) in spaces {
                        items[i].free = Some(free);
                        items[i].capacity = Some(capacity);
                    }
                }
                self.apply_drives(items);
            }
            Err(error) => {
                let mut inner = self.lock();
                inner.caps.drives = false;
                inner.drives.clear();
                drop(inner);
                self.changed();
                crate::log!(info, "drives unavailable: {}", error.message());
            }
        }
    }

    fn apply_drives(&self, items: Vec<Item>) {
        let mut inner = self.lock();
        inner.caps.drives = true;
        let ids: HashSet<&str> = items.iter().map(|i| i.id.as_str()).collect();
        inner
            .overlay
            .retain(|k, _| !k.starts_with("block:") || ids.contains(k.as_str()));
        // A state UDisks2 now reports supersedes a stale failure.
        for item in items.iter().filter(|i| i.state == State::Mounted) {
            if matches!(inner.overlay.get(&item.id), Some(State::Failed { .. })) {
                inner.overlay.remove(&item.id);
            }
        }
        inner.drives = items;
        drop(inner);
        self.changed();
    }

    async fn watch_drives(self: Arc<Self>) {
        let Some(system) = self.system.clone() else {
            return;
        };
        let udisks = udisks::Udisks::new(system);
        loop {
            let mut changes = match udisks.changes().await {
                Ok(changes) => changes,
                Err(error) => {
                    crate::log!(warn, "cannot watch drives: {}", error.message());
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    continue;
                }
            };
            loop {
                self.refresh_drives().await;
                // Wait for a signal, then let the burst settle.
                if changes.next().await.is_none() {
                    break;
                }
                let settle = tokio::time::sleep(Duration::from_millis(200));
                tokio::pin!(settle);
                loop {
                    tokio::select! {
                        () = &mut settle => break,
                        next = changes.next() => if next.is_none() { break },
                    }
                }
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    async fn watch_usb(self: Arc<Self>) {
        let (sender, mut receiver) = tokio::sync::mpsc::channel(8);
        usb::spawn(sender);
        while let Some(usb::Event::All(devices)) = receiver.recv().await {
            // Devices present when the service started were already there at
            // login; only later arrivals are announced.
            let (arrived, departed): (Vec<usb::UsbDevice>, Vec<String>) = {
                let inner = self.lock();
                let before: HashSet<String> = inner.usb.iter().map(usb::UsbDevice::id).collect();
                let now: HashSet<String> = devices.iter().map(usb::UsbDevice::id).collect();
                (
                    devices
                        .iter()
                        .filter(|d| !before.contains(&d.id()))
                        .cloned()
                        .collect(),
                    before.difference(&now).cloned().collect(),
                )
            };
            let gone: Vec<String> = {
                let mut inner = self.lock();
                let present: HashSet<String> = devices.iter().map(usb::UsbDevice::id).collect();
                let gone = inner
                    .mounts
                    .keys()
                    .filter(|id| {
                        (id.starts_with("mtp:") || id.starts_with("ios:")) && !present.contains(*id)
                    })
                    .cloned()
                    .collect();
                inner.overlay.retain(|id, _| {
                    !(id.starts_with("mtp:") || id.starts_with("ios:")) || present.contains(id)
                });
                inner.usb = devices;
                gone
            };
            for id in gone {
                // Unplugged while mounted: stop the helper and drop the dead mount.
                let _ = self.unmount(&id, true).await;
            }
            self.changed();
            for id in departed {
                self.unnotify(&id).await;
            }
            for device in arrived {
                let (summary, body, icon) = notify::arrival(device.kind, &device.label);
                let id = device.id();
                self.notify(notify::Note {
                    item: &id,
                    summary,
                    body,
                    icon,
                    actions: &[(notify::Action::Open, crate::tr!("action-open"))],
                    lasting: false,
                    category: "device.added",
                })
                .await;
            }
        }
    }

    /// Probe mounts and retry automatic locations every [`PROBE_INTERVAL`];
    /// with nothing mounted and nothing to reconnect, sleep until a change.
    async fn health(self: Arc<Self>) {
        loop {
            let idle = {
                let inner = self.lock();
                inner.mounts.is_empty()
                    && inner.restore.is_empty()
                    && !inner.locations.iter().any(|l| {
                        l.auto_connect
                            && inner
                                .retry
                                .get(&l.id)
                                .is_none_or(|r| !r.needs_user && !r.paused)
                    })
            };
            if idle {
                self.wake.notified().await;
                continue;
            }
            tokio::time::sleep(PROBE_INTERVAL).await;
            self.probe_all().await;
            self.autoconnect();
        }
    }

    async fn probe_all(self: &Arc<Self>) {
        let table = crate::mountinfo::current().ok();
        let targets: Vec<(String, PathBuf, bool)> = {
            let mut inner = self.lock();
            if inner.sleeping {
                return;
            }
            inner
                .mounts
                .iter_mut()
                .filter(|(_, a)| !a.probing)
                .map(|(id, a)| {
                    a.probing = true;
                    (
                        id.clone(),
                        a.path.clone(),
                        table
                            .as_ref()
                            .is_none_or(|t| crate::mountinfo::at(t, &a.path).is_some()),
                    )
                })
                .collect()
        };
        for (id, path, present) in targets {
            if !present {
                crate::log!(info, "{id} was unmounted outside the service");
                self.forget_mount(&id, true).await;
                continue;
            }
            let daemon = Arc::clone(self);
            tokio::spawn(async move {
                let result = fuse::probe(path, PROBE_TIMEOUT).await;
                let (disconnected, change) = {
                    let mut inner = daemon.lock();
                    // A share released for suspend fails its last probe.
                    if inner.sleeping {
                        if let Some(active) = inner.mounts.get_mut(&id) {
                            active.probing = false;
                        }
                        return;
                    }
                    let Some(active) = inner.mounts.get_mut(&id) else {
                        return;
                    };
                    active.probing = false;
                    if let Ok(space) = result {
                        active.space = Some(space);
                    }
                    let was = inner.overlay.get(&id) == Some(&State::NotResponding);
                    match result {
                        Ok(_) => {
                            if was {
                                inner.overlay.remove(&id);
                            }
                            (false, was.then_some(false))
                        }
                        Err(fuse::ProbeFailure::Disconnected) => (true, None),
                        Err(_) => {
                            inner.overlay.insert(id.clone(), State::NotResponding);
                            (false, (!was).then_some(true))
                        }
                    }
                };
                if disconnected {
                    daemon.helper_died(&id).await;
                }
                match change {
                    Some(true) => {
                        let label = daemon.label(&id);
                        daemon
                            .notify(notify::Note {
                                item: &id,
                                summary: crate::tr!("notify-not-responding", device = &label),
                                body: crate::tr!("notify-not-responding-body"),
                                icon: "network-error",
                                actions: &[(
                                    notify::Action::Disconnect,
                                    crate::tr!("action-disconnect"),
                                )],
                                lasting: true,
                                category: "device.error",
                            })
                            .await;
                    }
                    Some(false) => daemon.unnotify(&id).await,
                    None => {}
                }
                daemon.changed();
            });
        }
    }

    fn autoconnect(self: &Arc<Self>) {
        let now = Instant::now();
        let due: Vec<String> = {
            let mut inner = self.lock();
            if inner.sleeping {
                return;
            }
            let Inner {
                restore, mounts, ..
            } = &mut *inner;
            restore.retain(|id| !mounts.contains_key(id));
            let clouds = inner
                .clouds
                .iter()
                .filter(|a| a.auto_connect)
                .map(|a| &a.id);
            inner
                .locations
                .iter()
                .filter(|l| l.auto_connect || inner.restore.contains(&l.id))
                .map(|l| &l.id)
                .chain(clouds)
                .filter(|id| !inner.mounts.contains_key(*id) && !inner.busy.contains(*id))
                .filter(|id| {
                    inner.retry.get(*id).is_none_or(|r| {
                        !r.needs_user && !r.paused && r.next.is_none_or(|n| n <= now)
                    })
                })
                .cloned()
                .collect()
        };
        for id in due {
            let daemon = Arc::clone(self);
            tokio::spawn(async move {
                let result = daemon.mount(&id, Credentials::default()).await;
                let mut gone = false;
                let attention = {
                    let mut inner = daemon.lock();
                    // Auto-connecting locations keep retrying on their own.
                    let restoring = inner.restore.contains(&id)
                        && !inner.locations.iter().any(|l| l.id == id && l.auto_connect);
                    let retry = inner.retry.entry(id.clone()).or_default();
                    let attention = match result {
                        Ok(_) => {
                            inner.retry.remove(&id);
                            inner.restore.remove(&id);
                            None
                        }
                        Err(
                            error @ (Error::NeedsCredentials(_)
                            | Error::AuthFailed(_)
                            | Error::HostKeyUnknown(_)
                            | Error::HostKeyChanged(_)
                            | Error::NotAuthorized(_)
                            | Error::Unsupported(_)
                            | Error::Invalid(_)),
                        ) => {
                            retry.needs_user = true;
                            Some(error)
                        }
                        Err(_) => {
                            retry.failures = retry.failures.saturating_add(1);
                            let wait = Duration::from_secs(
                                30u64.saturating_mul(1 << retry.failures.min(5)),
                            )
                            .min(MAX_BACKOFF);
                            retry.next = Some(Instant::now() + wait);
                            gone = restoring && retry.failures >= RESTORE_ATTEMPTS;
                            None
                        }
                    };
                    if attention.is_some() || gone {
                        inner.restore.remove(&id);
                    }
                    attention
                };
                if gone {
                    daemon.helper_died(&id).await;
                } else if let Some(error) = attention {
                    let label = daemon.label(&id);
                    let body = match error {
                        Error::NeedsCredentials(_) | Error::AuthFailed(_) => {
                            crate::tr!("notify-auto-password")
                        }
                        Error::HostKeyUnknown(_) | Error::HostKeyChanged(_) => {
                            crate::tr!("notify-auto-identity")
                        }
                        other => other.message(),
                    };
                    daemon
                        .notify(notify::Note {
                            item: &id,
                            summary: crate::tr!("notify-auto-failed", device = &label),
                            body,
                            icon: "network-server",
                            actions: &[],
                            lasting: true,
                            category: "network.error",
                        })
                        .await;
                }
            });
        }
    }

    /// Reset backoff and retry automatic connections (network came back).
    fn network_up(self: &Arc<Self>) {
        let mut inner = self.lock();
        #[allow(
            clippy::iter_over_hash_type,
            reason = "every entry is reset; order is irrelevant"
        )]
        for retry in inner.retry.values_mut() {
            retry.failures = 0;
            retry.next = None;
        }
    }

    async fn watch_network(self: Arc<Self>) {
        let Some(system) = self.system.clone() else {
            return;
        };
        let Ok(rule) = zbus::MatchRule::builder()
            .msg_type(zbus::message::Type::Signal)
            .interface("org.freedesktop.NetworkManager")
            .member("StateChanged")
            .build()
        else {
            return;
        };
        let Ok(mut stream) =
            zbus::MessageStream::for_match_rule(rule, &system, std::num::NonZeroUsize::new(16))
                .await
        else {
            return;
        };
        while let Some(Ok(message)) = stream.next().await {
            let Ok(state) = message.body().deserialize::<u32>() else {
                continue;
            };
            // 50 local, 60 site, 70 global connectivity.
            if state >= 50 {
                self.network_up();
                tokio::time::sleep(Duration::from_secs(2)).await;
                self.autoconnect();
            } else if state != NM_STATE_ASLEEP {
                self.probe_all().await;
            }
        }
    }

    /// Release kernel network shares before suspend. When the Wi-Fi goes
    /// down, any task touching such a share blocks in the kernel until the
    /// client gives up on the server, about half a minute, and systemd cannot
    /// freeze the session around it, so suspend stalls that long with the
    /// screen frozen. A forced unmount fails those requests at once. The
    /// shares reconnect after resume.
    async fn watch_sleep(self: Arc<Self>) {
        let Some(system) = self.system.clone() else {
            return;
        };
        let Ok(manager) = zbus::Proxy::new_owned(
            system,
            "org.freedesktop.login1",
            "/org/freedesktop/login1",
            "org.freedesktop.login1.Manager",
        )
        .await
        else {
            return;
        };
        let Ok(mut signals) = manager.receive_signal("PrepareForSleep").await else {
            return;
        };
        let mut inhibitor = inhibit_sleep(&manager).await;
        while let Some(message) = signals.next().await {
            let Ok(starting) = message.body().deserialize::<bool>() else {
                continue;
            };
            if starting {
                self.lock().sleeping = true;
                self.release_for_sleep().await;
                drop(inhibitor.take());
            } else {
                self.lock().sleeping = false;
                if inhibitor.is_none() {
                    inhibitor = inhibit_sleep(&manager).await;
                }
                self.changed();
                self.autoconnect();
            }
        }
    }

    async fn release_for_sleep(self: &Arc<Self>) {
        let shares: Vec<(String, PathBuf)> = {
            let inner = self.lock();
            inner
                .mounts
                .iter()
                .filter(|(id, a)| a.kernel && id.starts_with("net-"))
                .map(|(id, a)| (id.clone(), a.path.clone()))
                .collect()
        };
        if shares.is_empty() {
            return;
        }
        let started = Instant::now();
        let mut waits = tokio::task::JoinSet::new();
        for (id, path) in shares {
            // Busy keeps the mount table watcher from releasing the folder a
            // second time, and reconnection from reusing it, until the root
            // service is done with it.
            let Ok(guard) = self.begin(&id) else {
                continue;
            };
            let daemon = Arc::clone(self);
            let target = path.clone();
            let call = tokio::spawn(async move {
                let _guard = guard;
                daemon
                    .system_call::<_, ()>("Unmount", &(target.to_string_lossy().as_ref(), true))
                    .await
            });
            let daemon = Arc::clone(self);
            waits.spawn(async move {
                // The kernel drops the mount at once. Logging off from a
                // server that is already out of reach keeps the call going
                // for seconds after that, and suspend need not wait for it.
                let mounted = || {
                    crate::mountinfo::current()
                        .map_or(true, |table| crate::mountinfo::at(&table, &path).is_some())
                };
                while mounted() {
                    if call.is_finished() {
                        let error = match call.await {
                            Ok(Err(error)) => error.message(),
                            Ok(Ok(())) => "still mounted".to_owned(),
                            Err(error) => error.to_string(),
                        };
                        crate::log!(warn, "{id} could not be released for suspend: {error}");
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
                let mut inner = daemon.lock();
                inner.mounts.remove(&id);
                inner.overlay.remove(&id);
                inner.restore.insert(id);
                drop(inner);
                daemon.changed();
            });
        }
        // Calls still running when suspend proceeds finish after resume.
        let finished = tokio::time::timeout(SLEEP_RELEASE_TIMEOUT, async {
            while waits.join_next().await.is_some() {}
        })
        .await
        .is_ok();
        waits.detach_all();
        crate::log!(
            info,
            "network shares {} for suspend after {} ms",
            if finished {
                "released"
            } else {
                "still releasing"
            },
            started.elapsed().as_millis()
        );
    }

    async fn watch_mount_table(self: Arc<Self>) {
        let (sender, mut receiver) = tokio::sync::mpsc::channel::<()>(1);
        let spawned = std::thread::Builder::new()
            .name("enzimos-mount-mounts".to_owned())
            .spawn(move || {
                let Ok(file) = std::fs::File::open("/proc/self/mountinfo") else {
                    return;
                };
                loop {
                    let mut fds = [rustix::event::PollFd::new(
                        &file,
                        rustix::event::PollFlags::PRI | rustix::event::PollFlags::ERR,
                    )];
                    if rustix::event::poll(&mut fds, None).is_err() {
                        std::thread::sleep(Duration::from_secs(1));
                        continue;
                    }
                    // Re-arm by reading from the start.
                    let mut buffer = [0u8; 4096];
                    let _ = rustix::io::pread(&file, &mut buffer, 0);
                    if sender.try_send(()).is_err() && sender.is_closed() {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            });
        if spawned.is_err() {
            return;
        }
        while receiver.recv().await.is_some() {
            let Ok(table) = crate::mountinfo::current() else {
                continue;
            };
            let gone: Vec<String> = self
                .lock()
                .mounts
                .iter()
                .filter(|(_, a)| crate::mountinfo::at(&table, &a.path).is_none())
                .map(|(id, _)| id.clone())
                .collect();
            for id in gone {
                if !self.lock().busy.contains(&id) {
                    self.forget_mount(&id, true).await;
                }
            }
        }
    }

    /// Adopt kernel mounts made before a restart; clear dead FUSE mounts.
    async fn adopt(&self) {
        // Only ask the root service (and so start it) when a kernel mount, a
        // FUSE mount or a leftover folder of ours is there.
        if !leftovers_present() {
            return;
        }
        let Ok(json) = self.system_call::<_, String>("List", &()).await else {
            return;
        };
        let Ok(entries) = serde_json::from_str::<Vec<serde_json::Value>>(&json) else {
            return;
        };
        for entry in entries {
            let path = PathBuf::from(entry["path"].as_str().unwrap_or_default());
            let mounted = entry["mounted"].as_bool().unwrap_or(false);
            let kernel = entry["kind"].as_str() == Some("kernel");
            if !kernel {
                if mounted {
                    // Its helper died with the previous service instance.
                    fuse::lazy_unmount(&path).await;
                }
                self.release_mountpoint(&path, false).await;
                continue;
            }
            if !mounted {
                continue;
            }
            let protocol = entry["protocol"].as_str().unwrap_or_default();
            let source = entry["source"].as_str().unwrap_or_default();
            let uri = match protocol {
                "smb" => format!("smb:{source}"),
                "nfs" => format!("nfs://{}", source.replacen(":/", "/", 1)),
                _ => continue,
            };
            let Ok(parsed) = NetUri::parse(&uri) else {
                continue;
            };
            let id = {
                let inner = self.lock();
                inner
                    .locations
                    .iter()
                    .find(|l| {
                        l.net_uri().is_ok_and(|u| {
                            u.host == parsed.host
                                && u.share == parsed.share
                                && u.path == parsed.path
                                && u.scheme == parsed.scheme
                        })
                    })
                    .map(|l| l.id.clone())
            };
            let id = match id {
                Some(id) => id,
                None => match self.add_location(&uri, "", &HashMap::new()) {
                    Ok(id) => id,
                    Err(_) => continue,
                },
            };
            self.lock().mounts.insert(id, Active::kernel(path));
        }
        self.changed();
    }
}

/// Names of this user's programs with files or folders open below `path`.
fn holders(path: &Path) -> Vec<String> {
    let uid = rustix::process::getuid().as_raw();
    let own_pid = std::process::id();
    let mut names = std::collections::BTreeSet::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        if pid == own_pid {
            continue;
        }
        let dir = entry.path();
        let Ok(meta) = std::fs::metadata(&dir) else {
            continue;
        };
        if std::os::unix::fs::MetadataExt::uid(&meta) != uid {
            continue;
        }
        // readlink reports the path without touching the (possibly dead) mount.
        let inside =
            |link: PathBuf| std::fs::read_link(link).is_ok_and(|target| target.starts_with(path));
        let open = inside(dir.join("cwd"))
            || std::fs::read_dir(dir.join("fd"))
                .is_ok_and(|fds| fds.flatten().take(4096).any(|fd| inside(fd.path())));
        if open && let Ok(comm) = std::fs::read_to_string(dir.join("comm")) {
            names.insert(comm.trim().to_owned());
        }
        if names.len() >= 6 {
            break;
        }
    }
    names.into_iter().filter(|n| !n.is_empty()).collect()
}

/// A Busy message naming what keeps the mount open, when that can be found.
async fn busy_message(path: &Path, fallback: &str) -> String {
    let target = path.to_path_buf();
    let found = tokio::time::timeout(
        Duration::from_secs(3),
        tokio::task::spawn_blocking(move || holders(&target)),
    )
    .await;
    match found {
        Ok(Ok(names)) if !names.is_empty() => {
            crate::tr!("error-busy-programs", programs = names.join(", "))
        }
        _ => fallback.to_owned(),
    }
}

/// Split `DOMAIN\user` (and, for SMB, `user@domain`) into user and domain.
fn split_account(typed: &str, scheme: Scheme) -> (Option<String>, Option<String>) {
    let typed = typed.trim();
    if typed.is_empty() {
        return (None, None);
    }
    if let Some((domain, user)) = typed.split_once('\\') {
        return (
            Some(user.to_owned()),
            Some(domain.to_owned()).filter(|d| !d.is_empty()),
        );
    }
    if scheme == Scheme::Smb
        && let Some((user, domain)) = typed.split_once('@')
    {
        return (
            Some(user.to_owned()),
            Some(domain.to_owned()).filter(|d| !d.is_empty()),
        );
    }
    (Some(typed.to_owned()), None)
}

/// Whether `/run/media/<user>` holds anything that is not a UDisks2 mount.
fn leftovers_present() -> bool {
    let Ok(user) = std::env::var("USER") else {
        return true;
    };
    let dir = crate::system::mountpoint::media_root().join(user);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return false;
    };
    let Ok(table) = crate::mountinfo::current() else {
        return true;
    };
    entries
        .flatten()
        .any(|entry| match crate::mountinfo::at(&table, &entry.path()) {
            None => true,
            Some(mount) => {
                mount.fs_type.starts_with("fuse")
                    || matches!(mount.fs_type.as_str(), "cifs" | "smb3" | "nfs" | "nfs4")
            }
        })
}

/// Drop the passwords a location kept for an account it no longer uses.
fn forget_other_users(id: &str, user: String) {
    let id = id.to_owned();
    tokio::spawn(async move { keyring::forget_other_users(&id, &user).await });
}

fn uri_user(location: &Location) -> Option<String> {
    location.net_uri().ok().and_then(|u| u.user)
}

fn supported(caps: &Capabilities, scheme: Scheme) -> bool {
    match scheme {
        Scheme::Smb => caps.smb,
        Scheme::Nfs => caps.nfs,
        Scheme::Sftp => caps.sftp,
        Scheme::Dav | Scheme::Davs | Scheme::Ftp | Scheme::Ftps => caps.webdav_ftp,
    }
}

fn apply_active(item: &mut Item, active: Option<&Active>, overlay: Option<&State>) {
    if let Some(active) = active {
        item.state = State::Mounted;
        item.mount_path = Some(active.path.clone());
        item.can_mount = false;
        item.can_unmount = true;
        item.read_only = active.read_only;
        if let Some((free, capacity)) = active.space {
            item.free = Some(free);
            item.capacity = Some(capacity);
        }
    }
    if let Some(state) = overlay {
        item.state = state.clone();
    }
}

fn persist(inner: &Inner) {
    if !inner.locations_writable {
        return;
    }
    if let Err(error) = locations::save(&inner.locations) {
        crate::log!(warn, "could not save network locations: {error}");
    }
}

fn apply_options(location: &mut Location, options: &HashMap<String, OwnedVariant>) -> Result<()> {
    let mut keys: Vec<&String> = options.keys().collect();
    keys.sort();
    for key in keys {
        let value = &options[key];
        let value: &Variant<'_> = value;
        match key.as_str() {
            "save" => {
                location.saved = value
                    .downcast_ref::<bool>()
                    .map_err(|_| Error::Invalid("save must be a boolean".to_owned()))?
            }
            "auto_connect" => {
                location.auto_connect = value
                    .downcast_ref::<bool>()
                    .map_err(|_| Error::Invalid("auto_connect must be a boolean".to_owned()))?;
                if location.auto_connect {
                    location.saved = true;
                }
            }
            "label" => {
                let label: &str = value
                    .downcast_ref()
                    .map_err(|_| Error::Invalid("label must be text".to_owned()))?;
                if !label.trim().is_empty() {
                    location.label = label
                        .trim()
                        .chars()
                        .filter(|c| !c.is_control())
                        .take(120)
                        .collect();
                }
            }
            "smb_version" => {
                let version: &str = value
                    .downcast_ref()
                    .map_err(|_| Error::Invalid("smb_version must be text".to_owned()))?;
                location.smb_version = match version {
                    "" | "default" => None,
                    v if crate::system::worker::SMB_VERSIONS.contains(&v) => Some(v.to_owned()),
                    _ => {
                        return Err(Error::Invalid(crate::tr!(
                            "error-invalid-field",
                            field = "smb_version"
                        )));
                    }
                };
            }
            "forget_password" => {}
            "username" => {
                let user: &str = value
                    .downcast_ref()
                    .map_err(|_| Error::Invalid("username must be text".to_owned()))?;
                let uri = location.net_uri().map_err(|e| Error::Invalid(e.0))?;
                if !user.is_empty() && !crate::uri::valid_name(user, 128) {
                    return Err(Error::Invalid(crate::tr!("uri-bad-user")));
                }
                location.uri = uri
                    .with_user(
                        Some(user.to_owned()).filter(|u| !u.is_empty()),
                        uri.domain.clone(),
                    )
                    .display();
            }
            _ => {
                return Err(Error::Invalid(crate::tr!(
                    "error-invalid-field",
                    field = key.as_str()
                )));
            }
        }
    }
    Ok(())
}

/// `(SHA256 fingerprint, known_hosts line)` for each key the server offers.
async fn scan_host_keys(uri: &NetUri) -> Vec<(String, String)> {
    let (Some(scan), Some(keygen)) = (
        crate::process::helper("ssh-keyscan"),
        crate::process::helper("ssh-keygen"),
    ) else {
        return Vec::new();
    };
    let port = uri.port.unwrap_or(22).to_string();
    let Ok(output) = crate::process::run(
        Spec::new(scan, Duration::from_secs(12)).args(["-T", "5", "-p", &port, "--", &uri.host]),
    )
    .await
    else {
        return Vec::new();
    };
    let mut keys = Vec::new();
    for line in output
        .stdout
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .take(8)
    {
        let mut spec =
            Spec::new(&keygen, Duration::from_secs(5)).args(["-l", "-E", "sha256", "-f", "-"]);
        spec.stdin = Some(zeroize::Zeroizing::new(format!("{line}\n").into_bytes()));
        if let Ok(fp) = crate::process::run(spec).await
            && let Some(fingerprint) = fp
                .stdout
                .split_whitespace()
                .nth(1)
                .filter(|f| f.starts_with("SHA256:"))
        {
            keys.push((fingerprint.to_owned(), line.to_owned()));
        }
    }
    keys
}

/// The D-Bus object.
pub struct Interface {
    daemon: Arc<Daemon>,
}

fn options_map(options: HashMap<String, OwnedVariant>) -> HashMap<String, OwnedVariant> {
    options
}

#[allow(missing_docs, reason = "zbus generates the D-Bus glue")]
#[zbus::interface(name = "org.enzimos.Mount1")]
impl Interface {
    /// The current snapshot as JSON.
    fn list(&self) -> String {
        serde_json::to_string(&self.daemon.snapshot()).unwrap_or_default()
    }

    /// Mount an item; returns the mounted folder.
    async fn mount(&self, id: String) -> Result<String> {
        self.daemon
            .mount(&id, Credentials::default())
            .await
            .map(|p| p.to_string_lossy().into_owned())
    }

    /// Mount with credentials; `secret` is a sealed memfd (may be empty).
    async fn mount_with_credentials(
        &self,
        id: String,
        username: String,
        domain: String,
        secret: OwnedFd,
        remember: bool,
    ) -> Result<String> {
        let secret = crate::secret::from_fd(&secret).map_err(Error::Invalid)?;
        let credentials = Credentials {
            username: Some(username).filter(|u| !u.is_empty()),
            domain: Some(domain).filter(|d| !d.is_empty()),
            secret: Some(secret),
            remember,
        };
        self.daemon
            .mount(&id, credentials)
            .await
            .map(|p| p.to_string_lossy().into_owned())
    }

    /// Unlock an encrypted drive with a passphrase memfd and mount it.
    async fn unlock(&self, id: String, passphrase: OwnedFd) -> Result<String> {
        let secret = crate::secret::from_fd(&passphrase).map_err(Error::Invalid)?;
        self.daemon
            .unlock(&id, &secret)
            .await
            .map(|p| p.to_string_lossy().into_owned())
    }

    /// Unmount; `force` detaches even with open files or a dead server.
    async fn unmount(&self, id: String, force: bool) -> Result<()> {
        self.daemon.unmount(&id, force).await
    }

    /// Eject the drive holding this item (unmounting all its volumes).
    async fn eject(&self, id: String) -> Result<()> {
        self.daemon.eject(&id, false).await
    }

    /// Unmount all volumes of the drive and power it off.
    async fn safely_remove(&self, id: String) -> Result<()> {
        self.daemon.eject(&id, true).await
    }

    /// Add a cloud account; returns its identity while the sign-in runs in
    /// the browser (see [`Daemon::add_cloud`]).
    fn add_cloud(&self, provider: String, server: String) -> Result<String> {
        self.daemon.add_cloud(&provider, &server)
    }

    /// Quick-format a removable drive (see [`Daemon::format`]).
    async fn format(&self, id: String, options: HashMap<String, OwnedVariant>) -> Result<String> {
        self.daemon.format(&id, &options).await
    }

    /// Add a network location; options: `save`, `auto_connect`, `smb_version`.
    fn add_location(
        &self,
        uri: String,
        label: String,
        options: HashMap<String, OwnedVariant>,
    ) -> Result<String> {
        self.daemon
            .add_location(&uri, &label, &options_map(options))
    }

    /// Change `label`, `save`, `auto_connect`, `smb_version` or `username`.
    fn update_location(&self, id: String, options: HashMap<String, OwnedVariant>) -> Result<()> {
        self.daemon.update_location(&id, &options_map(options))
    }

    /// Mount a SMB/NFS location at startup, before login (administrator
    /// approval once). `secret` may be empty to use the remembered password.
    async fn set_mount_at_boot(&self, id: String, enabled: bool, secret: OwnedFd) -> Result<()> {
        let secret = crate::secret::from_fd(&secret).map_err(Error::Invalid)?;
        self.daemon
            .set_mount_at_boot(&id, enabled, Some(secret))
            .await
    }

    /// Remove a location and its remembered password.
    async fn remove_location(&self, id: String) -> Result<()> {
        self.daemon.remove_location(&id).await
    }

    /// Trust SFTP host key fingerprints offered in a HostKeyUnknown error.
    async fn trust_host_key(&self, id: String, fingerprints: Vec<String>) -> Result<()> {
        self.daemon.trust_host_key(&id, &fingerprints).await
    }

    /// Find servers on the local network (JSON list).
    async fn discover(&self) -> String {
        serde_json::to_string(&discovery::discover(self.daemon.system.as_ref()).await)
            .unwrap_or_default()
    }

    /// List an SMB server's shares (JSON list); `secret` may be empty.
    async fn list_shares(
        &self,
        uri: String,
        username: String,
        domain: String,
        secret: OwnedFd,
    ) -> Result<String> {
        let secret = crate::secret::from_fd(&secret).map_err(Error::Invalid)?;
        let secret = (!secret.is_empty()).then_some(secret);
        let shares = self
            .daemon
            .list_shares(&uri, &username, &domain, secret)
            .await?;
        serde_json::to_string(&shares).map_err(|e| Error::Failed(e.to_string()))
    }

    /// Attach a disk image read-only and mount it.
    async fn mount_image(&self, path: String) -> Result<String> {
        self.daemon
            .mount_image(Path::new(&path))
            .await
            .map(|p| p.to_string_lossy().into_owned())
    }

    /// Emitted with the full snapshot JSON after changes.
    #[zbus(signal)]
    async fn changed(
        emitter: &zbus::object_server::SignalEmitter<'_>,
        snapshot: &str,
    ) -> zbus::Result<()>;

    /// Snapshot schema version.
    #[zbus(property)]
    fn version(&self) -> u32 {
        api::SCHEMA_VERSION
    }
}

/// Run the session service until the session ends.
///
/// # Errors
/// D-Bus connection failures.
pub async fn serve() -> zbus::Result<()> {
    let system = match zbus::Connection::system().await {
        Ok(connection) => Some(connection),
        Err(error) => {
            crate::log!(warn, "no system bus: {error}");
            None
        }
    };
    let (saved, writable) = locations::load();
    let daemon = Arc::new_cyclic(|me| Daemon {
        inner: Mutex::new(Inner {
            locations: saved,
            locations_writable: writable,
            clouds: cloud::load(),
            ..Inner::default()
        }),
        notify: tokio::sync::Notify::new(),
        wake: tokio::sync::Notify::new(),
        generation: AtomicU64::new(1),
        system,
        me: Weak::clone(me),
        notifier: std::sync::OnceLock::new(),
    });
    let connection = zbus::connection::Builder::session()
        .serve_at(
            api::OBJECT_PATH,
            Interface {
                daemon: Arc::clone(&daemon),
            },
        )
        .build()
        .await?;
    // Take the name only once the first snapshot is complete, so the first
    // List() a D-Bus-activated client makes is already accurate.
    daemon.refresh_caps(&connection).await;
    daemon.refresh_drives().await;
    if let Ok(devices) = tokio::task::spawn_blocking(usb::enumerate).await {
        daemon.lock().usb = devices;
    }
    daemon.adopt().await;
    connection.request_name(api::BUS_NAME).await?;
    crate::log!(info, "enzimos-mountd ready");
    tokio::spawn(Arc::clone(&daemon).watch_drives());
    tokio::spawn(Arc::clone(&daemon).watch_usb());
    tokio::spawn(Arc::clone(&daemon).watch_network());
    tokio::spawn(Arc::clone(&daemon).watch_sleep());
    tokio::spawn(Arc::clone(&daemon).watch_mount_table());
    tokio::spawn(Arc::clone(&daemon).health());
    let _ = daemon
        .notifier
        .set(notify::Notifier::new(connection.clone()));
    tokio::spawn(Arc::clone(&daemon).watch_notifications());
    let interface = connection
        .object_server()
        .interface::<_, Interface>(api::OBJECT_PATH)
        .await?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|e| zbus::Error::Failure(e.to_string()))?;
    loop {
        tokio::select! {
            () = daemon.notify.notified() => {
                tokio::time::sleep(Duration::from_millis(100)).await;
                daemon.generation.fetch_add(1, Ordering::SeqCst);
                let json = serde_json::to_string(&daemon.snapshot()).unwrap_or_default();
                let _ = Interface::changed(interface.signal_emitter(), &json).await;
            }
            _ = terminate.recv() => break,
        }
    }
    // Leave kernel mounts in place (they survive a service restart and are
    // adopted again); detach FUSE mounts whose helpers stop with us.
    let fuse: Vec<(String, PathBuf)> = daemon
        .lock()
        .mounts
        .iter()
        .filter(|(_, a)| !a.kernel)
        .map(|(id, a)| (id.clone(), a.path.clone()))
        .collect();
    for (id, path) in fuse {
        let _ = tokio::time::timeout(Duration::from_secs(5), daemon.unmount(&id, true)).await;
        let _ = std::fs::remove_dir(path);
    }
    Ok(())
}

/// A delay lock that holds suspend until the shares are released.
async fn inhibit_sleep(manager: &zbus::Proxy<'_>) -> Option<OwnedFd> {
    match manager
        .call::<_, _, OwnedFd>(
            "Inhibit",
            &(
                "sleep",
                "enzimos-mount",
                "Disconnecting network shares",
                "delay",
            ),
        )
        .await
    {
        Ok(fd) => Some(fd),
        Err(error) => {
            crate::log!(warn, "no suspend delay lock: {error}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_windows_accounts_split_into_user_and_domain() {
        let bs = char::from(92);
        let typed = format!("WORK{bs}alice");
        assert_eq!(
            split_account(&typed, Scheme::Smb),
            (Some("alice".to_owned()), Some("WORK".to_owned())),
            "DOMAIN\\user"
        );
        assert_eq!(
            split_account("alice@WORK", Scheme::Smb),
            (Some("alice".to_owned()), Some("WORK".to_owned())),
            "user@domain"
        );
        assert_eq!(
            split_account("alice@WORK", Scheme::Sftp).1,
            None,
            "@ only means a domain for SMB"
        );
        assert_eq!(
            split_account("  ", Scheme::Smb),
            (None, None),
            "blank keeps the address's user"
        );
    }
}
