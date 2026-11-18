//! The session service's public data model, serialized as JSON over D-Bus.
//!
//! Clients (Files, the shell, the CLI) receive a complete [`Snapshot`] from
//! `List()` and again in every `Changed` signal. Fields are only ever added;
//! a client ignores fields it does not know and must treat an unknown `kind`
//! or `state` as a generic location.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Snapshot schema version carried in [`Snapshot::version`].
pub const SCHEMA_VERSION: u32 = 1;

/// Well-known session bus name of the user service.
pub const BUS_NAME: &str = "org.enzimos.Mount1";
/// Object path of the user service.
pub const OBJECT_PATH: &str = "/org/enzimos/Mount1";
/// Interface name of the user service.
pub const INTERFACE: &str = "org.enzimos.Mount1";

/// Well-known system bus name of the root service.
pub const SYSTEM_BUS_NAME: &str = "org.enzimos.MountSystem1";
/// Object path of the root service.
pub const SYSTEM_OBJECT_PATH: &str = "/org/enzimos/MountSystem1";

/// Everything the user can open, mount or eject, at one moment.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    /// [`SCHEMA_VERSION`].
    pub version: u32,
    /// Increases with every published change.
    pub generation: u64,
    /// Which optional backends this system can use.
    pub capabilities: Capabilities,
    /// Locations in display order: drives, phones, then network.
    pub items: Vec<Item>,
}

/// Optional helpers found on this system.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools, reason = "independent feature flags")]
pub struct Capabilities {
    /// UDisks2 is reachable for drives.
    pub drives: bool,
    /// The root service can make kernel SMB mounts.
    pub smb: bool,
    /// The root service can make NFS mounts.
    pub nfs: bool,
    /// `sshfs` is installed.
    pub sftp: bool,
    /// `rclone` is installed (WebDAV and FTP).
    pub webdav_ftp: bool,
    /// `aft-mtp-mount` is installed.
    pub mtp: bool,
    /// `ifuse` and `idevicepair` are installed.
    pub ios: bool,
    /// `smbclient` is installed for listing a server's shares.
    pub smb_browse: bool,
    /// The Secret Service answered, so passwords can be remembered.
    pub keyring: bool,
    /// Cloud services that can be added (`google_drive`, `onedrive`, `dropbox`, `nextcloud`).
    #[serde(default)]
    pub cloud: Vec<String>,
}

/// What kind of storage an item is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// A USB drive or stick.
    Usb,
    /// A memory card in a reader.
    Card,
    /// An optical disc drive.
    Optical,
    /// An internal or other disk partition.
    Disk,
    /// A mounted disk image.
    Image,
    /// An Android phone or other MTP device.
    Phone,
    /// An iPhone or iPad.
    Ios,
    /// A camera speaking PTP/MTP.
    Camera,
    /// A network share.
    Network,
    /// A cloud drive account (Google Drive, OneDrive, Dropbox, Nextcloud).
    Cloud,
}

/// Where an item is in its life cycle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum State {
    /// Present and not mounted.
    Unmounted,
    /// A mount is in progress.
    Mounting,
    /// Mounted and responding.
    Mounted,
    /// An unmount is in progress.
    Unmounting,
    /// Being formatted.
    Formatting,
    /// Waiting for the person to sign in in the browser.
    SigningIn,
    /// Encrypted and locked; `Unlock` opens it.
    Locked,
    /// Mounted, but the last health probe did not answer in time.
    NotResponding,
    /// A drive with removable media but none inserted.
    NoMedia,
    /// The last operation failed; the item can be retried.
    Failed {
        /// A short, user-presentable reason.
        reason: String,
    },
}

/// One drive, phone or network location.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools, reason = "independent action flags")]
pub struct Item {
    /// Stable identity used by every method.
    pub id: String,
    /// What it is.
    pub kind: Kind,
    /// Display name.
    pub label: String,
    /// Secondary text, e.g. a size, server or model.
    pub detail: String,
    /// Life-cycle state.
    #[serde(flatten)]
    pub state: State,
    /// The mounted folder, when mounted.
    pub mount_path: Option<PathBuf>,
    /// Mounted read-only.
    pub read_only: bool,
    /// Size in bytes, when known.
    pub size: Option<u64>,
    /// `Mount` is meaningful.
    pub can_mount: bool,
    /// `Unmount` is meaningful.
    pub can_unmount: bool,
    /// `Eject` is meaningful (optical trays, card readers).
    pub can_eject: bool,
    /// `SafelyRemove` can power the drive off.
    pub can_power_off: bool,
    /// The block device, for drives.
    pub device: Option<PathBuf>,
    /// The drive this item belongs to; items with the same drive are removed together.
    pub drive: Option<String>,
    /// Network locations: the password-free address.
    pub uri: Option<String>,
    /// Network locations: kept across sessions.
    pub saved: bool,
    /// Network locations: connected automatically at login.
    pub auto_connect: bool,
    /// Network locations: mounted at startup, before login (SMB and NFS).
    #[serde(default)]
    pub mount_at_boot: bool,
    /// Network locations: `SetMountAtBoot` is possible (SMB and NFS).
    #[serde(default)]
    pub can_mount_at_boot: bool,
    /// Free bytes, when mounted and known.
    #[serde(default)]
    pub free: Option<u64>,
    /// Total bytes of the mounted file system, when known.
    #[serde(default)]
    pub capacity: Option<u64>,
    /// Drives: `Format` is possible (a removable drive that is not read-only).
    #[serde(default)]
    pub can_format: bool,
    /// Drives: the file system type, e.g. `exfat`, `vfat`, `ntfs`, `ext4`.
    #[serde(default)]
    pub filesystem: Option<String>,
}

impl Item {
    /// A minimal unmounted item; callers fill the rest.
    #[must_use]
    pub fn new(id: impl Into<String>, kind: Kind, label: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            kind,
            label: label.into(),
            detail: String::new(),
            state: State::Unmounted,
            mount_path: None,
            read_only: false,
            size: None,
            can_mount: true,
            can_unmount: false,
            can_eject: false,
            can_power_off: false,
            device: None,
            drive: None,
            uri: None,
            saved: false,
            auto_connect: false,
            mount_at_boot: false,
            can_mount_at_boot: false,
            free: None,
            capacity: None,
            can_format: false,
            filesystem: None,
        }
    }
}

/// D-Bus error names returned by `org.enzimos.Mount1`. The message carries a
/// user-presentable sentence; for [`NEEDS_CREDENTIALS`] and
/// [`HOST_KEY_UNKNOWN`] it is a JSON object instead (see `docs/API.md`).
pub mod errors {
    /// The location needs a user name and password.
    pub const NEEDS_CREDENTIALS: &str = "org.enzimos.Mount1.Error.NeedsCredentials";
    /// The supplied credentials were refused.
    pub const AUTH_FAILED: &str = "org.enzimos.Mount1.Error.AuthFailed";
    /// An SFTP server's key is not yet trusted.
    pub const HOST_KEY_UNKNOWN: &str = "org.enzimos.Mount1.Error.HostKeyUnknown";
    /// An SFTP server's key changed since it was trusted.
    pub const HOST_KEY_CHANGED: &str = "org.enzimos.Mount1.Error.HostKeyChanged";
    /// The server or device did not answer.
    pub const UNREACHABLE: &str = "org.enzimos.Mount1.Error.Unreachable";
    /// The operation did not finish within its time limit.
    pub const TIMEOUT: &str = "org.enzimos.Mount1.Error.Timeout";
    /// Files are still open on the mount.
    pub const BUSY: &str = "org.enzimos.Mount1.Error.Busy";
    /// No item has that identity.
    pub const NOT_FOUND: &str = "org.enzimos.Mount1.Error.NotFound";
    /// This system lacks the helper the item needs.
    pub const UNSUPPORTED: &str = "org.enzimos.Mount1.Error.Unsupported";
    /// The user or policy refused authorization.
    pub const NOT_AUTHORIZED: &str = "org.enzimos.Mount1.Error.NotAuthorized";
    /// The phone must be unlocked or must trust this computer.
    pub const DEVICE_LOCKED: &str = "org.enzimos.Mount1.Error.DeviceLocked";
    /// A request was malformed.
    pub const INVALID: &str = "org.enzimos.Mount1.Error.Invalid";
    /// A server address without a share: the message is JSON
    /// `{id, shares: [Share]}`; pick one and mount that.
    pub const CHOOSE_SHARE: &str = "org.enzimos.Mount1.Error.ChooseShare";
    /// The SMB server only speaks an older protocol; offer `smb_version`
    /// `1.0` (less secure) to the user.
    pub const PROTOCOL_MISMATCH: &str = "org.enzimos.Mount1.Error.ProtocolMismatch";
    /// Anything else.
    pub const FAILED: &str = "org.enzimos.Mount1.Error.Failed";
}

/// Body of a [`errors::NEEDS_CREDENTIALS`] error.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialRequest {
    /// The item asking.
    pub id: String,
    /// Suggested user name.
    pub username: String,
    /// Suggested domain or workgroup (SMB only).
    pub domain: Option<String>,
    /// Whether the password can be saved in the keyring.
    pub can_remember: bool,
    /// A previous attempt with the given credentials was refused.
    pub retry: bool,
}

/// Body of a [`errors::HOST_KEY_UNKNOWN`] or [`errors::HOST_KEY_CHANGED`] error.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostKeyRequest {
    /// The item asking.
    pub id: String,
    /// `host` or `[host]:port`.
    pub host: String,
    /// `SHA256:` fingerprints the server offered.
    pub fingerprints: Vec<String>,
}

/// A server found on the local network by `Discover()`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredServer {
    /// Display name.
    pub name: String,
    /// Connectable address, e.g. `smb://nas.local/`.
    pub uri: String,
    /// How it was found: `mdns` or `wsd`.
    pub source: String,
}

/// Body of a [`errors::CHOOSE_SHARE`] error.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareChoice {
    /// The server location asking.
    pub id: String,
    /// Shares the server offers.
    pub shares: Vec<Share>,
}

/// A share offered by an SMB server, from `ListShares()`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Share {
    /// Share name.
    pub name: String,
    /// Server-provided comment.
    pub comment: String,
    /// Address to connect to.
    pub uri: String,
}
