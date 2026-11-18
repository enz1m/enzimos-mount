//! Drives through UDisks2.
//!
//! The inventory is rebuilt from `GetManagedObjects` after any UDisks2 signal
//! (debounced), which keeps it correct without incremental bookkeeping. Mount,
//! unmount, unlock, eject and power-off are UDisks2 calls, so its polkit rules
//! decide what an active local user may do without a password.

use crate::api::{Item, Kind, State};
use crate::error::{Error, Result};
use futures_util::StreamExt;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;
use zbus::{OwnedObjectPath, OwnedVariant, Variant};

/// UDisks2 bus name.
pub const UDISKS: &str = "org.freedesktop.UDisks2";
const ROOT: &str = "/org/freedesktop/UDisks2";
/// Deadline for a UDisks2 action, which may wait for an administrator password.
pub const ACTION_TIMEOUT: Duration = Duration::from_secs(150);
/// Deadline for formatting (a quick format; large NTFS or ext4 drives take a while).
pub const FORMAT_TIMEOUT: Duration = Duration::from_secs(600);

/// File systems offered for formatting, with their MBR partition type.
pub const FORMATS: [(&str, &str); 4] = [
    ("exfat", "0x07"),
    ("vfat", "0x0c"),
    ("ntfs", "0x07"),
    ("ext4", "0x83"),
];

/// A volume label valid for file system `fs` (empty means none).
#[must_use]
pub fn valid_label(fs: &str, label: &str) -> bool {
    if label.chars().any(char::is_control) {
        return false;
    }
    match fs {
        // FAT labels are short, upper-case ASCII without these characters.
        "vfat" => {
            label.len() <= 11
                && label.is_ascii()
                && !label.contains([
                    '"', '*', '+', ',', '.', '/', ':', ';', '<', '=', '>', '?', '[', '\\', ']', '|',
                ])
        }
        "exfat" => label.encode_utf16().count() <= 15,
        "ntfs" => label.encode_utf16().count() <= 32,
        "ext4" => label.len() <= 16,
        _ => false,
    }
}

/// Interfaces and properties of one object.
pub type Interfaces = HashMap<String, HashMap<String, OwnedVariant>>;
/// All UDisks2 objects.
pub type Objects = HashMap<OwnedObjectPath, Interfaces>;

/// Partition types never offered: EFI system, Microsoft reserved, Windows
/// recovery, BIOS boot, Linux swap (GPT), and their MBR equivalents.
const HIDDEN_PARTITION_TYPES: [&str; 8] = [
    "c12a7328-f81f-11d2-ba4b-00a0c93ec93b",
    "e3c9e316-0b5c-4db8-817d-f92df00215ae",
    "de94bba4-06d1-4d40-a16a-bfd50179d6ac",
    "21686148-6449-6e6f-744e-656564454649",
    "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f",
    "0xef",
    "0x27",
    "0x82",
];

fn prop<'a>(o: &'a Interfaces, iface: &str, key: &str) -> Option<&'a OwnedVariant> {
    o.get(&format!("org.freedesktop.UDisks2.{iface}"))?.get(key)
}

fn has(o: &Interfaces, iface: &str) -> bool {
    o.contains_key(&format!("org.freedesktop.UDisks2.{iface}"))
}

fn flag(o: &Interfaces, iface: &str, key: &str) -> bool {
    prop(o, iface, key)
        .and_then(|v| v.downcast_ref::<bool>().ok())
        .unwrap_or(false)
}

fn text(o: &Interfaces, iface: &str, key: &str) -> String {
    prop(o, iface, key)
        .and_then(|v| v.downcast_ref::<&str>().ok().map(str::to_owned))
        .unwrap_or_default()
}

fn number(o: &Interfaces, iface: &str, key: &str) -> u64 {
    prop(o, iface, key)
        .and_then(|v| v.downcast_ref::<u64>().ok())
        .unwrap_or(0)
}

fn uid_of(o: &Interfaces, iface: &str, key: &str) -> Option<u32> {
    prop(o, iface, key).and_then(|v| v.downcast_ref::<u32>().ok())
}

fn object(o: &Interfaces, iface: &str, key: &str) -> Option<OwnedObjectPath> {
    prop(o, iface, key)
        .and_then(|v| OwnedObjectPath::try_from(v.try_clone().ok()?).ok())
        .filter(|p| p.as_str() != "/")
}

fn byte_string(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn device(o: &Interfaces) -> Option<PathBuf> {
    let raw = prop(o, "Block", "PreferredDevice").or_else(|| prop(o, "Block", "Device"))?;
    let bytes = <Vec<u8>>::try_from(raw.try_clone().ok()?).ok()?;
    let text = byte_string(&bytes);
    (!text.is_empty()).then(|| PathBuf::from(text))
}

/// Mount points of the `Filesystem` interface of `o`.
#[must_use]
pub fn mount_points(o: &Interfaces) -> Vec<PathBuf> {
    prop(o, "Filesystem", "MountPoints")
        .and_then(|v| <Vec<Vec<u8>>>::try_from(v.try_clone().ok()?).ok())
        .unwrap_or_default()
        .iter()
        .map(|b| PathBuf::from(byte_string(b)))
        .filter(|p| !p.as_os_str().is_empty())
        .collect()
}

/// A mount the desktop presents, as opposed to a system mount such as `/home`.
#[must_use]
pub fn is_media_mount(path: &Path) -> bool {
    path.starts_with("/run/media") || path.starts_with("/media") || path.starts_with("/mnt")
}

fn basename(path: &OwnedObjectPath) -> &str {
    path.as_str().rsplit('/').next().unwrap_or_default()
}

/// Human size, base 10 like drive vendors print it.
#[must_use]
pub fn format_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["bytes", "kB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1000.0 && unit + 1 < UNITS.len() {
        value /= 1000.0;
        unit += 1;
    }
    if unit == 0 {
        return crate::tr!(
            "size-bytes",
            count = usize::try_from(bytes).unwrap_or(usize::MAX)
        );
    }
    let number = if value >= 10.0 {
        format!("{value:.0}")
    } else {
        format!("{value:.1}").replace('.', &crate::tr!("number-decimal-separator"))
    };
    format!("{number} {}", UNITS[unit])
}

/// Item identity for a block object.
#[must_use]
pub fn block_id(path: &OwnedObjectPath) -> String {
    format!("block:{}", basename(path))
}

/// The items UDisks2 objects describe for user `uid`.
#[must_use]
pub fn items(objects: &Objects, uid: u32) -> Vec<Item> {
    let mut out = Vec::new();
    let mut drives_with_items = std::collections::HashSet::new();
    // Sorted, so identities and order never depend on hash iteration.
    let mut sorted: Vec<(&OwnedObjectPath, &Interfaces)> = objects.iter().collect();
    sorted.sort_by(|a, b| a.0.as_str().cmp(b.0.as_str()));
    for &(path, o) in &sorted {
        if !has(o, "Block")
            || flag(o, "Block", "HintIgnore")
            || object(o, "Block", "CryptoBackingDevice").is_some()
        {
            continue;
        }
        let encrypted = has(o, "Encrypted");
        let cleartext = if encrypted {
            object(o, "Encrypted", "CleartextDevice").and_then(|p| objects.get(&p))
        } else {
            None
        };
        let fs_object = if encrypted { cleartext } else { Some(o) };
        let filesystem = fs_object.is_some_and(|f| has(f, "Filesystem"));
        if !filesystem && !encrypted {
            continue;
        }
        if has(o, "Swapspace") || text(o, "Block", "IdType") == "swap" {
            continue;
        }
        let part_type = text(o, "Partition", "Type").to_ascii_lowercase();
        if HIDDEN_PARTITION_TYPES.contains(&part_type.as_str()) {
            continue;
        }
        let is_loop = has(o, "Loop");
        if is_loop && uid_of(o, "Loop", "SetupByUID") != Some(uid) {
            continue;
        }
        let drive_path = object(o, "Block", "Drive");
        let drive = drive_path.as_ref().and_then(|p| objects.get(p));
        let label_raw = {
            let own = text(o, "Block", "IdLabel");
            if own.is_empty() {
                cleartext
                    .map(|c| text(c, "Block", "IdLabel"))
                    .unwrap_or_default()
            } else {
                own
            }
        };
        if label_raw.to_ascii_uppercase().starts_with("ENZIMOS") {
            continue;
        }
        let points = fs_object.map(mount_points).unwrap_or_default();
        let removable = drive
            .is_some_and(|d| flag(d, "Drive", "Removable") || flag(d, "Drive", "MediaRemovable"));
        if !removable && !is_loop && points.iter().any(|p| !is_media_mount(p)) {
            // A system mount such as / or /home.
            continue;
        }
        let bus = drive
            .map(|d| text(d, "Drive", "ConnectionBus"))
            .unwrap_or_default();
        let media = drive.map(|d| text(d, "Drive", "Media")).unwrap_or_default();
        let optical = drive.is_some_and(|d| flag(d, "Drive", "Optical"));
        let kind = if is_loop {
            Kind::Image
        } else if optical {
            Kind::Optical
        } else if bus == "sdio"
            || media.starts_with("flash_sd")
            || media.starts_with("flash_ms")
            || media.starts_with("flash_cf")
        {
            Kind::Card
        } else if bus == "usb" || bus == "ieee1394" {
            Kind::Usb
        } else {
            Kind::Disk
        };
        let size = number(o, "Block", "Size");
        let label = if !label_raw.is_empty() {
            label_raw
        } else if is_loop {
            let raw = prop(o, "Loop", "BackingFile")
                .and_then(|v| <Vec<u8>>::try_from(v.try_clone().ok()?).ok())
                .unwrap_or_default();
            Path::new(&byte_string(&raw)).file_name().map_or_else(
                || crate::tr!("label-disk-image"),
                |n| n.to_string_lossy().into_owned(),
            )
        } else if size > 0 {
            crate::tr!("label-sized-volume", size = format_size(size))
        } else {
            crate::tr!("label-volume")
        };
        let model = drive
            .map(|d| {
                format!(
                    "{} {}",
                    text(d, "Drive", "Vendor"),
                    text(d, "Drive", "Model")
                )
                .trim()
                .to_owned()
            })
            .unwrap_or_default();
        let mut item = Item::new(block_id(path), kind, label);
        item.detail = match (size > 0, model.is_empty()) {
            (true, false) => format!("{} · {model}", format_size(size)),
            (true, true) => format_size(size),
            (false, _) => model,
        };
        let mount = points
            .iter()
            .find(|p| is_media_mount(p))
            .or_else(|| points.first())
            .cloned();
        item.state = if encrypted && cleartext.is_none() {
            State::Locked
        } else if mount.is_some() {
            State::Mounted
        } else {
            State::Unmounted
        };
        item.can_mount = mount.is_none() && item.state != State::Locked;
        item.can_unmount = mount.is_some();
        item.mount_path = mount;
        item.read_only = flag(o, "Block", "ReadOnly");
        let fs_type = text(o, "Block", "IdType");
        item.filesystem = (!fs_type.is_empty()).then_some(fs_type);
        // Only drives that can be unplugged are formatted from here; internal
        // disks belong to Settings, behind an administrator.
        item.can_format = removable && !is_loop && !optical && !item.read_only;
        item.size = (size > 0).then_some(size);
        item.device = device(o);
        if let (Some(d), Some(dp)) = (drive, drive_path.as_ref()) {
            item.can_eject = flag(d, "Drive", "Ejectable");
            item.can_power_off = flag(d, "Drive", "CanPowerOff") && removable;
            item.drive = Some(format!("drive:{}", basename(dp)));
            drives_with_items.insert(dp.clone());
        }
        out.push(item);
    }
    // Empty optical drives and card readers show "No media" with Eject.
    for &(path, o) in &sorted {
        if !has(o, "Drive") || drives_with_items.contains(path) {
            continue;
        }
        let compat = prop(o, "Drive", "MediaCompatibility")
            .and_then(|v| <Vec<String>>::try_from(v.try_clone().ok()?).ok())
            .unwrap_or_default();
        let optical = compat.iter().any(|m| m.starts_with("optical"));
        if !optical || flag(o, "Drive", "MediaAvailable") {
            continue;
        }
        let label = format!(
            "{} {}",
            text(o, "Drive", "Vendor"),
            text(o, "Drive", "Model")
        )
        .trim()
        .to_owned();
        let mut item = Item::new(
            format!("drive:{}", basename(path)),
            Kind::Optical,
            if label.is_empty() {
                crate::tr!("label-optical-drive")
            } else {
                label
            },
        );
        item.state = State::NoMedia;
        item.can_mount = false;
        item.can_eject = flag(o, "Drive", "Ejectable");
        item.drive = Some(format!("drive:{}", basename(path)));
        out.push(item);
    }
    out.sort_by(|a, b| (a.kind as u8, &a.label, &a.id).cmp(&(b.kind as u8, &b.label, &b.id)));
    out
}

/// A connection to UDisks2.
#[derive(Clone)]
pub struct Udisks {
    connection: zbus::Connection,
}

fn map_error(error: zbus::Error) -> Error {
    if let zbus::Error::MethodError(name, message, _) = &error {
        let message = message.clone().unwrap_or_default();
        let name = name.as_str();
        return if name.ends_with("DeviceBusy") {
            Error::Busy(crate::tr!("error-drive-busy"))
        } else if name.contains("NotAuthorized") {
            Error::NotAuthorized(crate::tr!("error-drive-not-allowed"))
        } else if name.ends_with("Cancelled") {
            Error::Failed(crate::tr!("error-cancelled"))
        } else if name.ends_with("ServiceUnknown") {
            Error::Unsupported(crate::tr!("error-udisks-missing"))
        } else if message.contains("passphrase")
            || message.contains("No key available")
            || message.contains("Operation not permitted")
        {
            Error::AuthFailed(crate::tr!("error-passphrase-refused"))
        } else {
            Error::Failed(message)
        };
    }
    Error::Failed(error.to_string())
}

impl Udisks {
    /// Use `connection` (the system bus).
    #[must_use]
    pub fn new(connection: zbus::Connection) -> Self {
        Self { connection }
    }

    /// All objects.
    ///
    /// # Errors
    /// When UDisks2 does not answer.
    pub async fn objects(&self) -> Result<Objects> {
        let proxy = zbus::fdo::ObjectManagerProxy::builder(&self.connection)
            .destination(UDISKS)
            .path(ROOT)
            .build()
            .await?;
        let objects = tokio::time::timeout(Duration::from_secs(25), proxy.get_managed_objects())
            .await
            .map_err(|_| Error::Timeout(crate::tr!("error-udisks-timeout")))?
            .map_err(|e| map_error(e.into()))?;
        Ok(objects
            .into_iter()
            .map(|(path, ifaces)| {
                let ifaces = ifaces
                    .into_iter()
                    .map(|(name, props)| (name.to_string(), props))
                    .collect();
                (path, ifaces)
            })
            .collect())
    }

    async fn call<B, R>(&self, path: &str, iface: &str, method: &str, body: &B) -> Result<R>
    where
        B: serde::Serialize + zbus::DynamicType,
        R: for<'d> serde::Deserialize<'d> + zbus::Type,
    {
        let proxy = zbus::Proxy::new(
            &self.connection,
            UDISKS,
            path.to_owned(),
            format!("org.freedesktop.UDisks2.{iface}"),
        )
        .await?;
        tokio::time::timeout(ACTION_TIMEOUT, proxy.call::<_, B, R>(method, body))
            .await
            .map_err(|_| Error::Timeout(crate::tr!("error-drive-timeout")))?
            .map_err(map_error)
    }

    fn options() -> HashMap<&'static str, Variant<'static>> {
        HashMap::from([("auth.no_user_interaction", Variant::from(false))])
    }

    async fn call_long<B, R>(&self, path: &str, iface: &str, method: &str, body: &B) -> Result<R>
    where
        B: serde::Serialize + zbus::DynamicType,
        R: for<'d> serde::Deserialize<'d> + zbus::Type,
    {
        let proxy = zbus::Proxy::new(
            &self.connection,
            UDISKS,
            path.to_owned(),
            format!("org.freedesktop.UDisks2.{iface}"),
        )
        .await?;
        tokio::time::timeout(FORMAT_TIMEOUT, proxy.call::<_, B, R>(method, body))
            .await
            .map_err(|_| Error::Timeout(crate::tr!("error-drive-timeout")))?
            .map_err(map_error)
    }

    fn format_options(fs: &str, label: &str) -> HashMap<&'static str, Variant<'static>> {
        // No "tear-down": it also edits fstab/crypttab, which needs an
        // administrator; the caller closes what is open first.
        let mut options = Self::options();
        options.insert("update-partition-type", Variant::from(true));
        if !label.is_empty() {
            let label = if fs == "vfat" {
                label.to_ascii_uppercase()
            } else {
                label.to_owned()
            };
            options.insert("label", Variant::from(label));
        }
        if fs == "ext4" {
            // The new file system's top folder belongs to the user.
            options.insert("take-ownership", Variant::from(true));
        }
        options
    }

    /// Quick-format the block object `path` (a partition, or a drive
    /// without a partition table) as `fs`.
    ///
    /// # Errors
    /// UDisks2 refusals.
    pub async fn format_volume(&self, path: &str, fs: &str, label: &str) -> Result<()> {
        self.call_long::<_, ()>(
            path,
            "Block",
            "Format",
            &(fs, Self::format_options(fs, label)),
        )
        .await
    }

    /// Erase the whole drive behind block object `disk`: a new MBR partition
    /// table (readable by cameras, TVs and older computers) with one
    /// partition formatted as `fs`. Returns the new partition's object path.
    ///
    /// # Errors
    /// UDisks2 refusals.
    pub async fn format_drive(&self, disk: &str, fs: &str, label: &str) -> Result<String> {
        self.call_long::<_, ()>(disk, "Block", "Format", &("dos", Self::options()))
            .await?;
        let kind = FORMATS
            .iter()
            .find(|(name, _)| *name == fs)
            .map_or("0x83", |(_, kind)| *kind);
        let created: OwnedObjectPath = self
            .call_long(
                disk,
                "PartitionTable",
                "CreatePartitionAndFormat",
                &(
                    1024u64 * 1024,
                    0u64,
                    kind,
                    "",
                    Self::options(),
                    fs,
                    Self::format_options(fs, label),
                ),
            )
            .await?;
        Ok(created.to_string())
    }

    /// Mount the file system at block object `path`.
    ///
    /// # Errors
    /// UDisks2 failures, mapped.
    pub async fn mount(&self, path: &str) -> Result<PathBuf> {
        match self
            .call::<_, String>(path, "Filesystem", "Mount", &(Self::options(),))
            .await
        {
            Ok(point) => Ok(PathBuf::from(point)),
            Err(Error::Failed(message)) if message.contains("already mounted") => {
                let objects = self.objects().await?;
                let o = objects
                    .iter()
                    .find(|(p, _)| p.as_str() == path)
                    .map(|(_, o)| o);
                o.and_then(|o| mount_points(o).into_iter().next())
                    .ok_or(Error::Failed(message))
            }
            Err(error) => Err(error),
        }
    }

    /// Unmount the file system at block object `path`.
    ///
    /// # Errors
    /// UDisks2 failures, mapped.
    pub async fn unmount(&self, path: &str, force: bool) -> Result<()> {
        let mut options = Self::options();
        options.insert("force", Variant::from(force));
        match self
            .call::<_, ()>(path, "Filesystem", "Unmount", &(options,))
            .await
        {
            Err(Error::Failed(message)) if message.contains("not mounted") => Ok(()),
            other => other,
        }
    }

    /// Unlock the encrypted block `path`; returns the cleartext object path.
    ///
    /// # Errors
    /// [`Error::AuthFailed`] for a wrong passphrase, other failures mapped.
    pub async fn unlock(&self, path: &str, passphrase: &crate::secret::Secret) -> Result<String> {
        let text = passphrase.as_text().map_err(Error::Invalid)?.to_owned();
        let text = zeroize::Zeroizing::new(text);
        let cleartext: OwnedObjectPath = self
            .call(
                path,
                "Encrypted",
                "Unlock",
                &(text.as_str(), Self::options()),
            )
            .await?;
        Ok(cleartext.to_string())
    }

    /// Lock the encrypted block `path`.
    ///
    /// # Errors
    /// UDisks2 failures, mapped.
    pub async fn lock(&self, path: &str) -> Result<()> {
        self.call::<_, ()>(path, "Encrypted", "Lock", &(Self::options(),))
            .await
    }

    /// Eject the drive `path`.
    ///
    /// # Errors
    /// UDisks2 failures, mapped.
    pub async fn eject(&self, path: &str) -> Result<()> {
        self.call::<_, ()>(path, "Drive", "Eject", &(Self::options(),))
            .await
    }

    /// Power off the drive `path`.
    ///
    /// # Errors
    /// UDisks2 failures, mapped.
    pub async fn power_off(&self, path: &str) -> Result<()> {
        self.call::<_, ()>(path, "Drive", "PowerOff", &(Self::options(),))
            .await
    }

    /// Attach a disk image read-only; returns the loop block object path.
    ///
    /// # Errors
    /// UDisks2 failures, mapped.
    pub async fn loop_setup(&self, image: std::os::fd::OwnedFd) -> Result<String> {
        let mut options = Self::options();
        options.insert("read-only", Variant::from(true));
        let fd = zbus::Fd::from(image);
        let block: OwnedObjectPath = self
            .call(
                &format!("{ROOT}/Manager"),
                "Manager",
                "LoopSetup",
                &(fd, options),
            )
            .await?;
        Ok(block.to_string())
    }

    /// Detach a loop device.
    ///
    /// # Errors
    /// UDisks2 failures, mapped.
    pub async fn loop_delete(&self, path: &str) -> Result<()> {
        self.call::<_, ()>(path, "Loop", "Delete", &(Self::options(),))
            .await
    }

    /// Wait for any UDisks2 signal, yielding after each burst.
    ///
    /// # Errors
    /// When the signal subscription fails.
    pub async fn changes(&self) -> Result<impl futures_util::Stream<Item = ()> + use<>> {
        let rule = zbus::MatchRule::builder()
            .msg_type(zbus::message::Type::Signal)
            .path_namespace(ROOT)
            .build()?;
        let stream = zbus::MessageStream::for_match_rule(
            rule,
            &self.connection,
            std::num::NonZeroUsize::new(256),
        )
        .await?;
        let owner = zbus::MatchRule::builder()
            .msg_type(zbus::message::Type::Signal)
            .interface("org.freedesktop.DBus")
            .member("NameOwnerChanged")
            .arg(0, UDISKS)
            .build()?;
        let owner_stream = zbus::MessageStream::for_match_rule(
            owner,
            &self.connection,
            std::num::NonZeroUsize::new(16),
        )
        .await?;
        Ok(futures_util::stream::select(stream, owner_stream).map(|_| ()))
    }
}

/// The block object of the whole disk behind drive object `drive` (the one
/// that is not a partition).
#[must_use]
pub fn whole_disk(objects: &Objects, drive: &str) -> Option<String> {
    let mut found: Vec<&OwnedObjectPath> = objects
        .iter()
        .filter(|(_, o)| {
            has(o, "Block")
                && !has(o, "Partition")
                && object(o, "Block", "Drive").is_some_and(|d| d.as_str() == drive)
        })
        .map(|(path, _)| path)
        .collect();
    found.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    found.first().map(ToString::to_string)
}

/// Object path of an item identity (`block:sdb1` or `drive:Name`).
#[must_use]
pub fn object_path(id: &str) -> Option<String> {
    if let Some(name) = id.strip_prefix("block:") {
        return (!name.contains('/')).then(|| format!("{ROOT}/block_devices/{name}"));
    }
    id.strip_prefix("drive:")
        .filter(|n| !n.contains('/'))
        .map(|name| format!("{ROOT}/drives/{name}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obj(entries: &[(&str, &[(&str, Variant<'_>)])]) -> Interfaces {
        entries
            .iter()
            .map(|(iface, props)| {
                (
                    format!("org.freedesktop.UDisks2.{iface}"),
                    props
                        .iter()
                        .map(|(k, v)| {
                            (
                                (*k).to_owned(),
                                OwnedVariant::try_from(v.try_clone().unwrap()).unwrap(),
                            )
                        })
                        .collect(),
                )
            })
            .collect()
    }

    fn path(p: &str) -> OwnedObjectPath {
        OwnedObjectPath::try_from(p).unwrap()
    }

    fn points(list: &[&str]) -> Variant<'static> {
        Variant::from(
            list.iter()
                .map(|p| {
                    let mut b = p.as_bytes().to_vec();
                    b.push(0);
                    b
                })
                .collect::<Vec<_>>(),
        )
    }

    #[test]
    fn drives_are_presented_and_system_volumes_hidden() {
        let usb_drive = path("/org/freedesktop/UDisks2/drives/Stick");
        let sys_drive = path("/org/freedesktop/UDisks2/drives/Internal");
        let mut objects: Objects = HashMap::new();
        objects.insert(
            usb_drive.clone(),
            obj(&[(
                "Drive",
                &[
                    ("ConnectionBus", Variant::from("usb")),
                    ("Removable", Variant::from(true)),
                    ("CanPowerOff", Variant::from(true)),
                    ("Vendor", Variant::from("ACME")),
                    ("Model", Variant::from("Stick")),
                ],
            )]),
        );
        objects.insert(
            sys_drive.clone(),
            obj(&[(
                "Drive",
                &[
                    ("ConnectionBus", Variant::from("")),
                    ("Removable", Variant::from(false)),
                ],
            )]),
        );
        let block = |drive: &OwnedObjectPath,
                     label: &str,
                     mounts: &[&str],
                     extra: &[(&str, &[(&str, Variant<'static>)])]| {
            let mut o = obj(&[
                (
                    "Block",
                    &[
                        ("Drive", Variant::from(drive.clone())),
                        ("IdLabel", Variant::from(label.to_owned())),
                        ("Size", Variant::from(16_000_000_000u64)),
                        ("CryptoBackingDevice", Variant::from(path("/"))),
                    ],
                ),
                ("Filesystem", &[("MountPoints", points(mounts))]),
            ]);
            o.extend(obj(extra));
            o
        };
        objects.insert(
            path("/org/freedesktop/UDisks2/block_devices/sdb1"),
            block(&usb_drive, "PHOTOS", &["/run/media/alice/PHOTOS"], &[]),
        );
        objects.insert(
            path("/org/freedesktop/UDisks2/block_devices/sda2"),
            block(&sys_drive, "", &["/"], &[]),
        );
        objects.insert(
            path("/org/freedesktop/UDisks2/block_devices/sda3"),
            block(&sys_drive, "Windows", &[], &[]),
        );
        objects.insert(
            path("/org/freedesktop/UDisks2/block_devices/sda1"),
            block(
                &sys_drive,
                "",
                &[],
                &[(
                    "Partition",
                    &[(
                        "Type",
                        Variant::from("C12A7328-F81F-11D2-BA4B-00A0C93EC93B"),
                    )],
                )],
            ),
        );
        objects.insert(
            path("/org/freedesktop/UDisks2/block_devices/sda4"),
            block(&sys_drive, "ENZIMOS_ROOT", &[], &[]),
        );
        let mut locked = obj(&[
            (
                "Block",
                &[
                    ("Drive", Variant::from(usb_drive)),
                    ("Size", Variant::from(1_000u64)),
                    ("CryptoBackingDevice", Variant::from(path("/"))),
                ],
            ),
            (
                "Encrypted",
                &[("CleartextDevice", Variant::from(path("/")))],
            ),
        ]);
        locked.extend(obj(&[("Partition", &[("Type", Variant::from("0x83"))])]));
        objects.insert(path("/org/freedesktop/UDisks2/block_devices/sdb2"), locked);

        let items = items(&objects, 1000);
        let ids: Vec<&str> = items.iter().map(|i| i.id.as_str()).collect();
        assert!(
            !ids.contains(&"block:sda2"),
            "the root file system is never offered"
        );
        assert!(!ids.contains(&"block:sda1"), "EFI system partition hidden");
        assert!(!ids.contains(&"block:sda4"), "enzimOS's own volumes hidden");
        let windows = items
            .iter()
            .find(|i| i.id == "block:sda3")
            .expect("unmounted internal volume offered");
        assert_eq!(
            (windows.kind, windows.can_power_off),
            (Kind::Disk, false),
            "internal disk"
        );
        let usb = items
            .iter()
            .find(|i| i.id == "block:sdb1")
            .expect("USB volume");
        assert_eq!(
            (
                usb.kind,
                &usb.state,
                usb.mount_path.as_deref(),
                usb.can_power_off,
                usb.drive.as_deref()
            ),
            (
                Kind::Usb,
                &State::Mounted,
                Some(Path::new("/run/media/alice/PHOTOS")),
                true,
                Some("drive:Stick")
            ),
            "mounted USB stick"
        );
        let crypt = items
            .iter()
            .find(|i| i.id == "block:sdb2")
            .expect("locked volume");
        assert_eq!(
            (&crypt.state, crypt.can_mount),
            (&State::Locked, false),
            "locked volumes need Unlock"
        );
        assert_eq!(
            object_path("block:sdb1").as_deref(),
            Some("/org/freedesktop/UDisks2/block_devices/sdb1"),
            "id maps back"
        );
        assert_eq!(object_path("block:../x"), None, "ids cannot escape");
    }
}
