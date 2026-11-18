//! Network shares mounted at startup, before anyone logs in.
//!
//! A user marks a saved SMB or NFS location "mount at startup" and an
//! administrator approves it once. The entry is stored root-only in
//! `/var/lib/enzimos-mount/boot`. Its password is encrypted at rest with
//! `systemd-creds` (bound to this machine's credential key, and to the TPM when
//! one is present) under a name tied to the entry, so a copied file cannot be
//! decrypted under another name or elsewhere.
//!
//! `enzimos-mount-boot.service` runs [`run`] in the background. It is ordered
//! after the network stack but nothing waits for it, so a server that is off
//! never delays or fails startup. It retries with a growing pause (5 s doubling
//! to 5 min) until every entry is mounted, then exits.
//! `enzimos-mount-cleanup.service` stops before the network does at shutdown
//! and detaches every kernel network mount ([`unmount_all`]), so shutdown never
//! waits on a share whose server is gone.

use super::{Caller, Service, nfs_params, smb_params, string};
use crate::error::{Error, Result};
use crate::secret::Secret;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;
use zbus::OwnedVariant;

/// Longest pause between attempts.
pub const MAX_PAUSE: Duration = Duration::from_secs(300);
/// Most startup shares per user.
pub const MAX_PER_USER: usize = 32;

/// Where entries live.
#[must_use]
pub fn dir() -> PathBuf {
    std::env::var_os("ENZIMOS_MOUNT_BOOT_DIR").map_or_else(
        || PathBuf::from("/var/lib/enzimos-mount/boot"),
        PathBuf::from,
    )
}

/// A location identity as the session service makes them (`net-` + 16 hex).
#[must_use]
pub fn valid_id(id: &str) -> bool {
    id.strip_prefix("net-")
        .is_some_and(|hex| hex.len() == 16 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// One share to mount at startup.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootEntry {
    /// The owner's location identity.
    pub id: String,
    /// Owner.
    pub uid: u32,
    /// `smb` or `nfs`.
    pub protocol: String,
    /// The validated mount parameters, as the D-Bus methods take them.
    pub host: String,
    /// Port.
    pub port: Option<u16>,
    /// SMB share.
    #[serde(default)]
    pub share: String,
    /// Sub-path or NFS export.
    #[serde(default)]
    pub path: String,
    /// SMB user; empty for guest.
    #[serde(default)]
    pub username: String,
    /// SMB domain.
    #[serde(default)]
    pub domain: Option<String>,
    /// SMB dialect.
    #[serde(default)]
    pub version: Option<String>,
    /// Folder name.
    pub label: String,
}

impl BootEntry {
    /// Validate a `SetBootMount` request.
    ///
    /// # Errors
    /// [`Error::Invalid`] for a bad field or protocol.
    pub fn from_params(id: &str, uid: u32, params: &HashMap<String, OwnedVariant>) -> Result<Self> {
        match string(params, "protocol").as_deref() {
            Some("smb") => {
                let p = smb_params(params)?;
                Ok(Self {
                    id: id.to_owned(),
                    uid,
                    protocol: "smb".to_owned(),
                    host: p.host,
                    port: p.port,
                    share: p.share,
                    path: p.path,
                    username: p.username,
                    domain: p.domain,
                    version: p.version,
                    label: p.label,
                })
            }
            Some("nfs") => {
                let p = nfs_params(params)?;
                Ok(Self {
                    id: id.to_owned(),
                    uid,
                    protocol: "nfs".to_owned(),
                    host: p.host,
                    port: p.port,
                    share: String::new(),
                    path: p.path,
                    username: String::new(),
                    domain: None,
                    version: None,
                    label: p.label,
                })
            }
            _ => Err(Error::Invalid(crate::tr!("error-startup-protocol"))),
        }
    }

    /// Server and share (or export) for the approval dialog.
    #[must_use]
    pub fn describe(&self) -> (String, String) {
        let share = if self.protocol == "nfs" {
            format!("/{}", self.path)
        } else {
            self.share.clone()
        };
        (self.host.clone(), share)
    }

    fn stem(&self) -> String {
        format!("{}-{}", self.uid, self.id)
    }

    fn credential_name(&self) -> String {
        format!("enzimos-mount-{}", self.stem())
    }

    /// The same mount as a session would make: identity is server, share and path.
    fn source(&self) -> String {
        if self.protocol == "nfs" {
            if self.host.contains(':') {
                format!("[{}]:/{}", self.host, self.path)
            } else {
                format!("{}:/{}", self.host, self.path)
            }
        } else if self.path.is_empty() {
            format!("//{}/{}", self.host, self.share)
        } else {
            format!("//{}/{}/{}", self.host, self.share, self.path)
        }
    }
}

fn private_dir() -> Result<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let dir = dir();
    std::fs::create_dir_all(&dir).map_err(|e| Error::Failed(format!("{}: {e}", dir.display())))?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| Error::Failed(e.to_string()))?;
    Ok(dir)
}

/// All stored entries.
#[must_use]
pub fn list() -> Vec<BootEntry> {
    let Ok(entries) = std::fs::read_dir(dir()) else {
        return Vec::new();
    };
    let mut out: Vec<BootEntry> = entries
        .flatten()
        .filter_map(|file| {
            let name = file.file_name().to_string_lossy().into_owned();
            let stem = name.strip_suffix(".json")?.to_owned();
            let entry =
                serde_json::from_slice::<BootEntry>(&std::fs::read(file.path()).ok()?).ok()?;
            // The file name must be the entry's own: owner and identity.
            (valid_id(&entry.id) && entry.stem() == stem).then_some(entry)
        })
        .collect();
    out.sort_by(|a, b| (a.uid, &a.id).cmp(&(b.uid, &b.id)));
    out
}

/// Store `entry` and its encrypted password (empty for guest or NFS).
///
/// # Errors
/// When `systemd-creds` cannot encrypt or the files cannot be written.
pub async fn store(entry: &BootEntry, password: &Secret) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let dir = private_dir()?;
    if list()
        .iter()
        .filter(|e| e.uid == entry.uid && e.id != entry.id)
        .count()
        >= MAX_PER_USER
    {
        return Err(Error::Invalid(crate::tr!("error-startup-too-many")));
    }
    let credential = dir.join(format!("{}.cred", entry.stem()));
    if password.is_empty() {
        let _ = std::fs::remove_file(&credential);
    } else {
        let tool = crate::process::helper("systemd-creds").ok_or_else(|| {
            Error::Unsupported("systemd-creds is needed to store the password safely".to_owned())
        })?;
        let tmp = dir.join(format!(".{}.cred.tmp", entry.stem()));
        let mut spec = crate::process::Spec::new(tool, Duration::from_secs(20))
            .arg("encrypt")
            .arg(format!("--name={}", entry.credential_name()))
            .arg("-")
            .arg(&tmp);
        spec.stdin = Some(zeroize::Zeroizing::new(password.expose().to_vec()));
        let output = crate::process::run(spec)
            .await
            .map_err(|e| Error::Failed(e.to_string()))?;
        if !output.success() {
            let _ = std::fs::remove_file(&tmp);
            return Err(Error::Failed(crate::tr!(
                "error-startup-store",
                detail = output.stderr.trim()
            )));
        }
        std::fs::rename(&tmp, &credential).map_err(|e| Error::Failed(e.to_string()))?;
    }
    let tmp = dir.join(format!(".{}.json.tmp", entry.stem()));
    let bytes = serde_json::to_vec_pretty(entry).map_err(|e| Error::Failed(e.to_string()))?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| Error::Failed(e.to_string()))?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| Error::Failed(e.to_string()))?;
    std::fs::rename(&tmp, dir.join(format!("{}.json", entry.stem())))
        .map_err(|e| Error::Failed(e.to_string()))?;
    crate::log!(
        info,
        "uid {} set {} to mount at startup",
        entry.uid,
        entry.source()
    );
    Ok(())
}

/// Remove a user's entry and its credential.
pub fn remove(uid: u32, id: &str) {
    if !valid_id(id) {
        return;
    }
    let dir = dir();
    let _ = std::fs::remove_file(dir.join(format!("{uid}-{id}.json")));
    let _ = std::fs::remove_file(dir.join(format!("{uid}-{id}.cred")));
}

async fn password(entry: &BootEntry) -> Result<Secret> {
    let credential = dir().join(format!("{}.cred", entry.stem()));
    if !credential.exists() {
        return Ok(Secret::default());
    }
    let tool = crate::process::helper("systemd-creds")
        .ok_or_else(|| Error::Unsupported("systemd-creds is missing".to_owned()))?;
    let spec = crate::process::Spec::new(tool, Duration::from_secs(20))
        .arg("decrypt")
        .arg(format!("--name={}", entry.credential_name()))
        .arg(&credential)
        .arg("-");
    let output = crate::process::run(spec)
        .await
        .map_err(|e| Error::Failed(e.to_string()))?;
    let mut text = zeroize::Zeroizing::new(output.stdout);
    if output.code != Some(0) {
        return Err(Error::Failed(crate::tr!("error-startup-decrypt")));
    }
    Ok(Secret::new(std::mem::take(&mut *text).into_bytes()))
}

async fn mount(service: &Service, entry: &BootEntry) -> Result<PathBuf> {
    let caller = Caller::from_uid(entry.uid)?;
    let mut params: HashMap<String, OwnedVariant> = HashMap::new();
    let mut put = |key: &str, value: &str| {
        if let Ok(v) = OwnedVariant::try_from(zbus::Variant::from(value)) {
            params.insert(key.to_owned(), v);
        }
    };
    put("host", &entry.host);
    put("share", &entry.share);
    put("path", &entry.path);
    put("username", &entry.username);
    put("label", &entry.label);
    if let Some(domain) = &entry.domain {
        put("domain", domain);
    }
    if let Some(version) = &entry.version {
        put("version", version);
    }
    if let Some(port) = entry.port {
        params.insert("port".to_owned(), OwnedVariant::from(port));
    }
    if entry.protocol == "nfs" {
        service
            .do_mount_nfs(&caller, &nfs_params(&params)?, true)
            .await
    } else {
        service
            .do_mount_smb(
                &caller,
                &smb_params(&params)?,
                &password(entry).await?,
                true,
            )
            .await
    }
}

fn mounted(entry: &BootEntry) -> bool {
    let source = entry.source();
    super::load_registry()
        .unwrap_or_default()
        .iter()
        .any(|e| e.uid == entry.uid && e.source == source && !e.pending)
}

/// Mount every stored entry, retrying until all are mounted; never fails.
pub async fn run() {
    let service = Service::new();
    let mut pause = Duration::from_secs(5);
    loop {
        let pending: Vec<BootEntry> = list().into_iter().filter(|e| !mounted(e)).collect();
        if pending.is_empty() {
            crate::log!(info, "all startup shares are mounted");
            return;
        }
        for entry in &pending {
            match mount(&service, entry).await {
                Ok(path) => crate::log!(info, "mounted {} at {}", entry.source(), path.display()),
                Err(error) => crate::log!(
                    info,
                    "{} not mounted yet: {}",
                    entry.source(),
                    error.message()
                ),
            }
        }
        if list().iter().all(mounted) {
            continue;
        }
        tokio::time::sleep(pause).await;
        pause = (pause * 2).min(MAX_PAUSE);
    }
}

/// Detach every kernel network mount the service made (shutdown).
pub async fn unmount_all() {
    let service = Service::new();
    let kernel: Vec<super::Entry> = match super::load_registry() {
        Ok(registry) => registry
            .into_iter()
            .filter(|e| e.kind == super::EntryKind::Kernel)
            .collect(),
        Err(_) => Vec::new(),
    };
    let jobs = kernel.iter().map(|entry| async {
        if service.unmount_path(&entry.path, true).await.is_ok() {
            let _ = std::fs::remove_dir(&entry.path);
        }
    });
    futures_util::future::join_all(jobs).await;
    let _ =
        super::with_registry(|registry| registry.retain(|e| e.kind != super::EntryKind::Kernel));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_entries_are_validated_and_bound_to_their_owner() {
        let mut params: HashMap<String, OwnedVariant> = HashMap::new();
        let put = |params: &mut HashMap<String, OwnedVariant>, k: &str, v: &str| {
            params.insert(
                k.to_owned(),
                OwnedVariant::try_from(zbus::Variant::from(v)).unwrap(),
            );
        };
        put(&mut params, "protocol", "smb");
        put(&mut params, "host", "nas.local");
        put(&mut params, "share", "photos");
        put(&mut params, "username", "alice");
        let entry = BootEntry::from_params("net-0123456789abcdef", 1000, &params).unwrap();
        assert_eq!(
            entry.source(),
            "//nas.local/photos",
            "same identity as a session mount"
        );
        assert_eq!(
            entry.credential_name(),
            "enzimos-mount-1000-net-0123456789abcdef",
            "credential bound to owner and location"
        );
        put(&mut params, "protocol", "sftp");
        assert!(
            BootEntry::from_params("net-0123456789abcdef", 1000, &params).is_err(),
            "only kernel protocols at startup"
        );
        for bad in ["net-../../x", "net-0123", "../etc", "net-0123456789abcdeg"] {
            assert!(!valid_id(bad), "{bad} refused as a file name");
        }
    }
}
