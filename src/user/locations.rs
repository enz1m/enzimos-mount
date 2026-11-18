//! Network locations the user added.
//!
//! Saved locations persist in `$XDG_CONFIG_HOME/enzimos-mount/locations.json`
//! (mode 0600, replaced atomically). They never contain a password: passwords
//! live in the Secret Service, keyed by the location's identity. Unsaved
//! locations exist only for the session.

use crate::uri::NetUri;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Most locations kept.
pub const MAX_LOCATIONS: usize = 200;
/// File format version.
pub const FORMAT_VERSION: u32 = 1;

/// One network location.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Location {
    /// Stable identity, `net-<hex>`.
    pub id: String,
    /// Password-free address.
    pub uri: String,
    /// Display name.
    pub label: String,
    /// Persisted across sessions.
    #[serde(default)]
    pub saved: bool,
    /// Connected automatically at login and after network changes.
    #[serde(default)]
    pub auto_connect: bool,
    /// Mounted at startup by the root service (SMB and NFS).
    #[serde(default)]
    pub mount_at_boot: bool,
    /// SMB dialect override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub smb_version: Option<String>,
}

impl Location {
    /// The parsed address.
    ///
    /// # Errors
    /// When the stored address no longer parses.
    pub fn net_uri(&self) -> Result<NetUri, crate::uri::UriError> {
        NetUri::parse(&self.uri)
    }
}

#[derive(Serialize, Deserialize)]
struct File {
    version: u32,
    locations: Vec<Location>,
}

/// The configuration file path.
#[must_use]
pub fn path() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from("/nonexistent"));
    base.join("enzimos-mount/locations.json")
}

/// Load saved locations; a missing or unreadable file yields none, a newer
/// format is left untouched and yields none.
#[must_use]
pub fn load() -> (Vec<Location>, bool) {
    let Ok(bytes) = std::fs::read(path()) else {
        return (Vec::new(), true);
    };
    match serde_json::from_slice::<File>(&bytes) {
        Ok(file) if file.version <= FORMAT_VERSION => {
            let mut locations: Vec<Location> = file
                .locations
                .into_iter()
                .filter(|l| l.net_uri().is_ok() && l.id.starts_with("net-"))
                .map(|mut l| {
                    l.saved = true;
                    l
                })
                .collect();
            locations.truncate(MAX_LOCATIONS);
            (locations, true)
        }
        _ => {
            crate::log!(
                warn,
                "{} has an unknown format; not changing it",
                path().display()
            );
            (Vec::new(), false)
        }
    }
}

/// Persist the saved subset atomically.
///
/// # Errors
/// I/O failures.
pub fn save(locations: &[Location]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let path = path();
    let dir = path
        .parent()
        .ok_or_else(|| std::io::Error::other("no config directory"))?;
    std::fs::create_dir_all(dir)?;
    let file = File {
        version: FORMAT_VERSION,
        locations: locations
            .iter()
            .filter(|l| l.saved)
            .take(MAX_LOCATIONS)
            .cloned()
            .collect(),
    };
    let bytes = serde_json::to_vec_pretty(&file).map_err(std::io::Error::other)?;
    let tmp = dir.join(format!(".locations.{}.tmp", crate::secret::random_hex(4)));
    let mut out = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    out.write_all(&bytes)?;
    out.sync_all()?;
    drop(out);
    std::fs::rename(&tmp, &path)
}

/// A new identity.
#[must_use]
pub fn new_id() -> String {
    format!("net-{}", crate::secret::random_hex(8))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_saved_password_free_locations_persist_and_newer_files_are_preserved() {
        let home = tempfile::tempdir().unwrap();
        // SAFETY of the test: this test alone touches XDG_CONFIG_HOME.
        temp_env(home.path(), || {
            let saved = Location {
                id: new_id(),
                uri: "smb://alice@nas/photos".to_owned(),
                label: "Photos".to_owned(),
                saved: true,
                auto_connect: true,
                mount_at_boot: false,
                smb_version: None,
            };
            let transient = Location {
                id: new_id(),
                saved: false,
                ..saved.clone()
            };
            save(&[saved.clone(), transient]).unwrap();
            let (loaded, writable) = load();
            assert!(writable, "own format is writable");
            assert_eq!(loaded, vec![saved], "unsaved locations are not persisted");
            let mode = std::fs::metadata(path())
                .map(|m| std::os::unix::fs::PermissionsExt::mode(&m.permissions()))
                .unwrap();
            assert_eq!(mode & 0o777, 0o600, "private file");
            std::fs::write(path(), br#"{"version":99,"locations":[]}"#).unwrap();
            let (loaded, writable) = load();
            assert!(
                loaded.is_empty() && !writable,
                "a newer format is read-only"
            );
        });
    }

    fn temp_env(dir: &std::path::Path, f: impl FnOnce()) {
        let old = std::env::var_os("XDG_CONFIG_HOME");
        // Tests in this crate do not read XDG_CONFIG_HOME concurrently.
        #[allow(unsafe_code, reason = "test-only environment override")]
        // SAFETY: no other test thread reads or writes this variable.
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", dir);
        }
        f();
        #[allow(unsafe_code, reason = "test-only environment override")]
        // SAFETY: as above.
        unsafe {
            match old {
                Some(v) => std::env::set_var("XDG_CONFIG_HOME", v),
                None => std::env::remove_var("XDG_CONFIG_HOME"),
            }
        }
    }
}
