//! Mount points below `/run/media/<user>`.
//!
//! The per-user directory is owned by root with mode 0700 and a POSIX ACL
//! granting only that user read and search access, exactly as UDisks2 sets it
//! up, so the user can open mounts but cannot rename or replace a mount point
//! between its creation and the mount. Every operation goes through directory
//! descriptors opened without following symbolic links.

use rustix::fd::{AsFd, OwnedFd};
use rustix::fs::{AtFlags, Mode, OFlags};
use std::path::{Path, PathBuf};

/// Default media root.
pub const MEDIA_ROOT: &str = "/run/media";

/// The media root, overridable for tests.
#[must_use]
pub fn media_root() -> PathBuf {
    std::env::var_os("ENZIMOS_MOUNT_MEDIA_ROOT")
        .map_or_else(|| PathBuf::from(MEDIA_ROOT), PathBuf::from)
}

const ACL_USER_OBJ: u16 = 0x01;
const ACL_USER: u16 = 0x02;
const ACL_GROUP_OBJ: u16 = 0x04;
const ACL_MASK: u16 = 0x10;
const ACL_OTHER: u16 = 0x20;
const ACL_UNDEFINED_ID: u32 = u32::MAX;

/// The `system.posix_acl_access` value: owner rwx, `uid` r-x, nobody else.
#[must_use]
pub fn user_read_acl(uid: u32) -> Vec<u8> {
    let entries = [
        (ACL_USER_OBJ, 7u16, ACL_UNDEFINED_ID),
        (ACL_USER, 5, uid),
        (ACL_GROUP_OBJ, 0, ACL_UNDEFINED_ID),
        (ACL_MASK, 5, ACL_UNDEFINED_ID),
        (ACL_OTHER, 0, ACL_UNDEFINED_ID),
    ];
    let mut out = 2u32.to_le_bytes().to_vec();
    for (tag, perm, id) in entries {
        out.extend_from_slice(&tag.to_le_bytes());
        out.extend_from_slice(&perm.to_le_bytes());
        out.extend_from_slice(&id.to_le_bytes());
    }
    out
}

fn open_dir_at(dir: impl AsFd, name: &str) -> rustix::io::Result<OwnedFd> {
    rustix::fs::openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
}

fn require_root_dir(fd: impl AsFd, what: &Path) -> Result<(), String> {
    let stat = rustix::fs::fstat(fd).map_err(|e| format!("{}: {e}", what.display()))?;
    if stat.st_uid != 0 {
        return Err(format!(
            "{} is not owned by root; refusing to use it",
            what.display()
        ));
    }
    Ok(())
}

/// Open (creating if needed) the root-owned media directory for `user`.
///
/// # Errors
/// A sentence when the directory cannot be created or is not root-owned.
pub fn user_dir(user: &str, uid: u32) -> Result<(OwnedFd, PathBuf), String> {
    if !crate::uri::valid_name(user, 64) || user.contains(' ') || user == "." || user == ".." {
        return Err(crate::tr!("error-user-folder"));
    }
    let root_path = media_root();
    std::fs::create_dir_all(&root_path).map_err(|e| format!("{}: {e}", root_path.display()))?;
    let root = rustix::fs::open(
        &root_path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| format!("{}: {e}", root_path.display()))?;
    let path = root_path.join(user);
    match rustix::fs::mkdirat(&root, user, Mode::from_raw_mode(0o700)) {
        Ok(()) | Err(rustix::io::Errno::EXIST) => {}
        Err(e) => return Err(format!("{}: {e}", path.display())),
    }
    let dir = open_dir_at(&root, user).map_err(|e| format!("{}: {e}", path.display()))?;
    if rustix::process::geteuid().is_root() {
        require_root_dir(&dir, &path)?;
        rustix::fs::fchmod(&dir, Mode::from_raw_mode(0o700)).map_err(|e| e.to_string())?;
        if rustix::fs::fsetxattr(
            &dir,
            "system.posix_acl_access",
            &user_read_acl(uid),
            rustix::fs::XattrFlags::empty(),
        )
        .is_err()
        {
            // No ACL support: let the user traverse to known names only.
            rustix::fs::fchmod(&dir, Mode::from_raw_mode(0o711)).map_err(|e| e.to_string())?;
        }
    }
    Ok((dir, path))
}

/// Create a fresh mount point named from `label` in `dir`.
///
/// `owner` makes it owned by that user (FUSE mounts are made by the user);
/// otherwise it stays root-owned for a kernel mount.
///
/// # Errors
/// A sentence when no directory could be created.
pub fn create(
    dir: impl AsFd,
    dir_path: &Path,
    label: &str,
    owner: Option<(u32, u32)>,
) -> Result<PathBuf, String> {
    let dir = dir.as_fd();
    let base = crate::names::component(label, "Network");
    for _ in 0..8 {
        let name = crate::names::unique(&base, |candidate| {
            rustix::fs::statat(dir, candidate, AtFlags::SYMLINK_NOFOLLOW).is_ok()
        });
        match rustix::fs::mkdirat(dir, name.as_str(), Mode::from_raw_mode(0o700)) {
            Ok(()) => {
                if let Some((uid, gid)) = owner {
                    let fd = open_dir_at(dir, &name).map_err(|e| e.to_string())?;
                    rustix::fs::fchown(
                        &fd,
                        Some(rustix::process::Uid::from_raw(uid)),
                        Some(rustix::process::Gid::from_raw(gid)),
                    )
                    .map_err(|e| e.to_string())?;
                }
                return Ok(dir_path.join(name));
            }
            Err(rustix::io::Errno::EXIST) => {}
            Err(e) => return Err(crate::tr!("error-mount-folder", error = e.to_string())),
        }
    }
    Err(crate::tr!("error-mount-folder-name"))
}

/// Remove an empty, unmounted mount point `name` from `dir`.
///
/// # Errors
/// When it is still a mount or not empty.
pub fn remove(dir: impl AsFd, name: &str) -> Result<(), String> {
    rustix::fs::unlinkat(dir, name, AtFlags::REMOVEDIR).map_err(|e| e.to_string())
}

/// Split `path` into the user directory it must live in and its final name,
/// refusing anything else.
#[must_use]
pub fn split_owned(path: &Path, user: &str) -> Option<String> {
    let parent = media_root().join(user);
    if path.parent()? != parent {
        return None;
    }
    let name = path.file_name()?.to_str()?;
    (crate::names::component(name, "") == name).then(|| name.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acl_grants_only_the_owner_user_read_and_search() {
        let acl = user_read_acl(1000);
        assert_eq!(acl.len(), 4 + 5 * 8, "header plus five entries");
        assert_eq!(&acl[..4], &2u32.to_le_bytes(), "xattr version 2");
        let user_entry = &acl[12..20];
        assert_eq!(
            user_entry,
            [2, 0, 5, 0, 0xe8, 0x03, 0, 0],
            "ACL_USER 1000 r-x"
        );
        let other = &acl[36..44];
        assert_eq!(&other[..4], &[0x20, 0, 0, 0], "others get nothing");

        let tmp = tempfile::tempdir().unwrap();
        let dir = rustix::fs::open(
            tmp.path(),
            OFlags::RDONLY | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .unwrap();
        let first = create(&dir, tmp.path(), "../Share", None).unwrap();
        let second = create(&dir, tmp.path(), "../Share", None).unwrap();
        assert_eq!(
            first,
            tmp.path().join("-Share"),
            "label sanitized into one component"
        );
        assert_eq!(
            second,
            tmp.path().join("-Share (2)"),
            "collision gets a suffix"
        );
        std::os::unix::fs::symlink("/etc", tmp.path().join("link")).unwrap();
        assert_eq!(
            create(&dir, tmp.path(), "link", None).unwrap(),
            tmp.path().join("link (2)"),
            "an existing symlink is never reused"
        );
    }
}
