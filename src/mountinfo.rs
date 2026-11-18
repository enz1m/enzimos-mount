//! `/proc/self/mountinfo` parsing.

use std::path::{Path, PathBuf};

/// One mount.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MountEntry {
    /// Mount ID.
    pub id: u64,
    /// Where it is mounted.
    pub mount_point: PathBuf,
    /// File system type, e.g. `cifs` or `fuse.sshfs`.
    pub fs_type: String,
    /// Mount source, e.g. `//nas/share`.
    pub source: String,
    /// Per-mount options (`ro`, `nosuid`…).
    pub options: String,
}

impl MountEntry {
    /// Mounted read-only.
    #[must_use]
    pub fn read_only(&self) -> bool {
        self.options.split(',').any(|o| o == "ro")
    }
}

/// Undo the kernel's octal escaping of space, tab, newline and backslash.
#[must_use]
pub fn unescape(field: &str) -> String {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\'
            && i + 3 < bytes.len()
            && bytes[i + 1..i + 4]
                .iter()
                .all(|b| (b'0'..=b'7').contains(b))
        {
            let value =
                (bytes[i + 1] - b'0') * 64 + (bytes[i + 2] - b'0') * 8 + (bytes[i + 3] - b'0');
            out.push(value);
            i += 4;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse mountinfo text.
#[must_use]
pub fn parse(text: &str) -> Vec<MountEntry> {
    text.lines()
        .filter_map(|line| {
            let (left, right) = line.split_once(" - ")?;
            let mut l = left.split(' ');
            let id = l.next()?.parse().ok()?;
            let _parent = l.next()?;
            let _dev = l.next()?;
            let _root = l.next()?;
            let mount_point = PathBuf::from(unescape(l.next()?));
            let options = l.next()?.to_owned();
            let mut r = right.split(' ');
            let fs_type = r.next()?.to_owned();
            let source = unescape(r.next()?);
            Some(MountEntry {
                id,
                mount_point,
                fs_type,
                source,
                options,
            })
        })
        .collect()
}

/// The current mounts; an empty list when `/proc` is unreadable.
#[must_use]
pub fn current() -> Vec<MountEntry> {
    std::fs::read_to_string("/proc/self/mountinfo")
        .map(|t| parse(&t))
        .unwrap_or_default()
}

/// The topmost mount exactly at `path`.
#[must_use]
pub fn at(entries: &[MountEntry], path: &Path) -> Option<MountEntry> {
    entries
        .iter()
        .rev()
        .find(|e| e.mount_point == path)
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaped_mount_points_and_sources_parse() {
        let text = "36 25 0:32 / /run/media/alice/My\\040Share rw,nosuid,nodev,relatime shared:1 - cifs //nas/My\\040Share rw,vers=3.1.1\n\
                    40 25 0:50 / /run/media/alice/Phone rw,nosuid,nodev - fuse.aft-mtp-mount aft-mtp-mount ro,user_id=1000\n\
                    41 25 0:51 / /run/media/alice/Phone ro,nosuid - fuse.aft-mtp-mount aft-mtp-mount rw\n";
        let entries = parse(text);
        assert_eq!(entries.len(), 3, "all lines parse");
        assert_eq!(
            entries[0].mount_point,
            Path::new("/run/media/alice/My Share"),
            "octal space"
        );
        assert_eq!(entries[0].source, "//nas/My Share", "source unescaped");
        let top = at(&entries, Path::new("/run/media/alice/Phone")).unwrap();
        assert_eq!(
            (top.id, top.read_only()),
            (41, true),
            "topmost stacked mount wins; per-mount ro"
        );
    }
}
