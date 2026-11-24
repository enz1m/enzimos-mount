//! `/proc/self/mountinfo` parsing.

use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
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
pub fn unescape(field: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(field.len());
    let mut i = 0;
    while i < field.len() {
        if field[i] == b'\\'
            && let Some(&[a, b, c]) = field.get(i + 1..i + 4)
            && (b'0'..=b'3').contains(&a)
            && [b, c].iter().all(|d| (b'0'..=b'7').contains(d))
        {
            out.push((a - b'0') * 64 + (b - b'0') * 8 + (c - b'0'));
            i += 4;
        } else {
            out.push(field[i]);
            i += 1;
        }
    }
    out
}

fn parse_line(line: &[u8]) -> Option<MountEntry> {
    let text = |field: &[u8]| String::from_utf8_lossy(field).into_owned();
    let separator = line.windows(3).position(|w| w == b" - ")?;
    let mut l = line[..separator].split(|&b| b == b' ');
    let id = std::str::from_utf8(l.next()?).ok()?.parse().ok()?;
    let _parent = l.next()?;
    let _dev = l.next()?;
    let _root = l.next()?;
    let mount_point = PathBuf::from(OsString::from_vec(unescape(l.next()?)));
    let options = text(l.next()?);
    let mut r = line[separator + 3..].split(|&b| b == b' ');
    let fs_type = text(r.next()?);
    let source = text(&unescape(r.next()?));
    Some(MountEntry {
        id,
        mount_point,
        fs_type,
        source,
        options,
    })
}

/// Parse mountinfo bytes.
///
/// # Errors
/// [`std::io::ErrorKind::InvalidData`] when any line is malformed: a partial
/// table must not pass for the whole one.
pub fn parse(text: &[u8]) -> std::io::Result<Vec<MountEntry>> {
    text.split(|&b| b == b'\n')
        .enumerate()
        .filter(|(_, line)| !line.is_empty())
        .map(|(number, line)| {
            parse_line(line).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("malformed mountinfo line {}", number + 1),
                )
            })
        })
        .collect()
}

/// The current mounts.
///
/// # Errors
/// When `/proc/self/mountinfo` cannot be read or parsed. Callers must not
/// read an error as "nothing mounted".
pub fn current() -> std::io::Result<Vec<MountEntry>> {
    parse(&std::fs::read("/proc/self/mountinfo")?).inspect_err(|error| {
        crate::log!(err, "mount table unreadable: {error}");
    })
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
        let entries = parse(text.as_bytes()).unwrap();
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

    #[test]
    fn non_utf8_mount_points_keep_the_whole_table() {
        use std::os::unix::ffi::OsStrExt;
        let text = b"36 25 0:32 / /run/media/alice/Share rw - cifs //nas/Share rw\n\
                     50 25 0:60 / /run/media/mallory/\xff\xfe\\134x\\011 rw,nosuid - fuse.\xff \xfe rw\n\
                     51 25 0:61 / /run/media/bob/Docs rw - fuse.sshfs bob@host: rw\n";
        let entries = parse(text).unwrap();
        assert_eq!(entries.len(), 3, "a hostile line hides no other mount");
        assert_eq!(
            entries[1].mount_point.as_os_str().as_bytes(),
            b"/run/media/mallory/\xff\xfe\\x\t",
            "raw bytes with escapes undone"
        );
        assert!(at(&entries, Path::new("/run/media/bob/Docs")).is_some());
        assert!(
            parse(b"36 25 0:32 / /run/media/alice/Share rw\n").is_err(),
            "a malformed table is an error, not an empty one"
        );
    }
}
