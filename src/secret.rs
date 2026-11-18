//! Secrets in transit.
//!
//! Passwords never travel as D-Bus strings, command-line arguments or
//! environment variables of long-lived processes. Between processes they move
//! as a sealed anonymous memory file passed as a Unix file descriptor (the same
//! channel the backup enrollment uses); in memory they live in [`Secret`], which
//! is wiped on drop.

use rustix::fd::{AsFd, OwnedFd};
use rustix::fs::{MemfdFlags, SealFlags};
use std::fmt;
use std::io::{Read, Seek, SeekFrom, Write};
use zeroize::Zeroizing;

/// Largest accepted secret in bytes.
pub const MAX_SECRET_BYTES: usize = 4096;

/// A password or passphrase; wiped when dropped, never printed.
#[derive(Clone, Default)]
pub struct Secret(Zeroizing<Vec<u8>>);

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(..)")
    }
}

impl Secret {
    /// Wrap bytes.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// The secret bytes.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// The secret as UTF-8 text, as kernel and helper options require.
    ///
    /// # Errors
    /// When the bytes are not UTF-8 or contain NUL or a line break, which no
    /// mount helper can carry.
    pub fn as_text(&self) -> Result<&str, String> {
        let text =
            std::str::from_utf8(&self.0).map_err(|_| crate::tr!("error-password-not-text"))?;
        if text.contains(['\0', '\n', '\r']) {
            return Err(crate::tr!("error-password-line-break"));
        }
        Ok(text)
    }

    /// Whether there is no secret.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Put `secret` in a sealed memory file ready to pass as a descriptor.
///
/// # Errors
/// System call failures.
pub fn to_memfd(secret: &Secret) -> std::io::Result<OwnedFd> {
    let fd = rustix::fs::memfd_create(
        "enzimos-mount-secret",
        MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
    )?;
    let mut file = std::fs::File::from(fd);
    file.write_all(secret.expose())?;
    file.seek(SeekFrom::Start(0))?;
    rustix::fs::fcntl_add_seals(
        &file,
        SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK | SealFlags::SEAL,
    )?;
    Ok(OwnedFd::from(file))
}

/// Read a secret from a descriptor received over D-Bus.
///
/// Requires a sealed memory file (the sender can no longer change it) of at
/// most [`MAX_SECRET_BYTES`]; reads from offset zero without moving the
/// sender's file position. An empty secret is allowed (guest access).
///
/// # Errors
/// A sentence describing why the descriptor was refused.
pub fn from_fd(fd: impl AsFd) -> Result<Secret, String> {
    let fd = fd.as_fd();
    let seals =
        rustix::fs::fcntl_get_seals(fd).map_err(|_| crate::tr!("error-secret-not-memfd"))?;
    if !seals.contains(SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK) {
        return Err(crate::tr!("error-secret-not-sealed"));
    }
    let stat = rustix::fs::fstat(fd).map_err(|e| e.to_string())?;
    let size = usize::try_from(stat.st_size).unwrap_or(usize::MAX);
    if size > MAX_SECRET_BYTES {
        return Err(crate::tr!("error-secret-too-large"));
    }
    let mut bytes = Zeroizing::new(vec![0u8; size]);
    let mut read = 0;
    while read < size {
        let n =
            rustix::io::pread(fd, &mut bytes[read..], read as u64).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        read += n;
    }
    bytes.truncate(read);
    Ok(Secret(bytes))
}

/// Read at most [`MAX_SECRET_BYTES`] from a reader, e.g. standard input.
///
/// # Errors
/// I/O errors.
pub fn from_reader(mut reader: impl Read) -> std::io::Result<Secret> {
    let mut bytes = Zeroizing::new(Vec::new());
    reader
        .by_ref()
        .take(MAX_SECRET_BYTES as u64)
        .read_to_end(&mut bytes)?;
    while bytes.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
        bytes.pop();
    }
    Ok(Secret(bytes))
}

/// `n` random bytes as lowercase hex.
#[must_use]
pub fn random_hex(n: usize) -> String {
    let mut bytes = vec![0u8; n];
    let mut filled = 0;
    while filled < n {
        match rustix::rand::getrandom(&mut bytes[filled..], rustix::rand::GetRandomFlags::empty()) {
            Ok(got) => filled += got,
            Err(rustix::io::Errno::INTR) => {}
            Err(_) => break,
        }
    }
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_cross_only_as_sealed_bounded_memfds() {
        let secret = Secret::new(b"p,ass=word;\x01".to_vec());
        let fd = to_memfd(&secret).unwrap();
        assert_eq!(
            from_fd(&fd).unwrap().expose(),
            secret.expose(),
            "round trip keeps every byte"
        );
        assert_eq!(format!("{secret:?}"), "Secret(..)", "never printed");

        let unsealed = rustix::fs::memfd_create("x", MemfdFlags::ALLOW_SEALING).unwrap();
        assert!(from_fd(&unsealed).is_err(), "a writable memfd is refused");
        let file = tempfile::tempfile().unwrap();
        assert!(from_fd(&file).is_err(), "an ordinary file is refused");
        let big = Secret::new(vec![b'a'; MAX_SECRET_BYTES + 1]);
        assert!(
            from_fd(to_memfd(&big).unwrap()).is_err(),
            "oversized secret is refused"
        );
        assert!(
            Secret::new(b"a\nb".to_vec()).as_text().is_err(),
            "line breaks cannot reach helpers"
        );
    }
}
