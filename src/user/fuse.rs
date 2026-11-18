//! Supervised FUSE mounts (phones, iPhones, SFTP, WebDAV, FTP).
//!
//! The helper runs in the foreground as a child of the service, in its own
//! process group. The mount is ready once it appears in the mount table; if
//! the helper exits first, its error output explains why. Unmounting uses
//! `fusermount3 -u` (refusing while busy unless forced, then `-z`), then the
//! helper is stopped. A watcher task notices a helper that dies on its own
//! (cable pulled, server gone) and cleans the dead mount so nothing hangs on it.

use crate::error::{Error, Result};
use crate::process::{Spec, Supervised};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::sync::oneshot;

/// How long a helper may take to make its mount appear.
pub const READY_TIMEOUT: Duration = Duration::from_secs(40);
/// How long a fresh mount may take to answer its first `statfs`.
pub const READY_PROBE: Duration = Duration::from_secs(15);
/// Grace given to a helper after a forced stop before it is killed.
pub const STOP_GRACE: Duration = Duration::from_secs(3);
/// How long a helper may take to exit by itself after a clean unmount, e.g.
/// rclone finishing uploads of files closed just before.
pub const FLUSH_GRACE: Duration = Duration::from_secs(30);

/// A running FUSE mount.
#[derive(Debug)]
pub struct FuseMount {
    /// Mount point.
    pub path: PathBuf,
    stop: Option<oneshot::Sender<()>>,
    done: Option<oneshot::Receiver<()>>,
    stopping: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

/// Why a helper ended unexpectedly.
pub type ExitReport = (String, Option<i32>, String);

fn mounted(path: &Path) -> bool {
    crate::mountinfo::at(&crate::mountinfo::current(), path)
        .is_some_and(|m| m.fs_type.starts_with("fuse"))
}

/// Start `spec`, wait until `path` is a FUSE mount, and supervise it.
///
/// `on_exit` runs (with the item id, exit code and error tail) if the helper
/// exits without being asked to. `explain` turns a failed start's exit code and
/// error output into an error.
///
/// # Errors
/// The `explain`ed failure, or [`Error::Timeout`].
pub async fn start(
    id: String,
    spec: Spec,
    path: PathBuf,
    explain: impl Fn(Option<i32>, &str) -> Error,
    on_exit: impl FnOnce(ExitReport) + Send + 'static,
) -> Result<FuseMount> {
    let mut child = Supervised::spawn(spec)
        .map_err(|e| Error::Unsupported(crate::tr!("error-helper-start", error = e.to_string())))?;
    let deadline = tokio::time::Instant::now() + READY_TIMEOUT;
    loop {
        if mounted(&path) {
            // A helper can mount and then fail to connect (sshfs with an
            // untrusted host key does): ready means alive and answering.
            let answered = probe(path.clone(), READY_PROBE).await;
            tokio::time::sleep(Duration::from_millis(200)).await;
            if child.try_exited().is_none() && answered.is_ok() {
                break;
            }
            let code = child.try_exited().flatten();
            tokio::time::sleep(Duration::from_millis(100)).await;
            let tail = child.stderr_tail();
            child.stop(Duration::from_millis(500)).await;
            lazy_unmount(&path).await;
            return Err(explain(code, &tail));
        }
        if let Some(code) = child.try_exited() {
            // Give the error pipe a moment to drain.
            tokio::time::sleep(Duration::from_millis(100)).await;
            return Err(explain(code, &child.stderr_tail()));
        }
        if tokio::time::Instant::now() >= deadline {
            child.stop(Duration::from_millis(500)).await;
            lazy_unmount(&path).await;
            return Err(Error::Timeout(crate::tr!("error-helper-timeout")));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let (stop_tx, stop_rx) = oneshot::channel();
    let (done_tx, done_rx) = oneshot::channel();
    let watched = path.clone();
    let stopping = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let expected = std::sync::Arc::clone(&stopping);
    tokio::spawn(async move {
        tokio::select! {
            code = child.wait() => {
                let tail = child.stderr_tail();
                if !expected.load(std::sync::atomic::Ordering::SeqCst) {
                    lazy_unmount(&watched).await;
                    on_exit((id, code, tail));
                }
            }
            _ = stop_rx => {
                child.stop(STOP_GRACE).await;
            }
        }
        let _ = done_tx.send(());
    });
    Ok(FuseMount {
        path,
        stop: Some(stop_tx),
        done: Some(done_rx),
        stopping,
    })
}

/// Detach a FUSE mount even if its helper is gone or hung.
pub async fn lazy_unmount(path: &Path) {
    if let Some(fusermount) =
        crate::process::helper("fusermount3").or_else(|| crate::process::helper("fusermount"))
    {
        let _ = crate::process::run(
            Spec::new(fusermount, Duration::from_secs(10))
                .args(["-u", "-z", "-q"])
                .arg(path),
        )
        .await;
    }
}

impl FuseMount {
    /// Unmount; `force` detaches even with open files.
    ///
    /// # Errors
    /// [`Error::Busy`] when files are open and `force` is not set.
    pub async fn unmount(&mut self, force: bool) -> Result<()> {
        let fusermount = crate::process::helper("fusermount3")
            .or_else(|| crate::process::helper("fusermount"))
            .ok_or_else(|| Error::Unsupported("fusermount3 is not installed".to_owned()))?;
        self.stopping
            .store(true, std::sync::atomic::Ordering::SeqCst);
        if mounted(&self.path) {
            let flags: &[&str] = if force { &["-u", "-z"] } else { &["-u"] };
            let output = crate::process::run(
                Spec::new(fusermount, Duration::from_secs(15))
                    .args(flags)
                    .arg(&self.path),
            )
            .await;
            match output {
                Ok(o) if o.success() => {}
                Ok(o) if o.stderr.contains("busy") => {
                    self.stopping
                        .store(false, std::sync::atomic::Ordering::SeqCst);
                    return Err(Error::Busy(crate::tr!("error-files-open")));
                }
                Ok(o) => {
                    self.stopping
                        .store(false, std::sync::atomic::Ordering::SeqCst);
                    return Err(Error::Failed(o.stderr.trim().to_owned()));
                }
                Err(_) => {
                    lazy_unmount(&self.path).await;
                }
            }
        }
        // After a clean unmount the helper exits by itself once it has
        // flushed; only a forced unmount or a helper that lingers is signalled.
        let mut done = self.done.take();
        if !force
            && let Some(waiting) = done.as_mut()
            && tokio::time::timeout(FLUSH_GRACE, waiting).await.is_ok()
        {
            return Ok(());
        }
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(done) = done {
            let _ = tokio::time::timeout(STOP_GRACE + Duration::from_secs(3), done).await;
        }
        Ok(())
    }
}

/// Probe a mount without risking the caller: `statvfs` runs on a blocking
/// thread and the result is abandoned after `timeout`. Answers free and
/// total bytes.
///
/// # Errors
/// The kind of failure: disconnected, no answer, or another error.
pub async fn probe(
    path: PathBuf,
    timeout: Duration,
) -> std::result::Result<(u64, u64), ProbeFailure> {
    let task = tokio::task::spawn_blocking(move || {
        rustix::fs::statvfs(&path).map(|v| {
            (
                v.f_bavail.saturating_mul(v.f_frsize),
                v.f_blocks.saturating_mul(v.f_frsize),
            )
        })
    });
    match tokio::time::timeout(timeout, task).await {
        Ok(Ok(Ok(space))) => Ok(space),
        Ok(Ok(Err(rustix::io::Errno::NOTCONN))) => Err(ProbeFailure::Disconnected),
        Ok(Ok(Err(_)) | Err(_)) => Err(ProbeFailure::Error),
        Err(_) => Err(ProbeFailure::NoAnswer),
    }
}

/// A failed health probe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeFailure {
    /// The FUSE helper is gone.
    Disconnected,
    /// The probe did not return in time.
    NoAnswer,
    /// Another error.
    Error,
}
