//! Bounded helper processes.
//!
//! Every external helper runs in its own process group with a cleared
//! environment, a deadline and capped output. On timeout the whole group is
//! killed, so a helper stuck on a dead server or device cannot hold a caller.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, Command};

/// Captured output cap per stream.
pub const MAX_OUTPUT_BYTES: usize = 256 * 1024;

/// Directories searched for helpers. Fixed, so a user's `PATH` cannot
/// substitute a helper in a service.
pub const HELPER_DIRS: [&str; 2] = ["/usr/bin", "/usr/sbin"];

/// Find an installed helper by name.
#[must_use]
pub fn helper(name: &str) -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("ENZIMOS_MOUNT_HELPER_DIR") {
        // Test hook: tests point this at fixture helpers.
        let candidate = Path::new(&dir).join(name);
        return candidate.is_file().then_some(candidate);
    }
    HELPER_DIRS
        .iter()
        .map(|d| Path::new(d).join(name))
        .find(|p| p.is_file())
}

/// What to run.
#[derive(Debug, Default)]
pub struct Spec {
    /// Program path.
    pub program: PathBuf,
    /// Arguments.
    pub args: Vec<OsString>,
    /// Environment on top of a minimal base.
    pub env: BTreeMap<String, OsString>,
    /// Bytes written to standard input, then closed.
    pub stdin: Option<zeroize::Zeroizing<Vec<u8>>>,
    /// Deadline for the whole run.
    pub timeout: Duration,
}

impl Spec {
    /// A run of `program` with a deadline.
    #[must_use]
    pub fn new(program: impl Into<PathBuf>, timeout: Duration) -> Self {
        Self {
            program: program.into(),
            timeout,
            ..Self::default()
        }
    }

    /// Add an argument.
    #[must_use]
    pub fn arg(mut self, arg: impl Into<OsString>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Add arguments.
    #[must_use]
    pub fn args<I: IntoIterator<Item = S>, S: Into<OsString>>(mut self, args: I) -> Self {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Set an environment variable.
    #[must_use]
    pub fn env(mut self, key: &str, value: impl Into<OsString>) -> Self {
        self.env.insert(key.to_owned(), value.into());
        self
    }

    fn command(&self) -> Command {
        let mut command = Command::new(&self.program);
        command
            .args(&self.args)
            .env_clear()
            .env("PATH", "/usr/bin:/usr/sbin")
            .env("LANG", "C.UTF-8");
        for key in [
            "HOME",
            "USER",
            "LOGNAME",
            "XDG_RUNTIME_DIR",
            "SSH_AUTH_SOCK",
            "DBUS_SESSION_BUS_ADDRESS",
        ] {
            if let Some(value) = std::env::var_os(key) {
                command.env(key, value);
            }
        }
        command.envs(&self.env);
        command.process_group(0).kill_on_drop(true);
        command
    }
}

/// A finished run.
#[derive(Debug)]
pub struct Output {
    /// Exit code; `None` when killed by a signal.
    pub code: Option<i32>,
    /// Standard output, capped.
    pub stdout: String,
    /// Standard error, capped.
    pub stderr: String,
}

impl Output {
    /// Exited with status zero.
    #[must_use]
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }
}

/// Why a run did not produce an [`Output`].
#[derive(Debug)]
pub enum RunError {
    /// The program could not start.
    Spawn(std::io::Error),
    /// The deadline passed; the process group was killed.
    Timeout,
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Spawn(e) => write!(f, "could not start helper: {e}"),
            Self::Timeout => f.write_str("the helper did not finish in time"),
        }
    }
}

async fn read_capped(mut reader: impl AsyncRead + Unpin) -> String {
    let mut out = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        match reader.read(&mut buffer).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let room = MAX_OUTPUT_BYTES.saturating_sub(out.len());
                out.extend_from_slice(&buffer[..n.min(room)]);
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Kill a child's whole process group.
pub fn kill_group(child: &Child) {
    if let Some(pid) = child
        .id()
        .and_then(|id| rustix::process::Pid::from_raw(id as i32))
    {
        let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
    }
}

/// Run to completion within the deadline.
///
/// # Errors
/// [`RunError`] when the program cannot start or overruns its deadline.
pub async fn run(spec: Spec) -> Result<Output, RunError> {
    let mut command = spec.command();
    command.stdin(if spec.stdin.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn().map_err(RunError::Spawn)?;
    let stdin = child.stdin.take();
    let input = spec.stdin;
    let feed = async move {
        if let (Some(mut pipe), Some(bytes)) = (stdin, input) {
            let _ = pipe.write_all(&bytes).await;
            let _ = pipe.shutdown().await;
        }
    };
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let collect = async {
        let ((), out, err) = tokio::join!(
            feed,
            async {
                match stdout {
                    Some(s) => read_capped(s).await,
                    None => String::new(),
                }
            },
            async {
                match stderr {
                    Some(s) => read_capped(s).await,
                    None => String::new(),
                }
            }
        );
        (out, err)
    };
    match tokio::time::timeout(spec.timeout, async {
        let (stdout, stderr) = collect.await;
        let status = child.wait().await;
        (stdout, stderr, status)
    })
    .await
    {
        Ok((stdout, stderr, status)) => {
            let code = status.ok().and_then(|s| s.code());
            Ok(Output {
                code,
                stdout,
                stderr,
            })
        }
        Err(_) => {
            kill_group(&child);
            let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
            Err(RunError::Timeout)
        }
    }
}

/// A long-running helper (a FUSE file system) owned by the service.
#[derive(Debug)]
pub struct Supervised {
    child: Child,
    stderr_tail: Arc<Mutex<String>>,
}

/// Bytes of a supervised helper's latest standard error kept for diagnosis.
pub const TAIL_BYTES: usize = 4096;

impl Supervised {
    /// Start `spec` without a deadline; `spec.stdin` is written then closed.
    ///
    /// # Errors
    /// When the program cannot start.
    pub fn spawn(spec: Spec) -> std::io::Result<Self> {
        let mut command = spec.command();
        command.stdin(if spec.stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });
        command.stdout(Stdio::null()).stderr(Stdio::piped());
        let mut child = command.spawn()?;
        if let (Some(mut pipe), Some(bytes)) = (child.stdin.take(), spec.stdin) {
            tokio::spawn(async move {
                let _ = pipe.write_all(&bytes).await;
                let _ = pipe.shutdown().await;
            });
        }
        let tail = Arc::new(Mutex::new(String::new()));
        if let Some(mut stderr) = child.stderr.take() {
            let tail = Arc::clone(&tail);
            tokio::spawn(async move {
                let mut buffer = [0u8; 2048];
                while let Ok(n) = stderr.read(&mut buffer).await {
                    if n == 0 {
                        break;
                    }
                    let text = String::from_utf8_lossy(&buffer[..n]).into_owned();
                    let mut tail = tail
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    tail.push_str(&text);
                    if tail.len() > TAIL_BYTES {
                        let mut cut = tail.len() - TAIL_BYTES;
                        while !tail.is_char_boundary(cut) {
                            cut += 1;
                        }
                        tail.drain(..cut);
                    }
                }
            });
        }
        Ok(Self {
            child,
            stderr_tail: tail,
        })
    }

    /// The latest standard error text.
    #[must_use]
    pub fn stderr_tail(&self) -> String {
        self.stderr_tail
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Exit status if it has exited.
    pub fn try_exited(&mut self) -> Option<Option<i32>> {
        self.child
            .try_wait()
            .ok()
            .flatten()
            .map(|status| status.code())
    }

    /// Process ID while running.
    #[must_use]
    pub fn pid(&self) -> Option<u32> {
        self.child.id()
    }

    /// Ask the group to stop, then kill it after `grace`.
    pub async fn stop(mut self, grace: Duration) {
        if let Some(pid) = self
            .child
            .id()
            .and_then(|id| rustix::process::Pid::from_raw(id as i32))
        {
            let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::TERM);
        }
        if tokio::time::timeout(grace, self.child.wait())
            .await
            .is_err()
        {
            kill_group(&self.child);
            let _ = tokio::time::timeout(Duration::from_secs(2), self.child.wait()).await;
        }
    }

    /// Wait for exit.
    pub async fn wait(&mut self) -> Option<i32> {
        self.child.wait().await.ok().and_then(|s| s.code())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_hung_helper_and_its_children_are_killed_at_the_deadline() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("grandchild.pid");
        // The helper starts a grandchild in its group and hangs; both must die.
        let script = format!("sleep 30 & echo $! > {}; wait", marker.display());
        let started = std::time::Instant::now();
        let result =
            run(Spec::new("/bin/sh", Duration::from_millis(400)).args(["-c", &script])).await;
        assert!(
            matches!(result, Err(RunError::Timeout)),
            "deadline reported"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "caller released promptly"
        );
        let pid: i32 = std::fs::read_to_string(&marker)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        let alive = std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .is_ok_and(|s| !s.split(' ').nth(2).is_some_and(|state| state == "Z"));
        assert!(!alive, "grandchild in the helper's group was killed");

        let ok = run(Spec::new("/bin/sh", Duration::from_secs(5))
            .args(["-c", "head -c 400000 /dev/zero; echo err >&2"]))
        .await
        .unwrap();
        assert!(
            ok.success() && ok.stdout.len() == MAX_OUTPUT_BYTES && ok.stderr == "err\n",
            "output is capped"
        );
    }
}
