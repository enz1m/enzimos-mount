//! enzimOS storage mounting.
//!
//! Three processes share this library:
//!
//! * `enzimos-mountd`, the per-user session service (`org.enzimos.Mount1`). It
//!   watches removable drives through UDisks2, phones through udev, keeps the
//!   user's saved network locations, stores their passwords with the Secret
//!   Service (oo7) and runs the unprivileged FUSE helpers.
//! * `enzimos-mount-system`, a D-Bus-activated root service
//!   (`org.enzimos.MountSystem1`) that performs the kernel mounts a user cannot:
//!   SMB through the in-kernel CIFS client and NFS. It prepares mount points
//!   below `/run/media/<user>` and only ever unmounts what it mounted for the
//!   same user.
//! * `enzimos-mount-worker`, a short-lived child of the root service that makes
//!   one mount system call, so a mount stuck inside the kernel can be abandoned
//!   instead of wedging the service.
//!
//! Nothing here may block a D-Bus loop on a file system call: every operation
//! that touches a mount runs in a bounded child process or a timed blocking task.

pub mod api;
pub mod error;
pub mod i18n;
pub mod log;
pub mod mountinfo;
pub mod names;
pub mod process;
pub mod secret;
pub mod system;
pub mod uri;
pub mod user;
