# enzimOS Mount

Drives, phones and network shares for enzimOS: the replacement for GVfs's
volume monitors, mount backends and FUSE bridge. The Files app, the shell and
the `enzimos-mount` command use it through one session D-Bus API
(`org.enzimos.Mount1`, see [docs/API.md](docs/API.md)).

Every mount is either a kernel mount or a FUSE mount, so
it appears as an ordinary folder below `/run/media/<user>/` to every program,
not only to GIO programs. There is no metadata daemon and no background
indexing. Per-folder view state stays with the apps that use it.

## What it handles

| Storage | How | Helper |
| --- | --- | --- |
| USB drives, cards, optical discs, other disks | UDisks2 (`Filesystem.Mount`, `Drive.Eject`/`PowerOff`) | udisks2 |
| Encrypted (LUKS, BitLocker) drives | UDisks2 `Encrypted.Unlock`, then mount | udisks2, cryptsetup |
| Disk images (`.iso`, `.img`) | UDisks2 `LoopSetup`, read-only | udisks2 |
| Android phones, MTP players | `aft-mtp-mount` (FUSE), selected by USB serial | `enzimos-aft-mtp` (no Qt) |
| iPhone and iPad | pairing with `idevicepair`, then `ifuse` | libimobiledevice, usbmuxd, ifuse |
| SMB / Windows shares | **in-kernel CIFS client**, through the root service | Linux `cifs` |
| NFS | kernel NFS client, through the root service | nfs-utils (`mount.nfs`) |
| SFTP | `sshfs` (FUSE), with host-key confirmation | sshfs, openssh |
| WebDAV, FTP, FTPS | `rclone mount` (FUSE) | rclone (optional) |
| Google Drive, OneDrive, Dropbox, Nextcloud | `rclone mount` with a full file cache; sign-in in the browser | rclone, curl |

Removable drives can also be **formatted** (`Format`): one volume quick-formatted
as exFAT, FAT32, NTFS or ext4, or the whole drive erased onto a new MBR table.
Open files give a Busy naming the programs; internal disks are left to Settings.

**Cloud drives** (`AddCloud`) sign in through the browser without blocking:
rclone's own OAuth sign-in for Google Drive, OneDrive and Dropbox, and
Nextcloud's Login Flow v2 (only the server address is typed). Each account keeps
a private rclone configuration in `~/.config/enzimos-mount/cloud/` (0600, so
refreshed tokens are kept) and mounts with a full cache (10 GB at most, kept
5 GB clear of a full disk). Google Drive needs an enzimOS sign-in client in
`/etc/enzimos-mount/google-drive.json`.

Cameras that only speak PTP are handed to `aft-mtp-mount` as well. Most of them
work, but they are not qualified. Files on an iPhone are limited to what
Apple's media service (AFC) exposes, which is usually the photos.

## Processes

* **`enzimos-mountd`**: the per-user session service `org.enzimos.Mount1`.
  - It watches UDisks2 through D-Bus signals, USB phones through a udev monitor,
    and the mount table with `poll(2)` on `/proc/self/mountinfo`.
  - It owns the user's network locations and their passwords, kept in the
    Secret Service (oo7 on enzimOS, unlocked at login by `pam_oo7`).
  - It supervises the FUSE helpers.
  - It starts with the enzUI session (`enzui-session.target`), and on other
    desktops through D-Bus activation.
* **`enzimos-mount-system`**: the root service `org.enzimos.MountSystem1`.
  - It is D-Bus activated and exits after 60 s idle.
  - It makes kernel SMB and NFS mounts for the calling user, and creates
    mount points for that user's FUSE mounts.
  - Every method that changes anything requires the polkit action
    `org.enzimos.mount.user-mount`, which is allowed for active local
    sessions. `List`, `BootMounts` and `Capabilities` only report the
    caller's own data.
* **`enzimos-mount-worker`**: a one-shot child of the root service.
  - Each worker makes exactly one `fsopen`/`fsmount`/`move_mount` or `umount2`
    call, under a deadline.
  - A mount waiting on a dead server is killed with its process group, and the
    service stays responsive.

## Startup mounts

A saved SMB location with a share, or an NFS location, can be set to **mount
at startup** (`SetMountAtBoot`, or `enzimos-mount startup ID on`):

- **Approval:** an administrator approves each startup share (polkit
  `org.enzimos.mount.boot-mount`, `auth_admin`); the dialog names the share
  and server. The owner can later refresh only the password of that entry
  without approving again.
- **Storage:** the entry lives root-only in `/var/lib/enzimos-mount/boot`. Its
  password is encrypted with `systemd-creds` (the machine's credential key, plus
  the TPM when present), under a name bound to owner and location.
- **At startup:** `enzimos-mount-boot.service` mounts each entry at
  `/run/media/<owner>/<name>`, owned by the owner, before anyone logs in. It is
  skipped when nothing is stored. It is ordered after the network stack, but
  nothing waits for it: a server that is off neither delays nor fails startup.
  It retries in the background (5 s doubling to 5 min) and exits when every
  share is mounted. A refused password is not retried, so it cannot lock the
  account; the owner is asked for it after logging in.
- **In a session,** the location also reconnects automatically like any
  auto-connect location.
- **At shutdown,** `enzimos-mount-cleanup.service` stops before the network
  and detaches every kernel network mount, so shutdown never waits on an
  unreachable server.

## Connecting

- **Addresses:** `smb://`, `sftp://`, `nfs://`, `dav(s)://` and `ftp(s)://`
  addresses work, and so do `\\server\share`, `server/share` and
  `user@host:/path` (SFTP).
- **A bare server address** answers `ChooseShare` with the shares it offers.
- **Accounts:** `DOMAIN\user` and `user@domain` are understood.
- **Passwords:** a password remembered for one location is reused for another
  location on the same server with the same account.
- **Old servers:** a server that only speaks SMB1 answers `ProtocolMismatch`,
  so the client can offer it explicitly. The first SMB1 connection of a user
  to a server needs administrator approval (polkit `org.enzimos.mount.smb1`),
  as on Windows; SMB1 mounts are made without Unix extensions.
- **Languages:** messages and notifications follow the session language
  (`LANGUAGE`, `LC_ALL`, `LC_MESSAGES`, `LANG`), like the enzUI apps.
  Catalogs are in [locales/](locales/) (English and Spanish); a missing
  translation falls back to English. The root service sends message
  identifiers, which the session service translates.
- **Busy:** when files are open, the message names the programs holding them.
- **Disconnecting:** a location you disconnect is not reconnected
  automatically until you connect it again.
- **Suspend:** the session service holds suspend briefly with a logind delay
  lock and force-unmounts its kernel network mounts (SMB, NFS) before the
  network goes down, so suspend never waits on a server it can no longer
  reach. They reconnect after resume; one that still fails after four tries
  gets a "… disconnected" notification.
- **iPhones:** pairing waits up to a minute for "Trust" and says so in a
  notification.
- **Free space:** free and total space are reported for mounted items.

## Notifications

The shell already announces USB drives, cards and discs from UDisks2. This
service sends desktop notifications (`org.freedesktop.Notifications`) only for
what the shell cannot see:

| Event | Notification | Button |
| --- | --- | --- |
| A phone, iPhone or camera is plugged in after login | “Pixel 8 connected”, with how to allow file access | Open (mounts it and opens the folder) |
| A phone is unmounted by the user | “… can be unplugged” | none |
| A mounted location stops answering | “… is not responding”, withdrawn when it answers again | Disconnect (forced unmount) |
| A helper's connection ends unexpectedly | “… disconnected” | Reconnect |
| A location set to connect automatically needs a password or a host-key confirmation | “… did not connect” | none (sign in from Files) |

The service keeps one notification per item, and a newer one replaces it.

## Reliability rules

* No file-system call on a mount runs on a service's D-Bus loop. Mount,
  unmount and health probes run in bounded child processes or timed blocking
  tasks. Every helper has a deadline (45 s for a kernel mount, 40 s for a FUSE
  mount to appear, 15 s for an unmount) and capped output.
* SMB is mounted `soft` with a 10 s echo interval and NFS `soft,timeo=100,retrans=2`,
  so I/O on a dead server returns errors instead of hanging forever.
* Every 15 s each network or phone mount is probed with `statfs` and an 8 s limit:
  - a mount that does not answer is shown as *not responding*;
  - a FUSE mount whose helper died (cable pulled, server gone) is detached
    (`fusermount3 -u -z`) and removed;
  - `Unmount(force)` detaches a dead SMB mount (`MNT_FORCE`, then `MNT_DETACH`).
* Unmounting refuses while files are open (`Busy`) unless forced.
* An unplugged phone has its helper stopped and its mount detached immediately.
* Saved locations marked *connect automatically* are retried with a backoff
  (30 s doubling to 10 min). NetworkManager reporting connectivity resets the
  backoff. Wrong passwords and untrusted host keys stop the retries until the
  user acts.
* Kernel mounts survive a restart of the session service and are adopted
  again. Mounts left by dead FUSE helpers are cleaned up at start.

## Resource use

The session service listens for device and mount-table changes rather than
indexing files. Mounted locations are probed periodically for availability.
Secret Service connections are opened only when credentials are needed. The root
service is activated on demand and exits after 60 seconds without work.

## Security model

* Passwords never appear in arguments, D-Bus strings or configuration files.
  - Clients pass them as sealed `memfd` descriptors, and helpers get them on
    standard input. The root worker hands them to the kernel with
    `fsconfig(FSCONFIG_SET_STRING, "password")`, never inside an option string.
  - rclone, which only reads passwords from its environment, gets an obscured
    value in its own environment.
* Addresses are parsed strictly ([src/uri.rs](src/uri.rs)). Host and user names
  cannot start with `-` or contain separators. Passwords inside addresses are
  refused.
* `/run/media/<user>` is root-owned (0700), with an ACL granting only that user
  read and search, as UDisks2 creates it. The root service creates and removes
  entries through directory descriptors with `O_NOFOLLOW`. It records what it
  made and only ever unmounts or removes those entries for the same user.
* SMB mounts are `nosuid,nodev`, owned by the user (`uid`, `gid`, `forceuid`),
  with file mode 0600 and directory mode 0700.
* The root service's state is root-only: `/run/enzimos-mount` is 0700 and its
  units set `UMask=0077`, so no other account can hold the registry lock. A
  registry that cannot be read stops the service instead of being reset.
* Kernel mounts are reserved in the registry before the mount system call, so
  a mount that attaches after its deadline is still tracked, counted against
  the per-user limit (64 mounts, 4 in progress) and detached at shutdown.
  Unmounting removes everything stacked on the folder before forgetting it.
* A forced unmount that a stalling server holds past its 15 s deadline is
  followed by a lazy detach, which never waits for the server. Unmount
  workers have their own pool, so stuck mounts cannot starve them.
* Labels are limited to 255 bytes and paths inside a share to 1024.
* SFTP host keys are never accepted silently.
  - The first connection fails with `HostKeyUnknown`, carrying the server's
    SHA-256 fingerprints.
  - Only keys whose fingerprints the user confirmed (`TrustHostKey`) are written
    to `~/.local/share/enzimos-mount/known_hosts`.
  - A changed key is a distinct `HostKeyChanged` error.

## Files

| Path | Contents |
| --- | --- |
| `~/.config/enzimos-mount/locations.json` | saved locations (mode 0600, no passwords) |
| Secret Service, schema `org.enzimos.Mount.Password` | remembered passwords |
| `~/.local/share/enzimos-mount/known_hosts` | trusted SFTP host keys |
| `/run/enzimos-mount/registry.json` | root-only list of mounts the root service owns (shared with the startup service under a file lock) |
| `/var/lib/enzimos-mount/boot/` | root-only startup shares; passwords encrypted with `systemd-creds` |
| `~/.config/enzimos-mount/clouds.json`, `~/.config/enzimos-mount/cloud/<id>.conf` | cloud accounts and their private rclone configurations (0600) |
| `~/.cache/enzimos-mount/cloud/<id>/` | cloud drive file cache |
| `/var/lib/enzimos-mount/smb1-allowed.json` | root-only list of servers each user may reach with SMB1 |

## Command line

```
enzimos-mount list
enzimos-mount connect smb://nas.local/photos --save --auto --mount
enzimos-mount login net-1a2b3c4d --user alice --remember < password-file
enzimos-mount unmount block:sdb1
enzimos-mount remove block:sdb1        # unmount every volume, power off
enzimos-mount startup net-1a2b3c4d on  # mount at startup (administrator approves)
enzimos-mount discover
```

The command exits 3 when credentials are needed, 4 when an SFTP host key must
be confirmed, and 5 when files are still open.

## Build and test

Requires Linux, Rust 1.95 or newer, pkg-config and libudev development files.
Runtime helpers are listed in the storage table above; unavailable helpers are
reported through service capabilities.

```sh
cargo build --release --locked
cargo test --locked
cargo clippy --all-targets --locked
cargo fmt --check
```

Tests use private temporary state, sealed descriptors and owned helper processes.
They do not mount devices or install services. Real mounts, formatting, credentials,
boot reconnect and shutdown behavior require disposable guests with the relevant
devices and servers. Do not test destructive operations on host disks.

`packaging/` supplies user/system activation, polkit policy and service units.
Building does not install or enable them. The root service, worker and session
service must be deployed together with matching policy.

## License

MIT; see [LICENSE](LICENSE).
