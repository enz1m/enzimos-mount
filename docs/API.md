# org.enzimos.Mount1

Session bus, object `/org/enzimos/Mount1`, interface `org.enzimos.Mount1`.
The service is D-Bus activatable. Clients must allow long method calls: a
mount can wait up to about 45 s for a server and longer for a polkit
password prompt. Use a timeout of at least 180 s, or none.

## Snapshot

`List() → s` returns, and `Changed(s)` carries, one JSON document:

```json
{
  "version": 1,
  "generation": 42,
  "capabilities": {"drives": true, "smb": true, "nfs": false, "sftp": true,
                   "webdav_ftp": true, "mtp": true, "ios": true,
                   "smb_browse": true, "keyring": true,
                   "cloud": ["onedrive", "dropbox", "nextcloud"]},
  "items": [
    {"id": "block:sdb1", "kind": "usb", "label": "PHOTOS", "detail": "16 GB · ACME Stick",
     "state": "mounted", "mount_path": "/run/media/alice/PHOTOS", "read_only": false,
     "size": 16000000000, "can_mount": false, "can_unmount": true, "can_eject": false,
     "can_power_off": true, "device": "/dev/sdb1", "drive": "drive:ACME_Stick_123",
     "uri": null, "saved": false, "auto_connect": false, "mount_at_boot": false,
     "can_mount_at_boot": false, "free": 9100000000, "capacity": 15990000000},
    {"id": "net-1a2b3c4d", "kind": "network", "label": "photos on nas.local",
     "state": "failed", "reason": "The server “nas.local” did not answer", "...": "..."}
  ]
}
```

* `kind` is one of `usb`, `card`, `optical`, `disk`, `image`, `phone`, `ios`,
  `camera`, `network` or `cloud`.
* `state` is one of `unmounted`, `mounting`, `mounted`, `unmounting`, `formatting`,
  `signing_in`, `locked`, `not_responding`, `no_media` or `failed`. A `failed` state also carries
  `reason`.
* `free` and `capacity` are in bytes. For drives they come from the latest
  drive refresh; for network locations and phones they come from the latest
  health probe, every 15 s.
* `capabilities.cloud` lists the cloud services that can be added:
  `google_drive` (only when the system provides a Google sign-in client),
  `onedrive`, `dropbox` and `nextcloud`.
* `mount_at_boot` means the location is also mounted at startup, before
  login. `can_mount_at_boot` is true for SMB locations with a share and for
  NFS.
* `can_format` is true for volumes of drives that can be unplugged and are not
  read-only; `filesystem` is the volume's file system type (`exfat`, `vfat`,
  `ntfs`, `ext4`, `crypto_LUKS`, …) when known.
* Items that share a `drive` belong to one physical drive. `Eject` and
  `SafelyRemove` act on all of them.
* Fields are only ever added. Ignore unknown fields, and treat unknown `kind`
  or `state` values as generic.

`Changed` is debounced (about 100 ms) and always carries the whole snapshot.

## Methods

| Method | Result |
| --- | --- |
| `Mount(s id) → s path` | Mount and return the folder. Already mounted returns the folder. |
| `MountWithCredentials(s id, s username, s domain, h secret, b remember) → s path` | Mount with a password in a sealed memfd (see below). With `remember`, the password is stored in the keyring and the location is saved. |
| `Unlock(s id, h passphrase) → s path` | Unlock an encrypted drive and mount it. |
| `Unmount(s id, b force)` | Unmount. Without `force`, open files give `Busy`, whose message names the programs holding them when they can be found. With `force`, the mount is detached, which also works for an unresponsive server. A network location the user unmounts is not reconnected automatically until it is mounted again or the session restarts. |
| `Eject(s id)` | Unmount every volume of the drive (locking encrypted ones), then eject. For phones and network items this is `Unmount`. |
| `SafelyRemove(s id)` | Same, then power the drive off. |
| `AddLocation(s uri, s label, a{sv} options) → s id` | Add a network location, or update the existing one with the same address. Options: `save` (b), `auto_connect` (b, implies `save`), `smb_version` (s: `1.0`…`3.1.1` or `default`). |
| `UpdateLocation(s id, a{sv} options)` | Options as above, plus `label` (s), `username` (s) and `forget_password` (b). Clears a paused automatic connection. |
| `SetMountAtBoot(s id, b enabled, h secret)` | Mount an SMB/NFS location at startup, before anyone logs in. It implies `save` and `auto_connect`. Enabling asks for administrator approval (polkit `org.enzimos.mount.boot-mount`, `auth_admin`). The secret may be empty to use the remembered password; without one the call answers `NeedsCredentials`. The root service keeps the password encrypted with `systemd-creds`. Disabling needs no approval. |
| `RemoveLocation(s id)` | Unmount (refused while busy), forget the remembered password, remove. |
| `TrustHostKey(s id, as fingerprints)` | Trust the SFTP server keys with these `SHA256:` fingerprints. The server is scanned again and only matching keys are stored. |
| `Discover() → s` | JSON list of `{name, uri, source}` found by mDNS and WS-Discovery in about 3 s. |
| `ListShares(s uri, s username, s domain, h secret) → s` | JSON list of `{name, comment, uri}` for an SMB server. The secret may be empty. |
| `MountImage(s path) → s path` | Attach a disk image read-only and mount it. |
| `AddCloud(s provider, s server) → s id` | Add a cloud drive. `provider` is one of `capabilities.cloud`; `server` is the Nextcloud address (`cloud.example.com`; `https://` is assumed, plain `http://` only for local addresses) and empty otherwise. Returns at once with the new identity, an item of kind `cloud` in state `signing_in`, while the sign-in opens in the person's browser (the OAuth services through rclone, Nextcloud through its Login Flow v2). When the person finishes, the item becomes a saved, auto-connecting cloud drive and is mounted; when they cancel or the sign-in fails or takes over ten minutes, the item disappears and a notification says why. Only one sign-in runs at a time (`Busy`). `RemoveLocation` cancels a sign-in or removes the account with its configuration and cache. |
| `Format(s id, a{sv} options) → s id` | Quick-format a removable drive's volume. Options: `type` (s: `exfat`, `vfat` (FAT32), `ntfs` or `ext4`), `label` (s, within that file system's limits), `whole_drive` (b: erase the whole drive and create one volume on a new MBR partition table, for sticks with several or unusual partitions). Open files give `Busy`; internal disks give `Invalid`. Returns the identity of the formatted volume, which is left unmounted. ext4 volumes belong to the user. |

Property `Version` (u) is the snapshot schema version.

### Addresses

`AddLocation` accepts these address forms:

* `smb://[DOMAIN;][user@]host[:port]/share[/path]`
* `sftp://[user@]host[:port][/path]`
* `nfs://host[:port]/export`
* `dav://` and `davs://`
* `ftp://` and `ftps://`

A bare `host/share` or `\\host\share` means SMB, and `user@host:/path` means SFTP. An address containing a
password is refused.

### Secrets

Pass passwords as a file descriptor to a `memfd` sealed with `F_SEAL_WRITE`,
`F_SEAL_GROW` and `F_SEAL_SHRINK`, of at most 4096 bytes. The service refuses
anything else. An empty memfd means "no password".

## Errors

Names are `org.enzimos.Mount1.Error.<Name>`. The message is a sentence you
can show to the user, in the session language, except where noted.

| Name | Meaning |
| --- | --- |
| `NeedsCredentials` | The message is JSON `{id, username, domain, can_remember, retry}`. Ask the user, then call `MountWithCredentials`. A user name typed as `DOMAIN\user`, or for SMB as `user@domain`, is split into user and domain. When `retry` is true, the previous or remembered password was refused. |
| `AuthFailed` | Explicitly supplied credentials or a passphrase were refused. |
| `HostKeyUnknown`, `HostKeyChanged` | The message is JSON `{id, host, fingerprints}`. Show the fingerprints. If the user accepts, call `TrustHostKey`, then mount again. |
| `Unreachable`, `Timeout` | The server or device did not answer. |
| `Busy` | Files are open on the mount, or another operation on the item is running. |
| `DeviceLocked` | Unlock the phone, or tap *Trust* on the iPhone. |
| `NotAuthorized` | Refused by polkit or by the server's export rules. |
| `Unsupported` | A helper this item needs is not installed. |
| `ChooseShare` | The location is a server without a share. The message is JSON `{id, shares: [{name, comment, uri}]}`. Let the user pick one, then `AddLocation` that share's `uri` and mount it. |
| `ProtocolMismatch` | The SMB server only speaks SMB1. Offer the user `UpdateLocation(id, {smb_version: "1.0"})`, explaining that it is less secure, then mount again. The first such mount asks for administrator approval. |
| `NotFound`, `Invalid`, `Failed` | As named. |

# org.enzimos.MountSystem1 (internal)

System bus, root-only owner, used by `enzimos-mountd`. Methods that change
anything check the caller with polkit (`org.enzimos.mount.user-mount`); the
others only return the caller's own data. Error messages are sent as message
identifiers with arguments, which `enzimos-mountd` translates; this interface
is not for other clients.

* `MountSmb(a{sv} params, h secret) → s path`. Params are `host`, `share`,
  `path`, `port`, `username`, `domain`, `version` and `label`. With `version`
  `1.0`, the first mount of that server by that user also needs
  `org.enzimos.mount.smb1` (administrator).
* `MountNfs(a{sv} params) → s path`.
* `PrepareMountpoint(s label) → s path`: a fresh folder owned by the caller,
  for a FUSE mount. Labels are at most 255 bytes.
* `Unmount(s path, b force)`: only folders this service created for the same
  caller. Unmounts kernel mounts and removes the folder.
* `List() → s`: the caller's registered mounts.
* `SetBootMount(a{sv} params, h secret, b enabled)` and `BootMounts() → s`:
  the caller's startup shares. Storing one needs `org.enzimos.mount.boot-mount`
  (administrator, every time; the dialog names server and share).
  The owner may update only the password of an entry that already exists,
  with the ordinary `org.enzimos.mount.user-mount` action. Any new or changed
  entry needs administrator approval again.
* `Capabilities() → a{sb}`.
