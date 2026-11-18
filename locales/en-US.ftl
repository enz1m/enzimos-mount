# enzimos-mount: messages shown to people (errors, item names, notifications).
# Every other catalog must define exactly these messages.

## Item names and details

label-folder-on-host = { $folder } on { $host }
label-protocol-on-host = { $protocol } on { $host }
label-phone = Phone
label-camera = Camera
label-ios-detail = iPhone or iPad
label-volume = Volume
label-sized-volume = { $size } Volume
label-disk-image = Disk Image
label-optical-drive = Optical Drive
size-bytes = { $count ->
    [one] { $count } byte
   *[other] { $count } bytes
}
number-decimal-separator = { "." }
keyring-item-title = Network location “{ $label }”
feature-phones = Phone support
feature-share-browsing = Share browsing

feature-sftp = SFTP support
feature-webdav-ftp = WebDAV and FTP support
## Notifications

notify-app-name = Devices
notify-connected = { $device } connected
notify-connected-phone = Unlock it and choose “File transfer” in its USB settings to see its files.
notify-connected-ios = Unlock it and tap “Trust” if asked, then open it to see its photos.
notify-connected-camera = Open it to see its photos.
notify-disconnected = { $device } disconnected
notify-disconnected-body = The connection ended unexpectedly. Files on it are no longer available.
notify-attention = { $device } needs your attention
notify-attention-sign-in = Open it in Files to sign in.
notify-attention-identity = Open it in Files to check the server’s identity.
notify-open-failed = { $device } could not be opened
notify-trust = Trust this computer on { $device }
notify-trust-body = Unlock the iPhone and tap “Trust”. Its photos open as soon as you do.
notify-unplug = { $device } can be unplugged
notify-unplug-body = Its files are closed.
notify-not-responding = { $device } is not responding
notify-not-responding-body = Files on it cannot be opened until it answers again. You can disconnect it.
notify-auto-failed = { $device } did not connect
notify-auto-password = It needs your password before it can connect automatically. Open it in Files to sign in.
notify-auto-identity = The server’s identity must be confirmed. Open it in Files to check it.
action-open = Open
action-reconnect = Reconnect
action-try-again = Try Again
action-disconnect = Disconnect

## Addresses

uri-control-characters = The address contains control characters
uri-empty = Enter a server address
uri-too-long = The address is too long
uri-not-valid = The address is not valid
uri-scheme = Use smb://, sftp://, nfs://, dav://, davs://, ftp:// or ftps://
uri-password = Do not put a password in the address; you will be asked for it
uri-query = The address may not contain ? or #
uri-no-host = The address has no server name
uri-bad-host = The server name is not valid
uri-bad-user = The user name is not valid
uri-bad-path = The folder path is not valid
uri-bad-share = The share name is not valid

## Errors

error-system-service-missing = The system mount service is not installed
error-system-service-timeout = The system mount service did not answer in time
error-no-system-bus = The system bus is not available
error-password-not-text = The password is not valid text
error-password-line-break = The password contains a line break or NUL character
error-secret-not-memfd = The secret must be a sealed memory file
error-secret-not-sealed = The secret memory file is not sealed
error-secret-too-large = The secret is too large
error-keyring-store = The keyring did not store the password
error-invalid-field = The request is not valid ({ $field })
error-item-busy = Another operation on this item is still running
error-no-such-item = There is no such item
error-no-such-location = There is no such network location
error-too-many-locations = Too many network locations
error-files-open = Files on it are still open; close them and try again
error-busy-programs = Files on it are open in { $programs }. Close them and try again, or disconnect anyway.
error-missing-helper = { $feature } ({ $helper }) is not installed
error-helper-start = Could not start the helper: { $error }
error-helper-timeout = The device or server did not respond in time
error-cancelled = Cancelled

error-format-label = That name is too long or uses characters this file system does not allow
error-not-formattable = Only drives that can be unplugged can be formatted here; use Settings for internal disks
error-drive-busy = Files on the drive are still open; close them and try again
error-drive-not-allowed = Not allowed to change this drive
error-drive-gone = The drive is gone
error-drive-timeout = The drive did not respond in time
error-udisks-missing = The drive service (UDisks2) is not available
error-udisks-timeout = The drive service did not answer
error-passphrase-refused = The passphrase was not accepted
error-unlock-first = Unlock the drive first
error-no-filesystem = The unlocked drive has no file system
error-no-disc = There is no disc in the drive
error-not-removable = This volume is not on a removable drive
error-image-open = Cannot open the image: { $error }
error-not-image = Not a disk image file
error-image-no-filesystem = The image has no file system this computer can read

error-phone-no-files = The phone is not offering its files. Unlock it and choose “File transfer” in its USB settings
error-phone-busy = Another program is using the phone
error-phone-not-allowed = This account may not access the phone’s USB connection
error-phone-locked = Unlock the phone and allow file access, then try again
error-phone-failed = The phone could not be opened: { $detail }
error-phone-gone = The phone is no longer connected
error-iphone-trust = Unlock your iPhone and tap “Trust”, then try again
error-iphone-not-ready = The iPhone is not ready; unlock it and try again
error-iphone-gone = The iPhone is no longer connected
error-usbmuxd-missing = The iPhone connection service (usbmuxd) is not running
error-iphone-pair-failed = The iPhone could not be paired: { $detail }
error-iphone-failed = The iPhone could not be opened: { $detail }

error-login-refused = The user name or password was not accepted
error-server-no-answer = The server “{ $host }” did not answer
error-server-no-answer-unnamed = The server did not answer
error-server-not-found = Could not find the server “{ $host }” on the network
error-server-timeout = The server did not answer in time
error-certificate = The server’s certificate is not trusted
error-location-failed = The location could not be opened ({ $code }): { $detail }
error-sftp-failed = The SFTP connection failed
error-no-such-folder = The folder does not exist on the server
error-not-sftp = Only SFTP locations have host keys
error-host-key-moved = The server’s key no longer matches the one you confirmed
error-not-smb = Only SMB servers have shares
error-choose-share = Choose a share first
error-no-such-share = The server has no share named “{ $share }”
error-no-cifs = This system’s kernel has no SMB client
error-smb1-only = “{ $host }” only speaks an older, less secure SMB version (SMB1). Allow it for this location to connect.
error-share-failed = The share could not be mounted: { $detail }
error-nfs-missing = NFS support is not installed
error-export-refused = The server refused access to this export
error-export-failed = The export could not be mounted: { $detail }

error-unknown-user = Unknown user
error-unknown-caller = The request did not come from a known program
error-authorization-timeout = Authorization timed out
error-authorization-failed = Authorization failed: { $error }
error-not-allowed = You are not allowed to mount here
error-registry = The mount service cannot read its list of mounts; see the system log
error-too-many-pending = Too many connections are being set up at once; wait for them to finish
error-service-busy = The mount service is busy; try again in a moment
error-too-many-mounts = Too many mounts are open
error-shutting-down = The mount service is shutting down
error-worker-failed = The mount helper failed: { $detail }
error-not-your-mount = This mount was not made for you by the mount service
error-detach-failed = The mount could not be detached
error-unmount-busy = Files on it are still open, or the server is not answering; close them, or force the unmount
error-unmount-failed = Could not unmount: { $detail }
error-user-folder = The user name cannot name a media folder
error-mount-folder = Could not create the mount folder: { $error }
error-mount-folder-name = Could not choose a free mount folder name

error-startup-protocol = Only SMB and NFS locations can be mounted at startup
error-startup-too-many = Too many shares are set to mount at startup
error-startup-store = The password could not be stored: { $detail }
error-startup-decrypt = The stored password could not be decrypted

## Cloud drives

feature-cloud = Cloud drive support
cloud-signing-in-detail = Finish signing in in your browser
notify-cloud-failed = { $service } was not added
error-cloud-denied = The sign-in was cancelled or refused
error-cloud-unreachable = The service could not be reached; check the internet connection
error-cloud-failed = The account could not be added
error-cloud-timeout = The sign-in was not finished in time
error-cloud-google-unavailable = Google Drive is not available on this computer yet
error-cloud-unavailable = { $service } cannot be added on this computer
error-cloud-server-invalid = Enter your Nextcloud server's address, such as cloud.example.com
error-cloud-server-https = Use an https:// address for a server on the internet
error-cloud-not-nextcloud = That server did not answer as a Nextcloud server
error-cloud-one-at-a-time = Finish the sign-in that is already open first
