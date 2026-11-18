//! Network location addresses.
//!
//! Addresses come from users and from the network, and parts of them end up as
//! helper arguments (`sshfs host:path`) and kernel mount options. Parsing is
//! strict: hosts and user names may not start with `-`, contain whitespace,
//! control characters or separators, and passwords are never accepted inside an
//! address.

use std::fmt;

/// Supported protocols.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scheme {
    /// SMB/CIFS, mounted by the kernel.
    Smb,
    /// SFTP, mounted with `sshfs`.
    Sftp,
    /// NFS, mounted by the kernel.
    Nfs,
    /// WebDAV over HTTP, mounted with `rclone`.
    Dav,
    /// WebDAV over HTTPS, mounted with `rclone`.
    Davs,
    /// FTP, mounted with `rclone`.
    Ftp,
    /// FTP over TLS, mounted with `rclone`.
    Ftps,
}

impl Scheme {
    /// The canonical URI scheme.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Smb => "smb",
            Self::Sftp => "sftp",
            Self::Nfs => "nfs",
            Self::Dav => "dav",
            Self::Davs => "davs",
            Self::Ftp => "ftp",
            Self::Ftps => "ftps",
        }
    }

    fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "smb" | "cifs" => Self::Smb,
            "sftp" | "ssh" => Self::Sftp,
            "nfs" => Self::Nfs,
            "dav" | "webdav" | "http" => Self::Dav,
            "davs" | "webdavs" | "https" => Self::Davs,
            "ftp" => Self::Ftp,
            "ftps" => Self::Ftps,
            _ => return None,
        })
    }

    /// Whether this protocol can authenticate with a password.
    #[must_use]
    pub const fn uses_password(self) -> bool {
        !matches!(self, Self::Nfs)
    }
}

/// A parsed, validated network address without any secret.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NetUri {
    /// Protocol.
    pub scheme: Scheme,
    /// Host name or IP address (IPv6 without brackets).
    pub host: String,
    /// Explicit port.
    pub port: Option<u16>,
    /// User name, if given.
    pub user: Option<String>,
    /// SMB domain or workgroup, from `smb://DOMAIN;user@host/`.
    pub domain: Option<String>,
    /// SMB share name (first path segment); empty for a server address.
    pub share: String,
    /// Remaining path, `/`-separated without leading slash.
    pub path: String,
}

/// Why an address was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UriError(pub String);

impl fmt::Display for UriError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for UriError {}

fn err(message: String) -> UriError {
    UriError(message)
}

/// Longest accepted address.
pub const MAX_URI_BYTES: usize = 2048;

fn decode(part: &str) -> Result<String, UriError> {
    let decoded = url::form_urlencoded::parse(format!("x={}", part.replace('+', "%2B")).as_bytes())
        .next()
        .map(|(_, value)| value.into_owned())
        .unwrap_or_default();
    if decoded.chars().any(char::is_control) {
        return Err(err(crate::tr!("uri-control-characters")));
    }
    Ok(decoded)
}

/// `user@host:/path` or `host:path` (as typed for scp/ssh) means SFTP.
fn scp_form(input: &str) -> Option<String> {
    if input.contains("://") || input.starts_with('\\') {
        return None;
    }
    let (left, path) = input.split_once(':')?;
    let host = left.rsplit('@').next()?;
    // `host:445` style ports and IPv6 literals are not the scp form.
    if path.is_empty()
        || path.bytes().all(|b| b.is_ascii_digit())
        || host.contains(['/', '[', ']'])
        || !left.contains('@') && !path.starts_with(['/', '~'])
    {
        return None;
    }
    let path = path.trim_start_matches('~').trim_start_matches('/');
    Some(format!("sftp://{left}/{path}"))
}

/// A host name or address safe to pass as an argument.
#[must_use]
pub fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && !host.starts_with(['-', '.'])
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'))
}

/// A user, domain or share name safe to pass as an argument or option value.
#[must_use]
pub fn valid_name(name: &str, max: usize) -> bool {
    !name.is_empty()
        && name.len() <= max
        && !name.starts_with('-')
        && !name
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() && c != ' ')
        && !name.contains(['/', '\\', '@', ':', ',', ';', '=', '"', '\0'])
}

impl NetUri {
    /// Parse a user-entered address. A bare `host/share` or `\\host\share` is
    /// read as SMB, as people type it from Windows habit.
    ///
    /// # Errors
    /// A [`UriError`] with a user-presentable sentence.
    pub fn parse(input: &str) -> Result<Self, UriError> {
        let input = input.trim();
        if input.is_empty() {
            return Err(err(crate::tr!("uri-empty")));
        }
        if input.len() > MAX_URI_BYTES {
            return Err(err(crate::tr!("uri-too-long")));
        }
        let owned;
        let text = if let Some(scp) = scp_form(input) {
            owned = scp;
            owned.as_str()
        } else if let Some(unc) = input.strip_prefix("\\\\") {
            owned = format!("smb://{}", unc.replace('\\', "/"));
            owned.as_str()
        } else if input.contains("://") {
            input
        } else {
            owned = format!("smb://{input}");
            owned.as_str()
        };
        // The URL parser silently resolves dot segments; refuse them instead.
        let lower = text.to_ascii_lowercase();
        if lower
            .split('/')
            .skip(3)
            .any(|s| matches!(s, "." | ".." | "%2e" | "%2e%2e" | ".%2e" | "%2e."))
        {
            return Err(err(crate::tr!("uri-bad-path")));
        }
        let parsed = url::Url::parse(text).map_err(|_| err(crate::tr!("uri-not-valid")))?;
        let scheme = Scheme::parse(parsed.scheme()).ok_or_else(|| err(crate::tr!("uri-scheme")))?;
        if parsed.password().is_some() {
            return Err(err(crate::tr!("uri-password")));
        }
        if parsed.query().is_some() || parsed.fragment().is_some() {
            return Err(err(crate::tr!("uri-query")));
        }
        let host = match parsed.host() {
            Some(url::Host::Domain(name)) => name.to_ascii_lowercase(),
            Some(url::Host::Ipv4(addr)) => addr.to_string(),
            Some(url::Host::Ipv6(addr)) => addr.to_string(),
            None => return Err(err(crate::tr!("uri-no-host"))),
        };
        if !valid_host(&host) {
            return Err(err(crate::tr!("uri-bad-host")));
        }
        let (domain, user) = match parsed.username() {
            "" => (None, None),
            raw => {
                let raw = decode(raw)?;
                let (domain, user) = match raw.split_once(';') {
                    Some((domain, user)) if scheme == Scheme::Smb => {
                        (Some(domain.to_owned()), user.to_owned())
                    }
                    _ => (None, raw),
                };
                if !valid_name(&user, 128) || domain.as_deref().is_some_and(|d| !valid_name(d, 64))
                {
                    return Err(err(crate::tr!("uri-bad-user")));
                }
                (domain, Some(user))
            }
        };
        let mut segments = Vec::new();
        for segment in parsed.path_segments().into_iter().flatten() {
            if segment.is_empty() {
                continue;
            }
            let segment = decode(segment)?;
            if segment == "." || segment == ".." || segment.contains('/') {
                return Err(err(crate::tr!("uri-bad-path")));
            }
            segments.push(segment);
        }
        let (share, path) = if scheme == Scheme::Smb {
            let mut rest = segments.into_iter();
            let share = rest.next().unwrap_or_default();
            if !share.is_empty() && !valid_name(&share, 80) {
                return Err(err(crate::tr!("uri-bad-share")));
            }
            (share, rest.collect::<Vec<_>>().join("/"))
        } else {
            (String::new(), segments.join("/"))
        };
        Ok(Self {
            scheme,
            host,
            port: parsed.port(),
            user,
            domain,
            share,
            path,
        })
    }

    /// The address without credentials, for display and storage.
    #[must_use]
    pub fn display(&self) -> String {
        let mut out = format!("{}://", self.scheme.as_str());
        if let Some(user) = &self.user {
            let encode = |s: &str| {
                url::form_urlencoded::byte_serialize(s.as_bytes())
                    .collect::<String>()
                    .replace('+', "%20")
            };
            if let Some(domain) = &self.domain {
                out.push_str(&encode(domain));
                out.push(';');
            }
            out.push_str(&encode(user));
            out.push('@');
        }
        if self.host.contains(':') {
            out.push('[');
            out.push_str(&self.host);
            out.push(']');
        } else {
            out.push_str(&self.host);
        }
        if let Some(port) = self.port {
            out = format!("{out}:{port}");
        }
        out.push('/');
        let mut parts: Vec<&str> = Vec::new();
        if !self.share.is_empty() {
            parts.push(&self.share);
        }
        if !self.path.is_empty() {
            parts.push(&self.path);
        }
        let joined = parts.join("/");
        for (i, segment) in joined.split('/').filter(|s| !s.is_empty()).enumerate() {
            if i > 0 {
                out.push('/');
            }
            out.push_str(
                &url::form_urlencoded::byte_serialize(segment.as_bytes())
                    .collect::<String>()
                    .replace('+', "%20"),
            );
        }
        out
    }

    /// The same address with a different user.
    #[must_use]
    pub fn with_user(&self, user: Option<String>, domain: Option<String>) -> Self {
        Self {
            user,
            domain,
            ..self.clone()
        }
    }

    /// A short default label: `share on host` or the host.
    #[must_use]
    pub fn label(&self) -> String {
        let last = self.path.rsplit('/').find(|s| !s.is_empty());
        match (self.share.is_empty(), last) {
            (_, Some(last)) => crate::tr!("label-folder-on-host", folder = last, host = &self.host),
            (false, None) => crate::tr!(
                "label-folder-on-host",
                folder = &self.share,
                host = &self.host
            ),
            (true, None) => match self.scheme {
                Scheme::Smb | Scheme::Nfs => self.host.clone(),
                Scheme::Sftp => crate::tr!(
                    "label-protocol-on-host",
                    protocol = "SFTP",
                    host = &self.host
                ),
                Scheme::Dav | Scheme::Davs => crate::tr!(
                    "label-protocol-on-host",
                    protocol = "WebDAV",
                    host = &self.host
                ),
                Scheme::Ftp | Scheme::Ftps => crate::tr!(
                    "label-protocol-on-host",
                    protocol = "FTP",
                    host = &self.host
                ),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_parse_strictly_and_never_carry_secrets() {
        let smb = NetUri::parse("smb://WORK;alice@NAS.local/Photos/2026/trip").unwrap();
        assert_eq!(
            (
                smb.scheme,
                smb.host.as_str(),
                smb.domain.as_deref(),
                smb.user.as_deref()
            ),
            (Scheme::Smb, "nas.local", Some("WORK"), Some("alice")),
            "domain;user split and host case"
        );
        assert_eq!(
            (smb.share.as_str(), smb.path.as_str()),
            ("Photos", "2026/trip"),
            "share and subpath"
        );
        assert_eq!(
            smb.display(),
            "smb://WORK;alice@nas.local/Photos/2026/trip",
            "round trip"
        );
        assert_eq!(
            NetUri::parse(&smb.display()).unwrap(),
            smb,
            "display reparses"
        );

        let unc = NetUri::parse(r"\\server\share").unwrap();
        assert_eq!(
            (unc.scheme, unc.share.as_str()),
            (Scheme::Smb, "share"),
            "UNC form"
        );
        let scp = NetUri::parse("bob@files.example:/srv/data").unwrap();
        assert_eq!(
            (scp.scheme, scp.user.as_deref(), scp.path.as_str()),
            (Scheme::Sftp, Some("bob"), "srv/data"),
            "scp form"
        );
        assert_eq!(
            NetUri::parse("nas:445").map(|u| u.scheme),
            Ok(Scheme::Smb),
            "host:port stays SMB"
        );
        let bare = NetUri::parse("192.168.1.5/music").unwrap();
        assert_eq!(
            (bare.host.as_str(), bare.share.as_str()),
            ("192.168.1.5", "music"),
            "bare form"
        );
        let v6 = NetUri::parse("sftp://bob@[fe80::1]:2222/srv/data").unwrap();
        assert_eq!(
            (v6.host.as_str(), v6.port, v6.path.as_str()),
            ("fe80::1", Some(2222), "srv/data"),
            "IPv6"
        );
        assert_eq!(
            v6.display(),
            "sftp://bob@[fe80::1]:2222/srv/data",
            "IPv6 display"
        );
        let spaced = NetUri::parse("smb://nas/My%20Files").unwrap();
        assert_eq!(spaced.share, "My Files", "percent-decoded share");
        assert_eq!(
            NetUri::parse(&spaced.display()).unwrap().share,
            "My Files",
            "space round trip"
        );

        for refused in [
            "smb://alice:secret@nas/share",
            "sftp://-oProxyCommand=evil/x",
            "sftp://%2DoProxyCommand@host/",
            "smb://nas/share/../etc",
            "smb://nas/sh%0Aare",
            "gopher://nas/",
            "smb://nas/share?x=1",
            "smb://user,uid=0@nas/share",
            "",
        ] {
            assert!(NetUri::parse(refused).is_err(), "must refuse {refused:?}");
        }
    }
}
