//! D-Bus errors shared by both services. Names match [`crate::api::errors`].

/// A failed request. The message is a user-presentable sentence, or JSON for
/// [`Error::NeedsCredentials`] and the host-key variants.
#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "org.enzimos.Mount1.Error")]
pub enum Error {
    /// Transport error.
    #[zbus(error)]
    ZBus(zbus::Error),
    /// Credentials are needed.
    NeedsCredentials(String),
    /// Credentials were refused.
    AuthFailed(String),
    /// The SFTP host key is unknown.
    HostKeyUnknown(String),
    /// The SFTP host key changed.
    HostKeyChanged(String),
    /// No answer from the server or device.
    Unreachable(String),
    /// Deadline passed.
    Timeout(String),
    /// Files are open on the mount.
    Busy(String),
    /// Unknown identity.
    NotFound(String),
    /// Missing helper.
    Unsupported(String),
    /// Authorization refused.
    NotAuthorized(String),
    /// The phone must be unlocked or trust this computer.
    DeviceLocked(String),
    /// Malformed request.
    Invalid(String),
    /// A share must be chosen (JSON body).
    ChooseShare(String),
    /// The server needs an older SMB dialect.
    ProtocolMismatch(String),
    /// Anything else.
    Failed(String),
}

impl Error {
    /// The user-presentable message.
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::ZBus(e) => e.to_string(),
            Self::NeedsCredentials(m)
            | Self::AuthFailed(m)
            | Self::HostKeyUnknown(m)
            | Self::HostKeyChanged(m)
            | Self::Unreachable(m)
            | Self::Timeout(m)
            | Self::Busy(m)
            | Self::NotFound(m)
            | Self::Unsupported(m)
            | Self::NotAuthorized(m)
            | Self::DeviceLocked(m)
            | Self::Invalid(m)
            | Self::ChooseShare(m)
            | Self::ProtocolMismatch(m)
            | Self::Failed(m) => m.clone(),
        }
    }

    /// Rebuild an error a remote service returned, keeping its kind.
    #[must_use]
    pub fn from_remote(error: zbus::Error) -> Self {
        if let zbus::Error::MethodError(name, message, _) = &error {
            // Root-service messages arrive untranslated; translate them here.
            let message = crate::i18n::render(message.as_deref().unwrap_or_default());
            let suffix = name.as_str().rsplit('.').next().unwrap_or_default();
            if name.as_str().starts_with("org.enzimos.Mount1.Error.") {
                return match suffix {
                    "NeedsCredentials" => Self::NeedsCredentials(message),
                    "AuthFailed" => Self::AuthFailed(message),
                    "HostKeyUnknown" => Self::HostKeyUnknown(message),
                    "HostKeyChanged" => Self::HostKeyChanged(message),
                    "Unreachable" => Self::Unreachable(message),
                    "Timeout" => Self::Timeout(message),
                    "Busy" => Self::Busy(message),
                    "NotFound" => Self::NotFound(message),
                    "Unsupported" => Self::Unsupported(message),
                    "NotAuthorized" => Self::NotAuthorized(message),
                    "DeviceLocked" => Self::DeviceLocked(message),
                    "Invalid" => Self::Invalid(message),
                    "ChooseShare" => Self::ChooseShare(message),
                    "ProtocolMismatch" => Self::ProtocolMismatch(message),
                    _ => Self::Failed(message),
                };
            }
            if name.as_str() == "org.freedesktop.DBus.Error.ServiceUnknown"
                || name.as_str() == "org.freedesktop.DBus.Error.NameHasNoOwner"
            {
                return Self::Unsupported(crate::tr!("error-system-service-missing"));
            }
            if name.as_str().ends_with("NotAuthorized") || name.as_str().ends_with("AccessDenied") {
                return Self::NotAuthorized(message);
            }
            if name.as_str().ends_with("NoReply") || name.as_str().ends_with("Timeout") {
                return Self::Timeout(crate::tr!("error-system-service-timeout"));
            }
            return Self::Failed(message);
        }
        Self::ZBus(error)
    }
}

/// Result alias.
pub type Result<T> = std::result::Result<T, Error>;
