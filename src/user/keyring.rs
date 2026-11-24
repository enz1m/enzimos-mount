//! Location passwords in the user's Secret Service keyring (oo7 on enzimOS,
//! unlocked at login through `pam_oo7`).
//!
//! The service opens a keyring connection on first use. Calls that can show an
//! unlock prompt have a longer deadline than noninteractive calls.
//!
//! Items carry the location identity and also protocol, server and user, so
//! another share on the same server with the same account finds the password
//! without asking again. A location keeps items for one user only.

use crate::secret::Secret;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

/// Schema attribute value identifying our items.
pub const SCHEMA: &str = "org.enzimos.Mount.Password";
const CALL_TIMEOUT: Duration = Duration::from_secs(10);
const UNLOCK_TIMEOUT: Duration = Duration::from_secs(90);

/// Who a password belongs to.
#[derive(Clone, Debug)]
pub struct Account<'a> {
    /// Location identity.
    pub id: &'a str,
    /// `smb`, `sftp`, …
    pub protocol: &'a str,
    /// Server host.
    pub server: &'a str,
    /// User name.
    pub user: &'a str,
}

static KEYRING: Mutex<Option<Arc<oo7::Keyring>>> = Mutex::const_new(None);

async fn with_keyring<T>(
    action: impl AsyncFnOnce(&oo7::Keyring) -> oo7::Result<T>,
    deadline: Duration,
) -> Option<T> {
    let connection = tokio::time::timeout(CALL_TIMEOUT, async {
        let mut slot = KEYRING.lock().await;
        if let Some(keyring) = &*slot {
            return Ok(Arc::clone(keyring));
        }
        let keyring = Arc::new(oo7::Keyring::new().await?);
        *slot = Some(Arc::clone(&keyring));
        Ok::<_, oo7::Error>(keyring)
    })
    .await;
    let keyring = match connection {
        Ok(Ok(keyring)) => keyring,
        Ok(Err(error)) => {
            crate::log!(info, "keyring unavailable: {error}");
            return None;
        }
        Err(_) => {
            crate::log!(warn, "keyring did not answer");
            return None;
        }
    };
    match tokio::time::timeout(deadline, action(&keyring)).await {
        Ok(Ok(value)) => Some(value),
        Ok(Err(error)) => {
            crate::log!(info, "keyring call failed: {error}");
            let mut slot = KEYRING.lock().await;
            if slot
                .as_ref()
                .is_some_and(|cached| Arc::ptr_eq(cached, &keyring))
            {
                *slot = None;
            }
            None
        }
        Err(_) => None,
    }
}

/// Whether a Secret Service is available, without starting or contacting it.
pub async fn available(session: &zbus::Connection) -> bool {
    let Ok(dbus) = zbus::fdo::DBusProxy::new(session).await else {
        return false;
    };
    let name = zbus::names::BusName::try_from("org.freedesktop.secrets").ok();
    if let Some(name) = name
        && dbus.name_has_owner(name).await.unwrap_or(false)
    {
        return true;
    }
    dbus.list_activatable_names().await.is_ok_and(|names| {
        names
            .iter()
            .any(|n| n.as_str() == "org.freedesktop.secrets")
    })
}

async fn find(attributes: HashMap<&str, &str>) -> Option<Secret> {
    with_keyring(
        async move |keyring| {
            let items = keyring.search_items(&attributes).await?;
            let Some(item) = items.into_iter().next() else {
                return Ok(None);
            };
            if item.is_locked().await.unwrap_or(true) {
                item.unlock().await?;
            }
            Ok(Some(Secret::new(item.secret().await?.as_bytes().to_vec())))
        },
        UNLOCK_TIMEOUT,
    )
    .await
    .flatten()
}

/// The stored password for this account at this location, or for the same
/// account on the same server.
pub async fn lookup(account: &Account<'_>) -> Option<Secret> {
    if account.user.is_empty() {
        return None;
    }
    if let Some(secret) = find(HashMap::from([
        ("xdg:schema", SCHEMA),
        ("location", account.id),
        ("user", account.user),
    ]))
    .await
    {
        return Some(secret);
    }
    find(HashMap::from([
        ("xdg:schema", SCHEMA),
        ("protocol", account.protocol),
        ("server", account.server),
        ("user", account.user),
    ]))
    .await
}

/// Store the password for this location, replacing any stored for another
/// user there.
///
/// # Errors
/// A sentence when the keyring refused or did not answer.
pub async fn store(
    account: &Account<'_>,
    uri: &str,
    label: &str,
    secret: &Secret,
) -> Result<(), String> {
    let attributes = HashMap::from([
        ("xdg:schema", SCHEMA),
        ("location", account.id),
        ("protocol", account.protocol),
        ("server", account.server),
        ("user", account.user),
        ("uri", uri),
    ]);
    let title = crate::tr!("keyring-item-title", label = label);
    with_keyring(
        async move |keyring| {
            if keyring.is_locked().await.unwrap_or(false) {
                keyring.unlock().await?;
            }
            keyring
                .create_item(
                    &title,
                    &attributes,
                    oo7::Secret::blob(secret.expose()),
                    true,
                )
                .await?;
            if let Err(error) = delete_other_users(keyring, account.id, account.user).await {
                crate::log!(info, "keyring cleanup failed: {error}");
            }
            Ok(())
        },
        UNLOCK_TIMEOUT,
    )
    .await
    .ok_or_else(|| crate::tr!("error-keyring-store"))
}

async fn delete_other_users(keyring: &oo7::Keyring, id: &str, user: &str) -> oo7::Result<()> {
    let attributes = HashMap::from([("xdg:schema", SCHEMA), ("location", id)]);
    for item in keyring.search_items(&attributes).await? {
        if item.attributes().await?.get("user").map(String::as_str) != Some(user) {
            item.delete().await?;
        }
    }
    Ok(())
}

/// Forget the passwords stored at location `id` for any user but `user`.
pub async fn forget_other_users(id: &str, user: &str) {
    let _ = with_keyring(
        async move |keyring| delete_other_users(keyring, id, user).await,
        CALL_TIMEOUT,
    )
    .await;
}

/// Forget the password for location `id`.
pub async fn forget(id: &str) {
    let attributes = HashMap::from([("xdg:schema", SCHEMA), ("location", id)]);
    let _ = with_keyring(
        async move |keyring| keyring.delete(&attributes).await,
        CALL_TIMEOUT,
    )
    .await;
}
