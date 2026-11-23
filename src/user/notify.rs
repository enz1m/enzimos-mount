//! Desktop notifications (org.freedesktop.Notifications, served by the shell).
//!
//! The shell already announces USB drives, cards and discs from UDisks2, so
//! this service only speaks about what the shell cannot see: phones, iPhones
//! and cameras arriving, and network locations that need attention (a server
//! not responding, an unexpected disconnect, a saved location that needs a
//! password or a host-key confirmation before it can reconnect). One
//! notification per item is kept and replaced, and closed when moot.

use std::collections::HashMap;
use std::time::Duration;
use tokio::sync::Mutex;
use zbus::Variant;

const DEST: &str = "org.freedesktop.Notifications";
const PATH: &str = "/org/freedesktop/Notifications";
const CALL_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Default)]
struct NotificationIds {
    by_item: HashMap<String, u32>,
    by_id: HashMap<u32, String>,
}

impl NotificationIds {
    fn record(&mut self, item: &str, id: u32) {
        self.remove_item(item);
        self.remove_id(id);
        self.by_item.insert(item.to_owned(), id);
        self.by_id.insert(id, item.to_owned());
    }

    fn remove_item(&mut self, item: &str) -> Option<u32> {
        let id = self.by_item.remove(item)?;
        self.by_id.remove(&id);
        Some(id)
    }

    fn remove_id(&mut self, id: u32) {
        if let Some(item) = self.by_id.remove(&id) {
            self.by_item.remove(&item);
        }
    }
}

/// What a notification action asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Mount (if needed) and open the item's folder.
    Open,
    /// Mount again.
    Retry,
    /// Force-unmount.
    Disconnect,
}

impl Action {
    const fn key(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Retry => "retry",
            Self::Disconnect => "disconnect",
        }
    }

    fn parse(key: &str) -> Option<Self> {
        Some(match key {
            "open" | "default" => Self::Open,
            "retry" => Self::Retry,
            "disconnect" => Self::Disconnect,
            _ => return None,
        })
    }
}

/// One notification to show.
#[derive(Debug)]
pub struct Note<'a> {
    /// Item it is about; a newer note for the same item replaces it.
    pub item: &'a str,
    /// Title.
    pub summary: String,
    /// Body.
    pub body: String,
    /// Freedesktop icon name.
    pub icon: &'a str,
    /// Buttons with their labels.
    pub actions: &'a [(Action, String)],
    /// Stays until dismissed (otherwise transient).
    pub lasting: bool,
    /// Freedesktop category hint.
    pub category: &'a str,
}

/// Sends notifications and maps their actions back to items.
pub struct Notifier {
    connection: zbus::Connection,
    // Keep the RPC and ID update ordered with withdrawals and signals.
    ids: Mutex<NotificationIds>,
}

impl Notifier {
    /// Use the session `connection`.
    #[must_use]
    pub fn new(connection: zbus::Connection) -> Self {
        Self {
            connection,
            ids: Mutex::default(),
        }
    }

    async fn proxy(&self) -> Option<zbus::Proxy<'static>> {
        zbus::Proxy::new_owned(self.connection.clone(), DEST, PATH, DEST)
            .await
            .ok()
    }

    /// Show `note`, replacing the item's previous notification.
    pub async fn show(&self, note: &Note<'_>) {
        let mut ids = self.ids.lock().await;
        let Some(proxy) = self.proxy().await else {
            return;
        };
        let replaces = ids.by_item.get(note.item).copied().unwrap_or(0);
        let mut actions: Vec<&str> = Vec::new();
        for (action, label) in note.actions {
            actions.push(action.key());
            actions.push(label);
        }
        if note.actions.iter().any(|(a, _)| *a == Action::Open) {
            // Clicking the notification itself opens the item too.
            actions.extend(["default", ""]);
        }
        let mut hints: HashMap<&str, Variant<'_>> = HashMap::new();
        hints.insert("category", Variant::from(note.category));
        hints.insert("desktop-entry", Variant::from("io.github.enzui.Files"));
        if !note.lasting {
            hints.insert("transient", Variant::from(true));
        }
        let app = crate::tr!("notify-app-name");
        let body = (
            app.as_str(),
            replaces,
            note.icon,
            note.summary.as_str(),
            note.body.as_str(),
            actions,
            hints,
            -1i32,
        );
        let call = proxy.call::<_, _, u32>("Notify", &body);
        match tokio::time::timeout(CALL_TIMEOUT, call).await {
            Ok(Ok(id)) => ids.record(note.item, id),
            Ok(Err(error)) => crate::log!(debug, "notification not shown: {error}"),
            Err(_) => crate::log!(debug, "notification service did not answer"),
        }
    }

    /// Withdraw the item's notification, if any.
    pub async fn close(&self, item: &str) {
        let mut ids = self.ids.lock().await;
        if let Some(id) = ids.remove_item(item)
            && let Some(proxy) = self.proxy().await
        {
            let _ = tokio::time::timeout(
                CALL_TIMEOUT,
                proxy.call::<_, _, ()>("CloseNotification", &(id,)),
            )
            .await;
        }
    }

    /// Notification signals (actions and closes) for [`Self::interpret`].
    ///
    /// # Errors
    /// When the signal subscription fails.
    pub async fn actions(&self) -> zbus::Result<zbus::MessageStream> {
        let rule = zbus::MatchRule::builder()
            .msg_type(zbus::message::Type::Signal)
            .interface(DEST)
            .path(PATH)
            .build()?;
        zbus::MessageStream::for_match_rule(rule, &self.connection, std::num::NonZeroUsize::new(32))
            .await
    }

    /// Interpret a Notifications signal: an action on one of ours, or a close.
    pub async fn interpret(&self, message: &zbus::Message) -> Option<(String, Action)> {
        match message.header().member()?.as_str() {
            "NotificationClosed" => {
                let (id, _reason) = message.body().deserialize::<(u32, u32)>().ok()?;
                self.ids.lock().await.remove_id(id);
                None
            }
            "ActionInvoked" => {
                let (id, key) = message.body().deserialize::<(u32, String)>().ok()?;
                let action = Action::parse(&key)?;
                let item = self.ids.lock().await.by_id.get(&id).cloned()?;
                Some((item, action))
            }
            _ => None,
        }
    }
}

/// Open a folder with the desktop's file manager.
pub async fn open_folder(path: &std::path::Path) {
    let Some(gio) = crate::process::helper("gio").or_else(|| crate::process::helper("xdg-open"))
    else {
        return;
    };
    let mut spec = crate::process::Spec::new(&gio, Duration::from_secs(15));
    if gio.ends_with("gio") {
        spec = spec.arg("open");
    }
    // Plain local GIO: a mount helper never starts GVfs daemons where they exist.
    spec = spec.env("GIO_USE_VFS", "local");
    for key in [
        "WAYLAND_DISPLAY",
        "DISPLAY",
        "XDG_CURRENT_DESKTOP",
        "XDG_DATA_DIRS",
    ] {
        if let Some(value) = std::env::var_os(key) {
            spec = spec.env(key, value);
        }
    }
    let _ = crate::process::run(spec.arg(path)).await;
}

/// The arrival notification for a USB device kind.
#[must_use]
pub fn arrival(kind: crate::api::Kind, label: &str) -> (String, String, &'static str) {
    use crate::api::Kind;
    match kind {
        Kind::Ios => (
            crate::tr!("notify-connected", device = label),
            crate::tr!("notify-connected-ios"),
            "phone-apple-iphone",
        ),
        Kind::Camera => (
            crate::tr!("notify-connected", device = label),
            crate::tr!("notify-connected-camera"),
            "camera-photo",
        ),
        _ => (
            crate::tr!("notify-connected", device = label),
            crate::tr!("notify-connected-phone"),
            "phone",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::NotificationIds;

    #[test]
    fn delayed_close_for_replaced_id_preserves_current_notification() {
        let mut ids = NotificationIds::default();
        ids.record("camera", 1);
        ids.record("camera", 2);
        ids.remove_id(1);

        assert_eq!(ids.by_id.get(&1), None);
        assert_eq!(ids.by_id.get(&2).map(String::as_str), Some("camera"));
        assert_eq!(ids.remove_item("camera"), Some(2));
        assert!(ids.by_id.is_empty());
    }
}
