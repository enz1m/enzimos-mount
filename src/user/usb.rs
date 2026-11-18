//! Phones and cameras on USB, from udev.
//!
//! UDisks2 does not handle MTP or Apple devices, so a udev monitor thread
//! reports USB device additions and removals. A device is a phone when libmtp's
//! rules marked it (`ID_MTP_DEVICE`, `ID_MEDIA_PLAYER`) or one of its
//! interfaces is the still-image class (06/01/01) or is named `MTP`; it is an
//! Apple device when it offers the usbmux interface (ff/fe/02).

use crate::api::Kind;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use tokio::sync::mpsc;

/// One USB phone, tablet or camera.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UsbDevice {
    /// Kernel device path, e.g. `/sys/devices/.../1-2`.
    pub syspath: PathBuf,
    /// `Phone`, `Camera` or `Ios`.
    pub kind: Kind,
    /// Vendor and model.
    pub label: String,
    /// USB serial number (UDID-derived for Apple devices).
    pub serial: String,
    /// USB vendor:product.
    pub usb_id: String,
}

impl UsbDevice {
    /// Stable identity for this session.
    #[must_use]
    pub fn id(&self) -> String {
        let key = if self.serial.is_empty() {
            self.syspath
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default()
        } else {
            self.serial.clone()
        };
        let prefix = if self.kind == Kind::Ios { "ios" } else { "mtp" };
        format!(
            "{prefix}:{}",
            key.chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
                .collect::<String>()
        )
    }
}

/// An interface's class, subclass, protocol and name.
pub type Interface = (u8, u8, u8, String);

/// Read a device's interfaces from sysfs.
#[must_use]
pub fn interfaces(syspath: &Path) -> Vec<Interface> {
    let Ok(entries) = std::fs::read_dir(syspath) else {
        return Vec::new();
    };
    let hex = |p: &Path, name: &str| -> u8 {
        std::fs::read_to_string(p.join(name))
            .ok()
            .and_then(|s| u8::from_str_radix(s.trim(), 16).ok())
            .unwrap_or(0)
    };
    entries
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().contains(':'))
        .map(|e| {
            let p = e.path();
            let name = std::fs::read_to_string(p.join("interface"))
                .unwrap_or_default()
                .trim()
                .to_owned();
            (
                hex(&p, "bInterfaceClass"),
                hex(&p, "bInterfaceSubClass"),
                hex(&p, "bInterfaceProtocol"),
                name,
            )
        })
        .collect()
}

fn pretty(raw: &str) -> String {
    raw.replace('_', " ").trim().to_owned()
}

/// Classify a USB device from its udev properties and interfaces.
#[must_use]
pub fn classify(
    syspath: &Path,
    props: &BTreeMap<String, String>,
    interfaces: &[Interface],
) -> Option<UsbDevice> {
    let get = |key: &str| props.get(key).map(String::as_str).unwrap_or_default();
    let usbmux = interfaces
        .iter()
        .any(|(c, s, p, _)| (*c, *s, *p) == (0xff, 0xfe, 0x02));
    let still_image = interfaces
        .iter()
        .any(|(c, s, p, _)| (*c, *s, *p) == (0x06, 0x01, 0x01));
    let named_mtp = interfaces.iter().any(|(_, _, _, name)| name == "MTP");
    let kind = if get("ID_VENDOR_ID") == "05ac" && usbmux {
        Kind::Ios
    } else if get("ID_MTP_DEVICE") == "1" || !get("ID_MEDIA_PLAYER").is_empty() || named_mtp {
        Kind::Phone
    } else if still_image {
        if get("ID_GPHOTO2") == "1" && get("ID_MTP_DEVICE").is_empty() {
            Kind::Camera
        } else {
            Kind::Phone
        }
    } else {
        return None;
    };
    let vendor = [get("ID_VENDOR_FROM_DATABASE"), get("ID_VENDOR")]
        .into_iter()
        .find(|s| !s.is_empty())
        .map(pretty)
        .unwrap_or_default();
    let model = [get("ID_MODEL_FROM_DATABASE"), get("ID_MODEL")]
        .into_iter()
        .find(|s| !s.is_empty())
        .map(pretty)
        .unwrap_or_default();
    let label = if model.is_empty() {
        match kind {
            Kind::Ios => "iPhone".to_owned(),
            Kind::Camera => crate::tr!("label-camera"),
            _ => crate::tr!("label-phone"),
        }
    } else if !vendor.is_empty()
        && !model.to_lowercase().contains(&vendor.to_lowercase())
        && kind != Kind::Ios
    {
        format!("{vendor} {model}")
    } else {
        model
    };
    Some(UsbDevice {
        syspath: syspath.to_path_buf(),
        kind,
        label,
        serial: get("ID_SERIAL_SHORT").to_owned(),
        usb_id: format!("{}:{}", get("ID_VENDOR_ID"), get("ID_MODEL_ID")),
    })
}

fn device_props(device: &udev::Device) -> BTreeMap<String, String> {
    device
        .properties()
        .map(|p| {
            (
                p.name().to_string_lossy().into_owned(),
                p.value().to_string_lossy().into_owned(),
            )
        })
        .collect()
}

fn from_device(device: &udev::Device) -> Option<UsbDevice> {
    if device.devtype().is_none_or(|t| t != "usb_device") {
        return None;
    }
    let syspath = device.syspath().to_path_buf();
    classify(&syspath, &device_props(device), &interfaces(&syspath))
}

/// A change in the set of USB phones.
#[derive(Debug)]
pub enum Event {
    /// The full current set (sent at start and after every change).
    All(Vec<UsbDevice>),
}

/// The USB phones present now.
#[must_use]
pub fn enumerate() -> Vec<UsbDevice> {
    let Ok(mut enumerator) = udev::Enumerator::new() else {
        return Vec::new();
    };
    let _ = enumerator.match_subsystem("usb");
    let _ = enumerator.match_property("DEVTYPE", "usb_device");
    enumerator
        .scan_devices()
        .map(|devices| devices.filter_map(|d| from_device(&d)).collect())
        .unwrap_or_default()
}

/// Watch USB devices on a dedicated thread (udev handles are not `Send`).
/// Sends the full set at start and after each relevant change.
pub fn spawn(sender: mpsc::Sender<Event>) {
    let spawned = std::thread::Builder::new()
        .name("enzimos-mount-udev".to_owned())
        .spawn(move || {
            let monitor = udev::MonitorBuilder::new()
                .and_then(|b| b.match_subsystem_devtype("usb", "usb_device"))
                .and_then(udev::MonitorBuilder::listen);
            let _ = sender.blocking_send(Event::All(enumerate()));
            let Ok(socket) = monitor else {
                crate::log!(
                    warn,
                    "udev monitor unavailable; phones will not be detected"
                );
                return;
            };
            loop {
                let mut fds = [rustix::event::PollFd::new(
                    &socket,
                    rustix::event::PollFlags::IN,
                )];
                if rustix::event::poll(&mut fds, None).is_err() {
                    std::thread::sleep(std::time::Duration::from_millis(500));
                    continue;
                }
                let mut relevant = false;
                for event in socket.iter() {
                    relevant |= event.event_type() == udev::EventType::Remove
                        || from_device(&event.device()).is_some();
                }
                if relevant {
                    // Interfaces and udev properties settle shortly after "add".
                    std::thread::sleep(std::time::Duration::from_millis(300));
                    if sender.blocking_send(Event::All(enumerate())).is_err() {
                        return;
                    }
                }
            }
        });
    if let Err(error) = spawned {
        crate::log!(err, "could not start the udev thread: {error}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phones_and_iphones_are_recognized_and_other_usb_devices_ignored() {
        let props = |pairs: &[(&str, &str)]| {
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect::<BTreeMap<_, _>>()
        };
        let path = Path::new("/sys/devices/pci0000:00/usb1/1-2");
        let iface = |c, s, p, n: &str| (c, s, p, n.to_owned());

        let qemu_mtp = classify(
            path,
            &props(&[("ID_MODEL", "MTP"), ("ID_SERIAL_SHORT", "34617")]),
            &[iface(6, 1, 1, "")],
        )
        .unwrap();
        assert_eq!(
            (qemu_mtp.kind, qemu_mtp.id()),
            (Kind::Phone, "mtp:34617".to_owned()),
            "still-image class interface"
        );
        let pixel = classify(
            path,
            &props(&[
                ("ID_MTP_DEVICE", "1"),
                ("ID_VENDOR", "Google"),
                ("ID_MODEL", "Pixel_8"),
                ("ID_SERIAL_SHORT", "ABC"),
            ]),
            &[iface(0xff, 0xff, 0, "MTP")],
        )
        .unwrap();
        assert_eq!(
            (pixel.kind, pixel.label.as_str()),
            (Kind::Phone, "Google Pixel 8"),
            "libmtp-tagged Android"
        );
        let iphone = classify(
            path,
            &props(&[
                ("ID_VENDOR_ID", "05ac"),
                ("ID_MODEL", "iPhone"),
                ("ID_SERIAL_SHORT", "00008030001A35E83C08402E"),
            ]),
            &[iface(6, 1, 1, "PTP"), iface(0xff, 0xfe, 2, "")],
        )
        .unwrap();
        assert_eq!(
            (iphone.kind, iphone.id().starts_with("ios:")),
            (Kind::Ios, true),
            "usbmux makes it an Apple device"
        );
        assert!(
            classify(
                path,
                &props(&[("ID_MODEL", "Keyboard")]),
                &[iface(3, 1, 1, "")]
            )
            .is_none(),
            "HID ignored"
        );
        assert!(
            classify(
                path,
                &props(&[("ID_MODEL", "Stick")]),
                &[iface(8, 6, 0x50, "")]
            )
            .is_none(),
            "mass storage is UDisks2's"
        );
    }
}
