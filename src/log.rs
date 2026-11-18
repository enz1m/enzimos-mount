//! Minimal journal logging: one line per event on standard error, which
//! systemd forwards to the journal with the unit's identity.

/// Log a line with a syslog priority prefix the journal understands.
#[macro_export]
macro_rules! log {
    (err, $($arg:tt)*) => { eprintln!("<3>{}", format_args!($($arg)*)) };
    (warn, $($arg:tt)*) => { eprintln!("<4>{}", format_args!($($arg)*)) };
    (info, $($arg:tt)*) => { eprintln!("<6>{}", format_args!($($arg)*)) };
    (debug, $($arg:tt)*) => {
        if $crate::log::debug_enabled() {
            eprintln!("<7>{}", format_args!($($arg)*))
        }
    };
}

/// Whether `ENZIMOS_MOUNT_DEBUG` asks for debug lines.
#[must_use]
pub fn debug_enabled() -> bool {
    static DEBUG: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *DEBUG.get_or_init(|| std::env::var_os("ENZIMOS_MOUNT_DEBUG").is_some())
}
