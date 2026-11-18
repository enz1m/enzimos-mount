//! Mount point names derived from untrusted labels.
//!
//! Volume labels, share names and phone models come from devices and servers.
//! A name becomes exactly one path component: never empty, `.` or `..`, never
//! containing `/` or NUL, no control characters, no leading dot (which would hide
//! it) and at most [`MAX_NAME_BYTES`] bytes.

/// Longest mount point name, in bytes.
pub const MAX_NAME_BYTES: usize = 64;

/// Turn `label` into a safe single path component; `fallback` is used when
/// nothing printable remains.
#[must_use]
pub fn component(label: &str, fallback: &str) -> String {
    let mut out = String::with_capacity(label.len().min(MAX_NAME_BYTES));
    for ch in label.trim().chars() {
        let ch = match ch {
            '/' | '\\' => '-',
            c if c.is_control() => continue,
            c => c,
        };
        if out.len() + ch.len_utf8() > MAX_NAME_BYTES {
            break;
        }
        out.push(ch);
    }
    let trimmed = out.trim().trim_start_matches('.').trim();
    if trimmed.is_empty() {
        if fallback == label {
            return "Untitled".to_owned();
        }
        return component(fallback, "Untitled");
    }
    trimmed.to_owned()
}

/// `base`, or `base (2)`, `base (3)`… — the first that `taken` rejects.
#[must_use]
pub fn unique(base: &str, mut taken: impl FnMut(&str) -> bool) -> String {
    if !taken(base) {
        return base.to_owned();
    }
    for n in 2..1000u32 {
        let suffix = format!(" ({n})");
        let mut stem = base.to_owned();
        while stem.len() + suffix.len() > MAX_NAME_BYTES {
            stem.pop();
        }
        let candidate = format!("{}{suffix}", stem.trim_end());
        if !taken(&candidate) {
            return candidate;
        }
    }
    format!(
        "{} {}",
        base.chars().take(40).collect::<String>(),
        crate::secret::random_hex(6)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostile_labels_become_one_visible_component() {
        let cases = [
            ("../../etc", "-..-etc"),
            ("..", "Untitled"),
            (".hidden", "hidden"),
            ("a/b\\c", "a-b-c"),
            ("tab\tnew\nline\0nul", "tabnewlinenul"),
            ("   ", "Untitled"),
            ("Photos 2026", "Photos 2026"),
        ];
        for (label, expected) in cases {
            let got = component(label, "Untitled");
            assert_eq!(got, expected, "label {label:?}");
            assert!(
                !got.contains('/') && !got.is_empty() && got != "." && got != "..",
                "{got:?}"
            );
        }
        let long = "é".repeat(100);
        let got = component(&long, "x");
        assert!(
            got.len() <= MAX_NAME_BYTES,
            "multi-byte truncation stays on a char boundary"
        );
        let taken = ["NAS", "NAS (2)"];
        assert_eq!(
            unique("NAS", |n| taken.contains(&n)),
            "NAS (3)",
            "collision suffix"
        );
    }
}
