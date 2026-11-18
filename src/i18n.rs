//! Translations of every sentence a person sees: error messages, item labels
//! and notifications.
//!
//! Catalogs are Fluent files in `locales/`, built into the binaries. The
//! language follows the session the same way the enzUI apps choose theirs:
//! `LANGUAGE`, then `LC_ALL`, `LC_MESSAGES` and `LANG`; `C` or `POSIX` means
//! English. Missing translations fall back to English.
//!
//! The root service does not know the language of the person it serves, so it
//! calls [`defer`] at startup. Its messages then travel as an identifier with
//! arguments, and the session service, which runs in the user's locale, turns
//! them into text with [`render`] when it receives them.

use fluent_bundle::concurrent::FluentBundle;
use fluent_bundle::{FluentArgs, FluentResource, FluentValue};
use std::collections::BTreeMap;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use unic_langid::LanguageIdentifier;

/// Built-in catalogs; the first is the fallback and must hold every message.
pub const CATALOGS: &[(&str, &str)] = &[
    ("en-US", include_str!("../locales/en-US.ftl")),
    ("es", include_str!("../locales/es.ftl")),
];

/// Marks a deferred message: `MARK id MARK {json arguments}`.
const MARK: char = '\u{1}';

static DEFER: AtomicBool = AtomicBool::new(false);

/// An argument value.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum Arg {
    /// Inserted as is.
    Text(String),
    /// Selects plural forms.
    Number(i64),
}

impl From<&str> for Arg {
    fn from(value: &str) -> Self {
        Self::Text(value.to_owned())
    }
}
impl From<String> for Arg {
    fn from(value: String) -> Self {
        Self::Text(value)
    }
}
impl From<&String> for Arg {
    fn from(value: &String) -> Self {
        Self::Text(value.clone())
    }
}
impl From<usize> for Arg {
    fn from(value: usize) -> Self {
        Self::Number(i64::try_from(value).unwrap_or(i64::MAX))
    }
}
impl From<i32> for Arg {
    fn from(value: i32) -> Self {
        Self::Number(value.into())
    }
}

/// Translate message `id` with `args` in the session language (or defer it).
///
/// Use through [`crate::tr!`].
#[must_use]
pub fn text(id: &str, args: &[(&str, Arg)]) -> String {
    if DEFER.load(Ordering::Relaxed) {
        let map: BTreeMap<&str, &Arg> = args.iter().map(|(k, v)| (*k, v)).collect();
        return format!(
            "{MARK}{id}{MARK}{}",
            serde_json::to_string(&map).unwrap_or_default()
        );
    }
    format(chain(), id, args)
}

/// Make this process send messages untranslated, for [`render`] at the
/// receiving end. Called by the root service.
pub fn defer() {
    DEFER.store(true, Ordering::Relaxed);
}

/// Text for a message received from the root service: deferred messages are
/// translated here, anything else is returned unchanged.
#[must_use]
pub fn render(message: &str) -> String {
    let Some(rest) = message.strip_prefix(MARK) else {
        return message.to_owned();
    };
    let Some((id, json)) = rest.split_once(MARK) else {
        return message.to_owned();
    };
    let map: BTreeMap<String, Arg> = serde_json::from_str(json).unwrap_or_default();
    let args: Vec<(&str, Arg)> = map.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
    format(chain(), id, &args)
}

type Bundle = FluentBundle<FluentResource>;

fn bundle(tag: &str, source: &str) -> Bundle {
    let lang: LanguageIdentifier = tag.parse().unwrap_or_default();
    let mut bundle = FluentBundle::new_concurrent(vec![lang]);
    // Plain text goes to notifications and logs; no bidi isolation marks.
    bundle.set_use_isolating(false);
    let resource =
        FluentResource::try_new(source.to_owned()).unwrap_or_else(|(partial, _)| partial);
    let _ = bundle.add_resource(resource);
    bundle
}

fn chain() -> &'static [Bundle] {
    static CHAIN: OnceLock<Vec<Bundle>> = OnceLock::new();
    CHAIN.get_or_init(|| build_chain(&preferred(|key| std::env::var(key).ok())))
}

/// Bundles for the preferred languages, English last.
#[must_use]
fn build_chain(preferred: &[LanguageIdentifier]) -> Vec<Bundle> {
    let mut tags: Vec<&str> = Vec::new();
    for want in preferred {
        let found = CATALOGS
            .iter()
            .map(|(tag, _)| *tag)
            .find(|tag| {
                tag.parse::<LanguageIdentifier>()
                    .is_ok_and(|have| have == *want)
            })
            .or_else(|| {
                CATALOGS.iter().map(|(tag, _)| *tag).find(|tag| {
                    tag.parse::<LanguageIdentifier>()
                        .is_ok_and(|have| have.language == want.language)
                })
            });
        if let Some(tag) = found
            && !tags.contains(&tag)
        {
            tags.push(tag);
        }
    }
    let fallback = CATALOGS[0].0;
    tags.retain(|tag| *tag != fallback);
    tags.push(fallback);
    tags.into_iter()
        .filter_map(|tag| CATALOGS.iter().find(|(t, _)| *t == tag))
        .map(|(tag, source)| bundle(tag, source))
        .collect()
}

/// A POSIX locale name (`es_MX.UTF-8@euro`) as a language identifier.
fn posix(value: &str) -> Option<LanguageIdentifier> {
    let base = value.trim().split(['.', '@']).next()?;
    if base.is_empty() {
        return None;
    }
    base.replace('_', "-").parse().ok()
}

/// Preferred languages from the environment, GNU `LANGUAGE` first.
fn preferred(read: impl Fn(&str) -> Option<String>) -> Vec<LanguageIdentifier> {
    let Some(raw) = ["LC_ALL", "LC_MESSAGES", "LANG"]
        .into_iter()
        .filter_map(&read)
        .find(|v| !v.trim().is_empty())
    else {
        return Vec::new();
    };
    let name = raw.trim().split(['.', '@']).next().unwrap_or_default();
    if name.eq_ignore_ascii_case("c") || name.eq_ignore_ascii_case("posix") {
        return Vec::new();
    }
    let mut out: Vec<LanguageIdentifier> = read("LANGUAGE")
        .unwrap_or_default()
        .split(':')
        .filter_map(posix)
        .collect();
    out.extend(posix(&raw));
    out
}

fn format(chain: &[Bundle], id: &str, args: &[(&str, Arg)]) -> String {
    let mut fluent = FluentArgs::new();
    for (key, value) in args {
        match value {
            Arg::Text(text) => fluent.set(*key, FluentValue::from(text.as_str())),
            Arg::Number(number) => fluent.set(*key, FluentValue::from(*number)),
        }
    }
    for bundle in chain {
        if let Some(pattern) = bundle.get_message(id).and_then(|m| m.value()) {
            let mut errors = Vec::new();
            let text = bundle.format_pattern(pattern, Some(&fluent), &mut errors);
            if errors.is_empty() {
                return text.into_owned();
            }
        }
    }
    id.to_owned()
}

/// Translate a message: `tr!("id")` or `tr!("id", name = value, …)`.
#[macro_export]
macro_rules! tr {
    ($id:literal) => {
        $crate::i18n::text($id, &[])
    };
    ($id:literal, $($key:ident = $value:expr),+ $(,)?) => {
        $crate::i18n::text($id, &[$((stringify!($key), $crate::i18n::Arg::from($value))),+])
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn language_follows_the_session_and_falls_back_to_english() {
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |key: &str| {
                pairs
                    .iter()
                    .find(|(k, _)| *k == key)
                    .map(|(_, v)| (*v).to_owned())
            }
        };
        let spanish = build_chain(&preferred(env(&[("LANG", "es_MX.UTF-8")])));
        let english = build_chain(&preferred(env(&[("LANG", "C.UTF-8"), ("LANGUAGE", "es")])));
        let german = build_chain(&preferred(env(&[("LANG", "de_DE.UTF-8")])));
        let override_ = build_chain(&preferred(env(&[
            ("LANG", "en_US.UTF-8"),
            ("LC_MESSAGES", "es_ES.UTF-8"),
        ])));
        let host = [("host", Arg::from("nas"))];
        assert_eq!(
            format(&spanish, "error-server-no-answer", &host),
            "El servidor «nas» no respondió"
        );
        assert_eq!(
            format(&override_, "error-server-no-answer", &host),
            "El servidor «nas» no respondió"
        );
        assert_eq!(
            format(&english, "error-server-no-answer", &host),
            "The server “nas” did not answer"
        );
        assert_eq!(
            format(&german, "error-server-no-answer", &host),
            "The server “nas” did not answer"
        );
        assert_eq!(format(&english, "no-such-message", &[]), "no-such-message");
    }

    #[test]
    fn deferred_messages_are_translated_by_the_receiver() {
        let chain = build_chain(&[]);
        let map: BTreeMap<&str, Arg> =
            BTreeMap::from([("host", Arg::from("nas")), ("count", Arg::from(2usize))]);
        let wire = format!(
            "{MARK}error-server-no-answer{MARK}{}",
            serde_json::to_string(&map).unwrap()
        );
        let rest = wire.strip_prefix(MARK).unwrap();
        let (id, json) = rest.split_once(MARK).unwrap();
        let decoded: BTreeMap<String, Arg> = serde_json::from_str(json).unwrap();
        let args: Vec<(&str, Arg)> = decoded
            .iter()
            .map(|(k, v)| (k.as_str(), v.clone()))
            .collect();
        assert_eq!(format(&chain, id, &args), "The server “nas” did not answer");
        assert_eq!(
            render("plain text"),
            "plain text",
            "ordinary messages pass through"
        );
        assert_eq!(
            render("{\"id\":\"net-1\"}"),
            "{\"id\":\"net-1\"}",
            "JSON bodies pass through"
        );
    }
}
