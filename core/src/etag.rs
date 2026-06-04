//! Protocol-neutral ETag identity and precondition matching.
//!
//! Adapters parse protocol-specific precondition syntax into this shape. The
//! matcher itself is disk physics: compare the caller's version expectation
//! against the current world identity without knowing about wire headers or
//! adapter rendering.

use crate::world;

pub(crate) fn hmac_etag(hmac: &str) -> String {
    format!("hmac-{hmac}")
}

pub(crate) fn body_etag(body: &[u8]) -> String {
    format!("sha256-{}", world::sha256_hex(body))
}

#[derive(Clone, Debug, Default)]
pub(crate) struct Preconditions {
    if_match: Vec<EtagMatcher>,
    if_none_match: Vec<EtagMatcher>,
}

impl Preconditions {
    pub(crate) fn new(if_match: Vec<EtagMatcher>, if_none_match: Vec<EtagMatcher>) -> Self {
        Self {
            if_match,
            if_none_match,
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.if_match.is_empty() && self.if_none_match.is_empty()
    }

    pub(crate) fn into_parts(self) -> (Vec<EtagMatcher>, Vec<EtagMatcher>) {
        (self.if_match, self.if_none_match)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum EtagMatcher {
    Any,
    Strong(String),
    Weak(String),
    Invalid,
}

pub(crate) fn check_preconditions(
    preconditions: &Preconditions,
    current_tag: Option<&str>,
) -> Result<(), &'static str> {
    if !preconditions.if_match.is_empty() {
        let Some(tag) = current_tag else {
            return Err("If-Match requires an existing world");
        };
        if !preconditions
            .if_match
            .iter()
            .any(|matcher| matcher.strong_matches(tag))
        {
            return Err("If-Match did not match current ETag");
        }
    }

    if let Some(tag) = current_tag {
        if preconditions
            .if_none_match
            .iter()
            .any(|matcher| matcher.weak_matches(tag))
        {
            return Err("If-None-Match matched current ETag");
        }
    }

    Ok(())
}

pub(crate) fn parse_etag_matchers(raw: &str) -> Vec<EtagMatcher> {
    raw.split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(parse_etag_matcher)
        .collect()
}

fn parse_etag_matcher(candidate: &str) -> EtagMatcher {
    if candidate == "*" {
        return EtagMatcher::Any;
    }
    if let Some(rest) = candidate
        .strip_prefix("W/")
        .or_else(|| candidate.strip_prefix("w/"))
    {
        if let Some(value) = quoted_etag(rest) {
            return EtagMatcher::Weak(value.to_owned());
        }
        return EtagMatcher::Invalid;
    }
    if let Some(value) = quoted_etag(candidate) {
        return EtagMatcher::Strong(value.to_owned());
    }
    EtagMatcher::Invalid
}

fn quoted_etag(candidate: &str) -> Option<&str> {
    let candidate = candidate.trim();
    candidate
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .filter(|value| !value.contains('"'))
}

impl EtagMatcher {
    fn strong_matches(&self, current: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Strong(value) => value == current,
            Self::Weak(_) | Self::Invalid => false,
        }
    }

    fn weak_matches(&self, current: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Strong(value) | Self::Weak(value) => value == current,
            Self::Invalid => false,
        }
    }
}

#[cfg(test)]
pub(crate) fn etag_list_strong_matches(header_value: &str, current: &str) -> bool {
    let quoted = format!("\"{current}\"");
    header_value
        .split(',')
        .map(str::trim)
        .any(|candidate| candidate == "*" || candidate == quoted.as_str())
}

#[cfg(test)]
pub(crate) fn etag_list_weak_matches(header_value: &str, current: &str) -> bool {
    let quoted = format!("\"{current}\"");
    header_value.split(',').map(str::trim).any(|candidate| {
        candidate == "*"
            || candidate == quoted.as_str()
            || candidate
                .strip_prefix("W/")
                .map(|weak| weak == quoted.as_str())
                .unwrap_or(false)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn etag_lists_match_strong_and_weak_rules() {
        assert!(etag_list_strong_matches("\"hmac-abc\"", "hmac-abc"));
        assert!(etag_list_strong_matches(
            "\"other\", \"hmac-abc\"",
            "hmac-abc"
        ));
        assert!(etag_list_strong_matches("*", "hmac-abc"));
        assert!(!etag_list_strong_matches("W/\"hmac-abc\"", "hmac-abc"));
        assert!(!etag_list_strong_matches("\"other\"", "hmac-abc"));

        assert!(etag_list_weak_matches("W/\"hmac-abc\"", "hmac-abc"));
    }

    #[test]
    fn preconditions_can_be_checked_without_adapter_header_types() {
        let preconditions = Preconditions::new(
            vec![EtagMatcher::Strong("hmac-current".to_owned())],
            Vec::new(),
        );

        assert_eq!(
            check_preconditions(&preconditions, Some("hmac-current")),
            Ok(())
        );
        assert_eq!(
            check_preconditions(&preconditions, Some("hmac-stale")),
            Err("If-Match did not match current ETag")
        );
    }
}
