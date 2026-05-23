//! Protocol-neutral ETag identity and precondition matching.
//!
//! HTTP adapters parse headers into this shape, but the matcher itself is disk
//! physics: compare the caller's version expectation against the current world
//! identity without knowing about `HeaderMap` or response rendering.

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
    raw.split(',').filter_map(parse_etag_matcher).collect()
}

fn parse_etag_matcher(raw: &str) -> Option<EtagMatcher> {
    let candidate = raw.trim();
    if candidate.is_empty() {
        return None;
    }
    if candidate == "*" {
        return Some(EtagMatcher::Any);
    }
    if let Some(strong) = quoted_etag(candidate) {
        return Some(EtagMatcher::Strong(strong.to_owned()));
    }
    if let Some(weak) = candidate.strip_prefix("W/").and_then(quoted_etag) {
        return Some(EtagMatcher::Weak(weak.to_owned()));
    }
    Some(EtagMatcher::Invalid)
}

fn quoted_etag(candidate: &str) -> Option<&str> {
    candidate
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
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
    fn preconditions_can_be_checked_without_http_headermap() {
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
