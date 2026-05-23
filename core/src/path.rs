//! Canonical world path validation.
//!
//! Pure string functions: decide whether a canonical world name is valid and
//! attach a human-readable rejection reason. No `Core`, no I/O, no adapter
//! wire-path normalization.
//!
//! HTTP/CoAP shorthand such as `/foo` -> `home/foo` lives in
//! `server/path.rs`, not in the production library surface.

/// Canonical Engine world namespaces.
pub(crate) const NAMESPACE_PREFIXES: &[&str] = &[
    "home", "tmp", "dev", "sys", "etc", "lib", "boot", "usr", "var",
];

/// Test-only copy of the adapter-side path canonicalizer, kept for legacy
/// white-box tests in `lib.rs`.
#[cfg(test)]
pub(crate) fn canonicalize_path(p: &str) -> String {
    let stripped = p.trim_start_matches('/');
    let first = stripped.split('/').next().unwrap_or("");
    if NAMESPACE_PREFIXES.contains(&first) || first == "proc" {
        stripped.to_owned()
    } else {
        format!("home/{stripped}")
    }
}

/// Boolean wrapper for callers that only need the yes/no answer (CoAP
/// surface, top-level reject path). Prefer `validate_world_name` when
/// the rejection reason matters — the bool form is documented to elide
/// the reason and a 400 with a generic message.
#[cfg(test)]
pub(crate) fn valid_world_name(world_name: &str) -> bool {
    validate_world_name(world_name).is_ok()
}

/// Returns the specific rejection reason so HTTP callers can surface
/// it in `400 bad_request: world path contains backslash` rather than
/// the historic blanket `400 bad_request: control bytes`. This makes
/// SDK-side error messages diagnostically useful.
pub(crate) fn validate_world_name(world_name: &str) -> Result<(), &'static str> {
    if world_name.is_empty() {
        return Err("world path is empty");
    }
    if is_reserved_world_name(world_name) {
        return Err("world path is a reserved namespace root");
    }
    if world_name.contains('\\') {
        return Err("world path contains backslash");
    }
    if world_name.chars().any(char::is_control) {
        return Err("world path contains control bytes");
    }
    for segment in world_name.split('/') {
        if segment.is_empty() {
            return Err("world path has empty segment");
        }
        if is_dot_segment(segment) {
            return Err("world path contains dot or encoded-dot segment");
        }
    }
    Ok(())
}

/// True if the segment is one of `.`, `..`, `%2e`, `%2e.`, `%2e%2e`,
/// `.%2e`, `%2E%2E`, etc. — anything an attacker might use to walk out
/// of a namespace through URL encoding tricks. Decoded paths AND raw
/// percent-encoded paths are both rejected.
///
/// Module-private: only `validate_world_name` calls it. Keeping it
/// out of `pub(crate) use crate::path::*;` prevents sibling modules
/// from acquiring an accidental dependency on this internal helper.
fn is_dot_segment(segment: &str) -> bool {
    let Some(rest) = strip_dot_token(segment) else {
        return false;
    };
    rest.is_empty()
        || strip_dot_token(rest)
            .map(|tail| tail.is_empty())
            .unwrap_or(false)
}

/// Strip a leading `.` or case-insensitive `%2e` from a segment.
/// Helper for `is_dot_segment`; returns the remaining slice or None
/// if the segment doesn't begin with a dot token. Module-private.
fn strip_dot_token(segment: &str) -> Option<&str> {
    if let Some(rest) = segment.strip_prefix('.') {
        return Some(rest);
    }
    if segment
        .as_bytes()
        .get(..3)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"%2e"))
    {
        return Some(&segment[3..]);
    }
    None
}

/// Reserved namespace roots (no world named exactly `home`, `tmp`,
/// etc.) and the entire `/proc/*` subtree (which is read-only
/// introspection, not a world). Module-private: only
/// `validate_world_name` calls it.
fn is_reserved_world_name(world_name: &str) -> bool {
    NAMESPACE_PREFIXES.contains(&world_name)
        || matches!(world_name, "proc" | "var/log")
        || world_name.starts_with("proc/")
}
