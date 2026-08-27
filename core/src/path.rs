//! Canonical world path validation.
//!
//! Pure string functions: decide whether a canonical world name is valid and
//! attach a human-readable rejection reason. No `Core`, no I/O, no adapter
//! wire-path normalization.
//!
//! Wire shorthand such as `/foo` -> `home/foo` lives in binary adapters, not
//! in the Engine library.

/// Canonical Engine world namespaces.
pub const NAMESPACE_PREFIXES: &[&str] = &[
    "home", "tmp", "dev", "sys", "etc", "lib", "boot", "usr", "var",
];

/// Maximum byte length of the percent-encoded on-disk directory name for one
/// world. The engine stores each world as one directory, so this stays below
/// common single-component filesystem limits instead of discovering them via
/// SQLite open failures.
pub const MAX_DISK_WORLD_NAME_BYTES: usize = 200;

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

/// Boolean wrapper for callers that only need the yes/no answer
/// (top-level reject path). Prefer `validate_world_name` when
/// the rejection reason matters — the bool form is documented to elide
/// the reason and a 400 with a generic message.
#[cfg(test)]
pub(crate) fn valid_world_name(world_name: &str) -> bool {
    validate_world_name(world_name).is_ok()
}

/// Returns the specific rejection reason so adapters can surface precise
/// diagnostics instead of a blanket invalid-path error.
pub fn validate_world_name(world_name: &str) -> Result<(), &'static str> {
    if world_name.is_empty() {
        return Err("world path is empty");
    }
    if disk_world_name_len(world_name) > MAX_DISK_WORLD_NAME_BYTES {
        return Err("world path is too long");
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

/// Mirrors `world::DISK_ENCODE` without depending on the storage module.
/// Slash is counted as `%2F`, so this checks the actual single directory
/// component length rather than the caller-visible world string length.
fn disk_world_name_len(world_name: &str) -> usize {
    world_name
        .as_bytes()
        .iter()
        .map(|byte| if should_disk_encode(*byte) { 3 } else { 1 })
        .sum()
}

fn should_disk_encode(byte: u8) -> bool {
    byte <= 0x1F
        || byte >= 0x7F
        || matches!(
            byte,
            b'%' | b'.' | b'/' | b'\\' | b':' | b'*' | b'?' | b'"' | b'<' | b'>' | b'|' | b' '
        )
}

/// True if the segment is one of `.`, `..`, `%2e`, `%2e.`, `%2e%2e`,
/// `.%2e`, `%2E%2E`, etc. — anything an attacker might use to walk out
/// of a namespace through URL encoding tricks. Decoded paths AND raw
/// percent-encoded paths are both rejected.
///
/// Module-private: only `validate_world_name` calls it. Keeping it private
/// prevents sibling modules from acquiring an accidental dependency on this
/// internal helper.
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn canonicalize_preserves_explicit_namespaces() {
        assert_eq!(canonicalize_path("/home/tmp/foo"), "home/tmp/foo");
        assert_eq!(canonicalize_path("/home/etc/foo"), "home/etc/foo");
        assert_eq!(canonicalize_path("/tmp/foo"), "tmp/foo");
        assert_eq!(canonicalize_path("/etc/foo"), "etc/foo");
        assert_eq!(canonicalize_path("/foo"), "home/foo");
    }

    #[test]
    fn control_bytes_are_not_valid_world_names() {
        assert!(valid_world_name("home/ok"));
        assert!(!valid_world_name("home/bad\nname"));
        assert!(!valid_world_name(""));
    }

    #[test]
    fn dot_segments_empty_segments_and_backslashes_are_not_valid_world_names() {
        assert!(!valid_world_name("home/../etc/secret"));
        assert!(!valid_world_name("home/%2E%2E/etc/secret"));
        assert!(!valid_world_name("home/./x"));
        assert!(!valid_world_name("home//x"));
        assert!(!valid_world_name("home/x/"));
        assert!(!valid_world_name("home\\x"));
        assert_eq!(
            validate_world_name("home/%2E%2E/etc/secret"),
            Err("world path contains dot or encoded-dot segment")
        );
        assert_eq!(
            validate_world_name("home//x"),
            Err("world path has empty segment")
        );
        assert_eq!(
            validate_world_name("home\\x"),
            Err("world path contains backslash")
        );
    }

    #[test]
    fn namespace_roots_and_proc_subtree_are_not_world_names() {
        for name in [
            "home",
            "tmp",
            "dev",
            "sys",
            "proc",
            "proc/anything",
            "etc",
            "lib",
            "boot",
            "usr",
            "var",
            "var/log",
        ] {
            assert!(!valid_world_name(name), "{name}");
        }
        assert!(valid_world_name("home/x"));
        assert!(valid_world_name("var/log/deletes"));
    }

    #[test]
    fn disk_encoded_world_name_length_is_bounded() {
        let exact_limit = format!("home/{}", "a".repeat(193));
        let one_over_limit = format!("home/{}", "a".repeat(194));
        let encoded_slashes_too_long = format!("home/{}", "a/".repeat(70));

        assert_eq!(disk_world_name_len(&exact_limit), MAX_DISK_WORLD_NAME_BYTES);
        assert!(valid_world_name(&exact_limit));
        let validated = crate::ValidatedWorldPath::new(exact_limit.clone()).unwrap();
        let encoded_component =
            crate::world::validated_world_dir(std::path::Path::new("data"), &validated);
        assert_eq!(
            encoded_component
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .len(),
            MAX_DISK_WORLD_NAME_BYTES,
            "validator length estimator must match the storage encoder"
        );
        assert_eq!(
            disk_world_name_len(&one_over_limit),
            MAX_DISK_WORLD_NAME_BYTES + 1
        );
        assert_eq!(
            validate_world_name(&one_over_limit),
            Err("world path is too long")
        );
        assert_eq!(
            validate_world_name(&encoded_slashes_too_long),
            Err("world path is too long")
        );
    }
}
