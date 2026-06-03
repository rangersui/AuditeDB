//! Adapter-side path canonicalization.
//!
//! This is where HTTP/CoAP wire paths like `/foo` become canonical Engine
//! world paths like `home/foo`. The library only validates canonical names.

/// Path prefix is policy: `/home/tmp/foo` must stay a durable home world, not
/// silently become transient `/tmp/foo`. Bare `/foo` is the convenience spelling
/// for `/home/foo`; explicit namespaces are kept.
pub(crate) fn canonicalize_path(p: &str) -> String {
    let stripped = p.trim_start_matches('/');
    let first = stripped.split('/').next().unwrap_or("");
    if crate::path::NAMESPACE_PREFIXES.contains(&first) || first == "proc" {
        stripped.to_owned()
    } else {
        format!("home/{stripped}")
    }
}
