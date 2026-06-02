//! UniFFI adapter for Elastik's protocol-neutral Engine.
//!
//! This crate is intentionally separate from `elastik-core`: it is an adapter
//! peer of HTTP and CoAP, not a new core surface. Layer 1 only proves the
//! UniFFI scaffold builds. Later stack layers will bind Engine methods.

uniffi::setup_scaffolding!();

/// Returns the FFI adapter package version.
#[uniffi::export]
pub fn ffi_version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}

/// Names the architectural boundary this adapter is allowed to cross.
///
/// This smoke export exists to make Layer 1 reviewable without binding any
/// Engine verbs yet. Future layers should replace this with real Engine-bound
/// types and keep HTTP/server vocabulary out of the FFI API.
#[uniffi::export]
pub fn ffi_engine_boundary() -> String {
    "Engine adapter only: no HTTP routes, no /proc paths, no status codes".to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scaffold_reports_version_and_boundary() {
        assert_eq!(ffi_version(), env!("CARGO_PKG_VERSION"));
        assert!(ffi_engine_boundary().contains("Engine adapter only"));
    }
}
