#![deny(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

fn main() {
    uniffi::uniffi_bindgen_main();
}
