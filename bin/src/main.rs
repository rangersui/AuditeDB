#![cfg_attr(test, allow(dead_code))]
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

mod core_bridge;
#[path = "server/mod.rs"]
mod server;

pub(crate) use core_bridge::*;

#[cfg_attr(feature = "multi-thread", tokio::main)]
#[cfg_attr(not(feature = "multi-thread"), tokio::main(flavor = "current_thread"))]
#[cfg(not(test))]
async fn main() {
    if let Err(err) = server::run_from_env().await {
        eprintln!("auditedb: {err}");
        std::process::exit(1);
    }
}

#[cfg(test)]
fn main() {}
