#![cfg_attr(test, allow(dead_code))]

mod core_bridge;
#[path = "server/mod.rs"]
mod server;

pub(crate) use core_bridge::*;

#[cfg_attr(feature = "multi-thread", tokio::main)]
#[cfg_attr(not(feature = "multi-thread"), tokio::main(flavor = "current_thread"))]
#[cfg(not(test))]
async fn main() {
    server::run_from_env().await;
}

#[cfg(test)]
fn main() {}
