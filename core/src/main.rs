#[cfg_attr(feature = "multi-thread", tokio::main)]
#[cfg_attr(not(feature = "multi-thread"), tokio::main(flavor = "current_thread"))]
async fn main() {
    elastik_core::run_from_env().await;
}
