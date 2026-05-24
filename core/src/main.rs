#[cfg(not(test))]
mod config;
#[cfg(not(test))]
mod defaults;
#[cfg(not(test))]
mod http_range;
#[cfg(not(test))]
mod http_semantics;
#[cfg(not(test))]
mod path;
#[cfg(not(test))]
mod server;
#[cfg(not(test))]
#[path = "server/path.rs"]
mod server_path;

#[cfg(not(test))]
mod engine {
    #[allow(unused_imports)]
    pub(crate) use elastik_core::ShutdownToken;
    pub(crate) use elastik_core::{Engine, EngineBuilder, EngineError};
}

#[cfg(not(test))]
mod engine_introspection {
    pub(crate) use elastik_core::{AuditBroken, AuditValid, AuditVerify, PoolSnapshot, WorldUsage};
}

#[cfg(not(test))]
mod engine_trace {
    pub(crate) use elastik_core::{DeleteMetadata, EngineDeleteTraceHooks, EngineWriteTraceHooks};
}

#[cfg(not(test))]
mod engine_types {
    pub(crate) use elastik_core::{
        parse_etag_matchers, AccessTier, ChangeEvent, EtagMatcher, Preconditions, Representation,
        SecretBytes, SubscribePattern, SubscriptionRecvError, ValidatedWorldPath, WriteKind,
    };
}

#[cfg(not(test))]
pub(crate) use elastik_core::AuthGate;
#[cfg(not(test))]
pub(crate) use path::*;
#[cfg(not(test))]
pub(crate) use pipeline::*;
#[cfg(not(test))]
pub(crate) use proc::*;
#[cfg(not(test))]
pub(crate) use response::*;
#[cfg(all(not(test), feature = "coap"))]
pub(crate) use server::{coap, coap_errors};
#[cfg(not(test))]
pub(crate) use server::{handler, listen, middleware, pipeline, proc, response};
#[cfg(not(test))]
pub(crate) use server_path::canonicalize_path;

#[cfg(not(test))]
pub(crate) const VERSION: &str = env!("CARGO_PKG_VERSION");
#[cfg(not(test))]
pub(crate) const WORLD_ALLOW: &str = "GET, HEAD, PUT, POST, DELETE, OPTIONS";

#[cfg_attr(feature = "multi-thread", tokio::main)]
#[cfg_attr(not(feature = "multi-thread"), tokio::main(flavor = "current_thread"))]
#[cfg(not(test))]
async fn main() {
    server::run_from_env().await;
}

#[cfg(test)]
fn main() {}
