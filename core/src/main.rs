#[cfg(not(test))]
mod defaults;
#[cfg(not(test))]
mod path;
#[cfg(not(test))]
mod server;

#[cfg(not(test))]
mod engine {
    #[cfg(any(feature = "coap", feature = "mqtt"))]
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
    #[cfg(feature = "mqtt")]
    pub(crate) use elastik_core::EngineSubscription;
    pub(crate) use elastik_core::{
        parse_etag_matchers, AccessTier, ChangeEvent, EtagMatcher, Preconditions, Representation,
        SecretBytes, SubscribePattern, SubscriptionRecvError, ValidatedWorldPath, WriteKind,
    };
}

#[cfg(not(test))]
pub(crate) use elastik_core::AuthGate;
#[cfg(not(test))]
pub(crate) use path::*;

#[cfg_attr(feature = "multi-thread", tokio::main)]
#[cfg_attr(not(feature = "multi-thread"), tokio::main(flavor = "current_thread"))]
#[cfg(not(test))]
async fn main() {
    server::run_from_env().await;
}

#[cfg(test)]
fn main() {}
