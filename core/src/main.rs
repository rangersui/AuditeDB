mod defaults;
mod path;
#[path = "bin/server/mod.rs"]
mod server;

// Binary white-box tests need core internals while exercising the server tree.
// Keep that test bridge here so `lib.rs` remains protocol-neutral even when
// binary-feature tests compile.
#[cfg(test)]
mod audit;
#[cfg(test)]
mod auth;
#[cfg(test)]
mod data_lock;
#[cfg(test)]
mod delete_ops;
#[cfg(test)]
mod engine;
#[cfg(test)]
mod engine_introspection;
#[cfg(test)]
mod engine_ops;
#[cfg(test)]
mod engine_trace;
#[cfg(test)]
mod engine_types;
#[cfg(test)]
mod etag;
#[cfg(test)]
mod event;
#[cfg(test)]
mod ledger;
#[cfg(test)]
mod read_cache;
#[cfg(test)]
mod state;
#[cfg(test)]
mod storage_class;
#[cfg(test)]
mod store;
#[cfg(test)]
mod test_support;
#[cfg(test)]
mod world;
#[cfg(test)]
mod world_ops;

#[cfg(test)]
pub(crate) use crate::state::*;
#[cfg(test)]
pub(crate) use crate::storage_class::*;
#[cfg(test)]
pub(crate) use auth::AuthGate;
#[cfg(test)]
pub(crate) use data_lock::acquire_data_root_writer_lock;

#[cfg(test)]
pub(crate) fn can_write(world_name: &str, tier: auth::Tier) -> bool {
    let needs_approve = needs_write_approve(world_name);
    match tier {
        auth::Tier::Anon | auth::Tier::Read => false,
        auth::Tier::Write => !needs_approve,
        auth::Tier::Approve => true,
    }
}

#[cfg(test)]
pub(crate) fn needs_write_approve(world_name: &str) -> bool {
    exact_or_child(world_name, "lib")
        || exact_or_child(world_name, "etc")
        || exact_or_child(world_name, "boot")
        || exact_or_child(world_name, "usr")
        || exact_or_child(world_name, "var/log")
}

#[cfg(test)]
pub(crate) fn can_delete(tier: auth::Tier) -> bool {
    matches!(tier, auth::Tier::Approve)
}

#[cfg(test)]
pub(crate) fn exact_or_child(world_name: &str, prefix: &str) -> bool {
    world_name == prefix
        || world_name
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('/'))
}

#[cfg(test)]
pub(crate) fn can_read(core: &Core, tier: auth::Tier) -> bool {
    !core.tokens.read_required()
        || matches!(
            tier,
            auth::Tier::Read | auth::Tier::Write | auth::Tier::Approve
        )
}

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

#[cfg_attr(feature = "multi-thread", tokio::main)]
#[cfg_attr(not(feature = "multi-thread"), tokio::main(flavor = "current_thread"))]
#[cfg(not(test))]
async fn main() {
    server::run_from_env().await;
}

#[cfg(test)]
fn main() {}
