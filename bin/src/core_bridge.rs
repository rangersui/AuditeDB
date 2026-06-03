//! Core compatibility imports for the binary crate.
//!
//! Production builds re-export only the public `elastik_core` API that server
//! adapters are allowed to consume. Test builds still compile a temporary
//! private bridge so the existing server white-box tests can be migrated in
//! small PRs instead of one giant rewrite.

#[cfg(test)]
#[path = "../../core/src/defaults.rs"]
pub(crate) mod defaults;
#[cfg(test)]
#[path = "../../core/src/path.rs"]
pub(crate) mod path;

#[cfg(test)]
#[path = "../../core/src/audit.rs"]
pub(crate) mod audit;
#[cfg(test)]
#[path = "../../core/src/auth.rs"]
pub(crate) mod auth;
#[cfg(test)]
#[path = "../../core/src/data_lock.rs"]
pub(crate) mod data_lock;
#[cfg(test)]
#[path = "../../core/src/delete_ops.rs"]
pub(crate) mod delete_ops;
#[cfg(test)]
#[path = "../../core/src/engine.rs"]
pub(crate) mod engine;
#[cfg(test)]
#[path = "../../core/src/engine_introspection.rs"]
pub(crate) mod engine_introspection;
#[cfg(test)]
#[path = "../../core/src/engine_ops.rs"]
pub(crate) mod engine_ops;
#[cfg(test)]
#[path = "../../core/src/engine_trace.rs"]
pub(crate) mod engine_trace;
#[cfg(test)]
#[path = "../../core/src/engine_types.rs"]
pub(crate) mod engine_types;
#[cfg(test)]
#[path = "../../core/src/etag.rs"]
pub(crate) mod etag;
#[cfg(test)]
#[path = "../../core/src/event.rs"]
pub(crate) mod event;
#[cfg(test)]
#[path = "../../core/src/ledger.rs"]
pub(crate) mod ledger;
#[cfg(test)]
#[path = "../../core/src/read_cache.rs"]
pub(crate) mod read_cache;
#[cfg(test)]
#[path = "../../core/src/state.rs"]
pub(crate) mod state;
#[cfg(test)]
#[path = "../../core/src/storage_class.rs"]
pub(crate) mod storage_class;
#[cfg(test)]
#[path = "../../core/src/store.rs"]
pub(crate) mod store;
#[cfg(test)]
#[path = "../../core/src/test_support.rs"]
pub(crate) mod test_support;
#[cfg(test)]
#[path = "../../core/src/world.rs"]
pub(crate) mod world;
#[cfg(test)]
#[path = "../../core/src/world_ops.rs"]
pub(crate) mod world_ops;

#[cfg(test)]
pub(crate) use auth::AuthGate;
#[cfg(test)]
pub(crate) use data_lock::acquire_data_root_writer_lock;
#[cfg(test)]
pub(crate) use state::*;
#[cfg(test)]
pub(crate) use storage_class::*;

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
pub(crate) mod engine {
    #[cfg(any(feature = "coap", feature = "mqtt"))]
    pub(crate) use elastik_core::ShutdownToken;
    pub(crate) use elastik_core::{Engine, EngineBuilder, EngineError};
}

#[cfg(not(test))]
pub(crate) mod engine_introspection {
    pub(crate) use elastik_core::{AuditBroken, AuditValid, AuditVerify, PoolSnapshot, WorldUsage};
}

#[cfg(not(test))]
pub(crate) mod engine_trace {
    pub(crate) use elastik_core::{DeleteMetadata, EngineDeleteTraceHooks, EngineWriteTraceHooks};
}

#[cfg(not(test))]
pub(crate) mod engine_types {
    #[cfg(feature = "mqtt")]
    pub(crate) use elastik_core::EngineSubscription;
    pub(crate) use elastik_core::{
        parse_etag_matchers, AccessTier, ChangeEvent, EtagMatcher, Preconditions, Representation,
        SecretBytes, SubscribePattern, SubscriptionRecvError, ValidatedWorldPath, WriteKind,
    };
}

#[cfg(not(test))]
pub(crate) mod defaults {
    pub(crate) use elastik_core::{
        DEFAULT_LISTEN_REPLAY_MAX, DEFAULT_MAX_LISTEN_CONNECTIONS, DEFAULT_MAX_MEMORY_BYTES,
        DEFAULT_MAX_WORLD_BYTES, DEFAULT_READ_CACHE_MAX_ENTRIES,
    };
}

#[cfg(not(test))]
pub(crate) mod path {
    pub(crate) use elastik_core::{validate_world_name, NAMESPACE_PREFIXES};
}

#[cfg(not(test))]
pub(crate) use elastik_core::AuthGate;
