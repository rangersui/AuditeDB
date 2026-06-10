//! Public Engine API imports for the binary crate.
//!
//! This module keeps the adapter-facing import paths stable while ensuring
//! both production and test builds consume `elastik_core` as an external
//! library. It must not `#[path]` into `core/src`; if bin tests need a core
//! capability, expose it through the public Engine API or a bin-owned test
//! helper.

pub(crate) mod defaults {
    #[allow(unused_imports)]
    pub(crate) use elastik_core::{
        DEFAULT_LISTEN_REPLAY_MAX, DEFAULT_MAX_LISTEN_CONNECTIONS, DEFAULT_MAX_MEMORY_BYTES,
        DEFAULT_MAX_WORLD_BYTES, DEFAULT_READ_CACHE_MAX_ENTRIES,
    };
}

pub(crate) mod path {
    pub(crate) use elastik_core::{validate_world_name, NAMESPACE_PREFIXES};
}

pub(crate) mod engine {
    #[cfg(any(feature = "coap", feature = "mqtt"))]
    pub(crate) use elastik_core::ShutdownToken;
    #[allow(unused_imports)]
    pub(crate) use elastik_core::{Engine, EngineBuilder, EngineError};
}

pub(crate) mod engine_introspection {
    pub(crate) use elastik_core::{AuditBroken, AuditValid, AuditVerify, PoolSnapshot, WorldUsage};
}

pub(crate) mod engine_trace {
    pub(crate) use elastik_core::{DeleteMetadata, EngineDeleteTraceHooks, EngineWriteTraceHooks};
}

pub(crate) mod engine_types {
    #[cfg(feature = "mqtt")]
    pub(crate) use elastik_core::EngineSubscription;
    #[cfg(test)]
    pub(crate) use elastik_core::WriteResult;
    pub(crate) use elastik_core::{
        parse_etag_matchers, AccessTier, AuditHmacKey, ChangeEvent, ChangeVerb, EtagMatcher,
        InvalidHmacKey, Preconditions, Representation, SubscribePattern, SubscriptionRecvError,
        ValidatedWorldPath, WriteKind,
    };
}

pub(crate) use elastik_core::AuthGate;
