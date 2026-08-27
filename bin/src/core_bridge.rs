//! Public Engine API imports for the binary crate.
//!
//! This module keeps the adapter-facing import paths stable while ensuring
//! both production and test builds consume `l5` as an external
//! library. It must not `#[path]` into `core/src`; if bin tests need a core
//! capability, expose it through the public Engine API or a bin-owned test
//! helper.

pub(crate) mod defaults {
    #[allow(unused_imports)]
    pub(crate) use l5::{
        DEFAULT_LISTEN_REPLAY_MAX, DEFAULT_MAX_LISTEN_CONNECTIONS, DEFAULT_MAX_MEMORY_BYTES,
        DEFAULT_MAX_WORLD_BYTES, DEFAULT_READ_CACHE_MAX_ENTRIES,
    };
}

pub(crate) mod path {
    pub(crate) use l5::{validate_world_name, NAMESPACE_PREFIXES};
}

pub(crate) mod engine {
    #[allow(unused_imports)]
    pub(crate) use l5::{Engine, EngineBuilder, EngineError};
}

pub(crate) mod engine_introspection {
    pub(crate) use l5::{
        AuditBroken, AuditValid, AuditVerify, ChainSeq, ChainStampRead, HeadStamp, PoolSnapshot,
        WorldUsage,
    };
}

pub(crate) mod engine_trace {
    pub(crate) use l5::{DeleteMetadata, EngineDeleteTraceHooks, EngineWriteTraceHooks};
}

pub(crate) mod engine_types {
    #[cfg(test)]
    pub(crate) use l5::WriteResult;
    pub(crate) use l5::{
        parse_etag_matchers, AccessTier, AuditHmacKey, ChangeEvent, ChangeEventIdentity,
        ChangeVerb, EtagMatcher, InvalidHmacKey, Preconditions, Representation, SubscribePattern,
        SubscriptionEventId, SubscriptionRecvError, SubscriptionResetReason, SubscriptionResume,
        ValidatedWorldPath, WriteKind,
    };
}

pub(crate) mod timeline {
    #[cfg(test)]
    pub(crate) use l5::TimelineAddress;
    pub(crate) use l5::{
        TimelineBody, TimelineCoordinate, TimelineDereference, VerifiedExpiredBody,
        VerifiedNonBodyEvent,
    };
}

pub(crate) use l5::AuthGate;
