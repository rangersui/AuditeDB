use axum::{
    http::{header, HeaderName, HeaderValue, StatusCode},
    response::IntoResponse,
};

use crate::{
    engine::EngineError,
    engine_types::AccessTier,
    server::{
        audit_header_value, bad_request, decimal_header_value, insufficient_storage, server_error,
        storage_temporarily_unavailable, to_header_map, unauthorized, ErrorReason, Phase,
        ServerState, TraceCtx,
    },
    timeline::{
        TimelineBody, TimelineCoordinate, TimelineDereference, VerifiedExpiredBody,
        VerifiedNonBodyEvent,
    },
};

pub(crate) async fn execute_timeline(
    coordinate: TimelineCoordinate,
    tier: AccessTier,
    state: &ServerState,
    trace: &TraceCtx,
    head: bool,
) -> Phase {
    let engine = state.engine().clone();
    let worker_coordinate = coordinate.clone();
    // Timeline dereference verifies SQLite audit rows and reads retained CAS
    // bytes; keep that filesystem/read-cache work off Tokio worker threads.
    let joined = tokio::task::spawn_blocking(move || {
        engine.dereference_timeline_coordinate(&worker_coordinate, tier)
    })
    .await;

    let result = match joined {
        Ok(Ok(result)) => result,
        Ok(Err(err)) => return timeline_engine_error_phase(err, head),
        Err(_) => {
            return timeline_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "timeline worker failed",
                head,
                ErrorReason::TimelineStorageRead,
            )
        }
    };

    trace.emit_aux_kv("timeline_world", coordinate.world().as_str());
    match result {
        TimelineDereference::Body(body) => {
            trace.emit_aux_kv("body_size", &body.representation().body.len().to_string());
            Phase::ExecutedRead(timeline_body_response(body, head))
        }
        other => {
            let (status, message, reason) = match other {
                TimelineDereference::GenMismatch(_) => (
                    StatusCode::CONFLICT,
                    "timeline generation mismatch",
                    ErrorReason::TimelineGenMismatch,
                ),
                TimelineDereference::BodyHashMismatch(_) => (
                    StatusCode::CONFLICT,
                    "timeline body sha256 mismatch",
                    ErrorReason::TimelineBodyHashMismatch,
                ),
                TimelineDereference::NonBodyEvent(non_body) => {
                    return Phase::Error {
                        resp: timeline_non_body_response(non_body, head),
                        reason: ErrorReason::TimelineNonBodyEvent,
                    };
                }
                TimelineDereference::Expired(expired) => {
                    return Phase::Error {
                        resp: timeline_expired_response(expired, head),
                        reason: ErrorReason::TimelineExpired,
                    };
                }
                TimelineDereference::MissingRow(_) => (
                    StatusCode::NOT_FOUND,
                    "timeline row not found",
                    ErrorReason::TimelineMissingRow,
                ),
                TimelineDereference::UnprovenCoordinate(_) => (
                    StatusCode::NOT_FOUND,
                    "timeline coordinate not proven",
                    ErrorReason::TimelineUnprovenCoordinate,
                ),
                TimelineDereference::Corrupt { .. } => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "timeline corruption",
                    ErrorReason::TimelineCorrupt,
                ),
                _ => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "unknown timeline dereference result",
                    ErrorReason::TimelineCorrupt,
                ),
            };
            timeline_error(status, message, head, reason)
        }
    }
}

fn timeline_body_response(body: TimelineBody, head: bool) -> axum::response::Response {
    let address = body.address();
    let representation = body.representation();
    let mut resp_headers = vec![
        (
            header::CONTENT_TYPE,
            HeaderValue::from_str(&representation.content_type)
                .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
        ),
        (
            header::CONTENT_LENGTH,
            decimal_header_value(representation.body.len()),
        ),
    ];
    crate::server::http::semantics::apply_meta_headers(&representation.headers, &mut resp_headers);
    resp_headers.extend([
        (
            HeaderName::from_static("x-timeline-world"),
            audit_header_value(address.world().as_str()),
        ),
        (
            HeaderName::from_static("x-timeline-generation"),
            audit_header_value(address.generation().as_str()),
        ),
        (
            HeaderName::from_static("x-timeline-seq"),
            HeaderValue::from_str(&address.seq().get().to_string())
                .unwrap_or_else(|_| HeaderValue::from_static("invalid")),
        ),
        (
            HeaderName::from_static("x-timeline-body-sha256"),
            audit_header_value(address.body_sha256().as_str()),
        ),
        (
            HeaderName::from_static("x-timeline-hmac"),
            audit_header_value(body.hmac()),
        ),
    ]);

    let body = if head {
        Default::default()
    } else {
        representation.body.clone()
    };
    (StatusCode::OK, to_header_map(resp_headers), body).into_response()
}

fn timeline_expired_response(expired: VerifiedExpiredBody, head: bool) -> axum::response::Response {
    let address = expired.requested();
    let body = "timeline body expired\n";
    let headers = to_header_map(vec![
        (
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        ),
        (header::CONTENT_LENGTH, decimal_header_value(body.len())),
        (
            HeaderName::from_static("x-timeline-world"),
            audit_header_value(address.world().as_str()),
        ),
        (
            HeaderName::from_static("x-timeline-generation"),
            audit_header_value(address.generation().as_str()),
        ),
        (
            HeaderName::from_static("x-timeline-seq"),
            HeaderValue::from_str(&address.seq().get().to_string())
                .unwrap_or_else(|_| HeaderValue::from_static("invalid")),
        ),
        (
            HeaderName::from_static("x-timeline-body-sha256"),
            audit_header_value(address.body_sha256().as_str()),
        ),
        (
            HeaderName::from_static("x-timeline-hmac"),
            audit_header_value(expired.hmac()),
        ),
        (
            HeaderName::from_static("x-timeline-expired-content-type"),
            audit_header_value(expired.content_type()),
        ),
        (
            HeaderName::from_static("x-timeline-expired-size"),
            decimal_header_value(expired.size().max(0) as usize),
        ),
    ]);
    (
        StatusCode::GONE,
        headers,
        if head { String::new() } else { body.to_owned() },
    )
        .into_response()
}

fn timeline_non_body_response(proof: VerifiedNonBodyEvent, head: bool) -> axum::response::Response {
    let requested = proof.requested();
    let body = "timeline event has no body\n";
    let mut headers = vec![
        (
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        ),
        (header::CONTENT_LENGTH, decimal_header_value(body.len())),
        (
            HeaderName::from_static("x-timeline-world"),
            audit_header_value(requested.world().as_str()),
        ),
        (
            HeaderName::from_static("x-timeline-generation"),
            audit_header_value(requested.generation().as_str()),
        ),
        (
            HeaderName::from_static("x-timeline-seq"),
            HeaderValue::from_str(&requested.seq().get().to_string())
                .unwrap_or_else(|_| HeaderValue::from_static("invalid")),
        ),
        (
            HeaderName::from_static("x-timeline-hmac"),
            audit_header_value(proof.hmac()),
        ),
        (
            HeaderName::from_static("x-timeline-event-type"),
            audit_header_value(proof.event_type()),
        ),
        (
            HeaderName::from_static("x-timeline-event-target"),
            audit_header_value(proof.event_target().as_str()),
        ),
        (
            HeaderName::from_static("x-timeline-event-body-sha256"),
            audit_header_value(proof.body_sha256().as_str()),
        ),
        (
            HeaderName::from_static("x-timeline-event-size"),
            decimal_header_value(proof.size().max(0) as usize),
        ),
        (
            HeaderName::from_static("x-timeline-event-content-type"),
            audit_header_value(proof.content_type()),
        ),
    ];
    if let Some(generation) = proof.delete_subject_generation() {
        headers.push((
            HeaderName::from_static("x-timeline-delete-subject-generation"),
            audit_header_value(generation.as_str()),
        ));
    }
    (
        StatusCode::NOT_FOUND,
        to_header_map(headers),
        if head { String::new() } else { body.to_owned() },
    )
        .into_response()
}

fn timeline_engine_error_phase(err: EngineError, head: bool) -> Phase {
    let (resp, reason) = match err {
        EngineError::Auth(gate) => (
            unauthorized("read requires read token"),
            ErrorReason::Auth(gate),
        ),
        EngineError::TransientStorage | EngineError::ShuttingDown => (
            storage_temporarily_unavailable(),
            ErrorReason::TimelineStorageRead,
        ),
        EngineError::InsufficientStorage => {
            (insufficient_storage(), ErrorReason::InsufficientStorage)
        }
        EngineError::InvalidMetadata { message } => {
            (bad_request(message), ErrorReason::TimelineStorageRead)
        }
        EngineError::Storage | EngineError::InternalInvariant(_) => (
            server_error("timeline storage failure".to_string()),
            ErrorReason::TimelineStorageRead,
        ),
        _ => (
            server_error("unexpected timeline read error".to_string()),
            ErrorReason::TimelineStorageRead,
        ),
    };
    Phase::Error {
        resp: timeline_head_response(resp, head),
        reason,
    }
}

fn timeline_error(
    status: StatusCode,
    message: &'static str,
    head: bool,
    reason: ErrorReason,
) -> Phase {
    Phase::Error {
        resp: timeline_text_response(status, message, head),
        reason,
    }
}

fn timeline_text_response(
    status: StatusCode,
    message: &str,
    head: bool,
) -> axum::response::Response {
    let body = format!("{message}\n");
    let headers = to_header_map(vec![
        (
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        ),
        (header::CONTENT_LENGTH, decimal_header_value(body.len())),
    ]);
    (status, headers, if head { String::new() } else { body }).into_response()
}

fn timeline_head_response(resp: axum::response::Response, head: bool) -> axum::response::Response {
    if !head {
        return resp;
    }
    let (parts, _) = resp.into_parts();
    axum::response::Response::from_parts(parts, axum::body::Body::empty())
}
