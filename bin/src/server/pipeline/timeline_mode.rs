use axum::{
    body::{Body, Bytes},
    http::{HeaderMap, Method},
    response::Response,
};

use crate::{
    engine_types::{AccessTier, ValidatedWorldPath},
    server::{bad_request, method_not_allowed, uri_too_long},
    timeline::TimelineCoordinate,
};

use super::{
    dispatch, query, ErrorReason, Phase, RawQuery, TimelineQueryError, TimelineRequestMode,
};

pub(crate) const TIMELINE_ALLOW: &str = "GET, HEAD, OPTIONS";

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum TimelineVerb {
    Get,
    Head,
}

pub(super) fn classify_timeline_request(
    method: Method,
    raw_query: RawQuery,
    headers: HeaderMap,
    body: Bytes,
    tier: AccessTier,
    world: ValidatedWorldPath,
) -> Phase {
    match raw_query.classify_timeline_mode(&world) {
        Ok(TimelineRequestMode::Current) => dispatch(method, headers, body, tier, world),
        Ok(TimelineRequestMode::Timeline(coordinate)) => {
            dispatch_timeline(method, coordinate, tier)
        }
        Err(err) => timeline_query_error(method, err),
    }
}

fn dispatch_timeline(method: Method, coordinate: TimelineCoordinate, tier: AccessTier) -> Phase {
    let verb = match method {
        Method::GET => TimelineVerb::Get,
        Method::HEAD => TimelineVerb::Head,
        _ => {
            return Phase::Error {
                resp: method_not_allowed(TIMELINE_ALLOW),
                reason: ErrorReason::TimelineMethodNotAllowed,
            };
        }
    };
    Phase::TimelineDispatched {
        verb,
        coordinate,
        tier,
    }
}

fn timeline_query_error(method: Method, err: TimelineQueryError) -> Phase {
    let (resp, reason) = match err {
        TimelineQueryError::RawQueryTooLong => (
            uri_too_long(&format!(
                "timeline query exceeds {} bytes",
                query::MAX_RAW_QUERY_BYTES
            )),
            ErrorReason::TimelineRequestTargetTooLong,
        ),
        other => {
            let message = format!("invalid timeline query: {other:?}");
            (bad_request(&message), ErrorReason::TimelineQuery(other))
        }
    };
    Phase::Error {
        resp: empty_body_for_head(method, resp),
        reason,
    }
}

fn empty_body_for_head(method: Method, resp: Response) -> Response {
    if method != Method::HEAD {
        return resp;
    }
    let (parts, _) = resp.into_parts();
    Response::from_parts(parts, Body::empty())
}
