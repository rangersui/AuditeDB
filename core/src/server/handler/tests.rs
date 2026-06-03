use super::*;
use crate::{etag as et, test_support::test_core, world};
use axum::response::Response;

fn world_path(world: &str) -> ValidatedWorldPath {
    ValidatedWorldPath::new(world).unwrap()
}

fn unwrap_response(phase: Phase) -> Response {
    match phase {
        Phase::ExecutedRead(r) | Phase::CommittedWrite(r) | Phase::Done(r) => r,
        Phase::Error { resp, .. } => resp,
        Phase::Received { .. }
        | Phase::Authenticated { .. }
        | Phase::PathValidated { .. }
        | Phase::Dispatched { .. } => {
            panic!("execute_* returned a non-terminal Phase variant")
        }
    }
}

#[tokio::test]
async fn get_and_head_require_read_token_when_enabled() {
    let (mut core, dir) = test_core("read-token-handlers");
    core.write_world("home/private", b"secret", "text/plain", &[])
        .unwrap();
    core.tokens.read = crate::auth::NonEmptyBytes::new(b"reader".to_vec());

    let headers = HeaderMap::new();
    let get_anon = unwrap_response(
        execute_get(
            headers.clone(),
            AccessTier::Anon,
            world_path("home/private"),
            &core,
            &TraceCtx::disabled(),
        )
        .await,
    );
    assert_eq!(get_anon.status(), StatusCode::UNAUTHORIZED);
    let head_reader = unwrap_response(
        execute_head(
            headers.clone(),
            AccessTier::Read,
            world_path("home/private"),
            &core,
            &TraceCtx::disabled(),
        )
        .await,
    );
    assert_eq!(head_reader.status(), StatusCode::OK);

    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn get_and_head_honor_single_byte_range() {
    let (core, dir) = test_core("range-handler");
    core.write_world("home/range", b"abcdef", "text/plain", &[])
        .unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(header::RANGE, HeaderValue::from_static("bytes=1-3"));

    let get = unwrap_response(
        execute_get(
            headers.clone(),
            AccessTier::Anon,
            world_path("home/range"),
            &core,
            &TraceCtx::disabled(),
        )
        .await,
    );
    assert_eq!(get.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        get.headers().get(header::CONTENT_RANGE).unwrap(),
        "bytes 1-3/6"
    );
    assert_eq!(get.headers().get(header::CONTENT_LENGTH).unwrap(), "3");

    let head = unwrap_response(
        execute_head(
            headers.clone(),
            AccessTier::Anon,
            world_path("home/range"),
            &core,
            &TraceCtx::disabled(),
        )
        .await,
    );
    assert_eq!(head.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        head.headers().get(header::CONTENT_RANGE).unwrap(),
        "bytes 1-3/6"
    );
    assert_eq!(head.headers().get(header::CONTENT_LENGTH).unwrap(), "3");

    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn get_and_head_advertise_accept_ranges_on_full_body() {
    let (core, dir) = test_core("accept-ranges");
    core.write_world("home/ranges", b"abcdef", "text/plain", &[])
        .unwrap();
    let headers = HeaderMap::new();

    let get = unwrap_response(
        execute_get(
            headers.clone(),
            AccessTier::Anon,
            world_path("home/ranges"),
            &core,
            &TraceCtx::disabled(),
        )
        .await,
    );
    assert_eq!(get.status(), StatusCode::OK);
    assert_eq!(get.headers().get(header::ACCEPT_RANGES).unwrap(), "bytes");

    let head = unwrap_response(
        execute_head(
            headers.clone(),
            AccessTier::Anon,
            world_path("home/ranges"),
            &core,
            &TraceCtx::disabled(),
        )
        .await,
    );
    assert_eq!(head.status(), StatusCode::OK);
    assert_eq!(head.headers().get(header::ACCEPT_RANGES).unwrap(), "bytes");

    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn unsatisfied_range_returns_416_with_content_range() {
    let (core, dir) = test_core("range-416");
    core.write_world("home/range", b"abcdef", "text/plain", &[])
        .unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(header::RANGE, HeaderValue::from_static("bytes=99-100"));

    let get = unwrap_response(
        execute_get(
            headers.clone(),
            AccessTier::Anon,
            world_path("home/range"),
            &core,
            &TraceCtx::disabled(),
        )
        .await,
    );
    assert_eq!(get.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(
        get.headers().get(header::CONTENT_RANGE).unwrap(),
        "bytes */6"
    );
    assert_eq!(get.headers().get(header::ACCEPT_RANGES).unwrap(), "bytes");

    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn multi_range_is_ignored_and_returns_full_body() {
    let (core, dir) = test_core("multi-range");
    core.write_world("home/range", b"abcdef", "text/plain", &[])
        .unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(header::RANGE, HeaderValue::from_static("bytes=0-1,4-5"));

    let get = unwrap_response(
        execute_get(
            headers.clone(),
            AccessTier::Anon,
            world_path("home/range"),
            &core,
            &TraceCtx::disabled(),
        )
        .await,
    );
    assert_eq!(get.status(), StatusCode::OK);
    assert!(get.headers().get(header::CONTENT_RANGE).is_none());
    assert_eq!(get.headers().get(header::CONTENT_LENGTH).unwrap(), "6");

    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn world_reads_advertise_monitor_and_collection_links() {
    let (core, dir) = test_core("link-headers");
    core.write_world("home/links", b"hello", "text/plain", &[])
        .unwrap();
    let headers = HeaderMap::new();

    let get = unwrap_response(
        execute_get(
            headers.clone(),
            AccessTier::Anon,
            world_path("home/links"),
            &core,
            &TraceCtx::disabled(),
        )
        .await,
    );
    let links: Vec<_> = get.headers().get_all(header::LINK).iter().collect();
    assert_eq!(links.len(), 2);
    assert!(links
        .iter()
        .any(|v| *v == "</listen/home/links>; rel=\"monitor\""));
    assert!(links
        .iter()
        .any(|v| *v == "</proc/worlds>; rel=\"collection\""));

    let head = unwrap_response(
        execute_head(
            headers.clone(),
            AccessTier::Anon,
            world_path("home/links"),
            &core,
            &TraceCtx::disabled(),
        )
        .await,
    );
    assert_eq!(head.headers().get_all(header::LINK).iter().count(), 2);

    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn stale_if_range_returns_full_body() {
    let (core, dir) = test_core("if-range-stale");
    core.write_world("home/range", b"abcdef", "text/plain", &[])
        .unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(header::RANGE, HeaderValue::from_static("bytes=1-3"));
    headers.insert(header::IF_RANGE, HeaderValue::from_static("\"hmac-stale\""));

    let get = unwrap_response(
        execute_get(
            headers.clone(),
            AccessTier::Anon,
            world_path("home/range"),
            &core,
            &TraceCtx::disabled(),
        )
        .await,
    );
    assert_eq!(get.status(), StatusCode::OK);
    assert!(get.headers().get(header::CONTENT_RANGE).is_none());
    assert_eq!(get.headers().get(header::CONTENT_LENGTH).unwrap(), "6");

    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn get_and_head_honor_if_none_match_cache_revalidation() {
    let (core, dir) = test_core("read-if-none-match");
    let h = world::write_with_audit(
        &core.data,
        "home/cache",
        b"cached body",
        "text/plain",
        &[],
        &core.hmac_key,
    )
    .unwrap();
    let etag = format!("\"{}\"", et::hmac_etag(&h));
    let mut headers = HeaderMap::new();
    headers.insert(header::IF_NONE_MATCH, HeaderValue::from_str(&etag).unwrap());

    let get = unwrap_response(
        execute_get(
            headers.clone(),
            AccessTier::Anon,
            world_path("home/cache"),
            &core,
            &TraceCtx::disabled(),
        )
        .await,
    );
    assert_eq!(get.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(get.headers().get(header::ETAG).unwrap(), etag.as_str());
    assert!(get
        .headers()
        .get_all(header::LINK)
        .iter()
        .any(|v| v == "</listen/home/cache>; rel=\"monitor\""));

    let head = unwrap_response(
        execute_head(
            headers.clone(),
            AccessTier::Anon,
            world_path("home/cache"),
            &core,
            &TraceCtx::disabled(),
        )
        .await,
    );
    assert_eq!(head.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(head.headers().get(header::ETAG).unwrap(), etag.as_str());

    headers.insert(
        header::IF_NONE_MATCH,
        HeaderValue::from_static("\"hmac-stale\""),
    );
    let get = unwrap_response(
        execute_get(
            headers.clone(),
            AccessTier::Anon,
            world_path("home/cache"),
            &core,
            &TraceCtx::disabled(),
        )
        .await,
    );
    assert_eq!(get.status(), StatusCode::OK);

    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn get_returns_stored_standard_representation_headers() {
    let (core, dir) = test_core("representation-headers");
    let headers = vec![
        ("content-encoding".to_string(), "gzip".to_string()),
        (
            "content-disposition".to_string(),
            "attachment; filename=\"report.pdf\"".to_string(),
        ),
        ("access-control-allow-origin".to_string(), "*".to_string()),
        (
            "content-security-policy".to_string(),
            "default-src 'self'".to_string(),
        ),
        ("x-frame-options".to_string(), "DENY".to_string()),
    ];
    core.write_world(
        "home/gzip",
        b"compressed bytes",
        "application/pdf",
        &headers,
    )
    .unwrap();

    let req_headers = HeaderMap::new();
    let resp = unwrap_response(
        execute_get(
            req_headers.clone(),
            AccessTier::Anon,
            world_path("home/gzip"),
            &core,
            &TraceCtx::disabled(),
        )
        .await,
    );
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get(header::CONTENT_ENCODING).unwrap(),
        "gzip"
    );
    assert_eq!(
        resp.headers().get(header::CONTENT_DISPOSITION).unwrap(),
        "attachment; filename=\"report.pdf\""
    );
    assert_eq!(
        resp.headers().get("access-control-allow-origin").unwrap(),
        "*"
    );
    assert_eq!(
        resp.headers().get("content-security-policy").unwrap(),
        "default-src 'self'"
    );
    assert_eq!(resp.headers().get("x-frame-options").unwrap(), "DENY");

    let _ = std::fs::remove_dir_all(dir);
}
