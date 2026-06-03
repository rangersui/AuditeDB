use super::*;
use crate::{
    engine::Engine,
    engine_types::{Preconditions, Representation, WriteResult},
    server::test_support::{
        server_state_for_engine_for_tests, server_state_for_tests, test_engine_for_server,
        test_engine_for_server_with_read_token, test_engine_for_server_with_storage_quota,
        world_db_path_for_server_tests, write_text_world_for_tests,
    },
    test_support::test_core,
    Core,
};
use axum::response::Response;
use std::sync::Arc;

fn world_path(world: &str) -> ValidatedWorldPath {
    ValidatedWorldPath::new(world).unwrap()
}

fn handler_state_for_tests(core: &Core) -> ServerState {
    server_state_for_tests(Arc::new(core.clone()))
}

fn handler_state_for_engine_tests(engine: &Engine) -> ServerState {
    server_state_for_engine_for_tests(engine.clone())
}

async fn execute_get_with_test_state(
    headers: HeaderMap,
    tier: impl Into<AccessTier>,
    world: ValidatedWorldPath,
    core: &Core,
    trace: &TraceCtx,
) -> Phase {
    let state = handler_state_for_tests(core);
    execute_get(headers, tier, world, &state, trace).await
}

async fn execute_get_with_engine_state(
    headers: HeaderMap,
    tier: impl Into<AccessTier>,
    world: ValidatedWorldPath,
    engine: &Engine,
    trace: &TraceCtx,
) -> Phase {
    let state = handler_state_for_engine_tests(engine);
    execute_get(headers, tier, world, &state, trace).await
}

async fn execute_head_with_test_state(
    headers: HeaderMap,
    tier: impl Into<AccessTier>,
    world: ValidatedWorldPath,
    core: &Core,
    trace: &TraceCtx,
) -> Phase {
    let state = handler_state_for_tests(core);
    execute_head(headers, tier, world, &state, trace).await
}

async fn execute_head_with_engine_state(
    headers: HeaderMap,
    tier: impl Into<AccessTier>,
    world: ValidatedWorldPath,
    engine: &Engine,
    trace: &TraceCtx,
) -> Phase {
    let state = handler_state_for_engine_tests(engine);
    execute_head(headers, tier, world, &state, trace).await
}

async fn execute_put_with_test_state(
    headers: HeaderMap,
    body: Bytes,
    tier: impl Into<AccessTier>,
    world: ValidatedWorldPath,
    core: &Core,
    trace: &TraceCtx,
) -> Phase {
    let state = handler_state_for_tests(core);
    execute_put(headers, body, tier, world, &state, trace).await
}

async fn execute_put_with_engine_state(
    headers: HeaderMap,
    body: Bytes,
    tier: impl Into<AccessTier>,
    world: ValidatedWorldPath,
    engine: &Engine,
    trace: &TraceCtx,
) -> Phase {
    let state = handler_state_for_engine_tests(engine);
    execute_put(headers, body, tier, world, &state, trace).await
}

async fn execute_post_with_test_state(
    headers: HeaderMap,
    body: Bytes,
    tier: impl Into<AccessTier>,
    world: ValidatedWorldPath,
    core: &Core,
    trace: &TraceCtx,
) -> Phase {
    let state = handler_state_for_tests(core);
    execute_post(headers, body, tier, world, &state, trace).await
}

async fn execute_post_with_engine_state(
    headers: HeaderMap,
    body: Bytes,
    tier: impl Into<AccessTier>,
    world: ValidatedWorldPath,
    engine: &Engine,
    trace: &TraceCtx,
) -> Phase {
    let state = handler_state_for_engine_tests(engine);
    execute_post(headers, body, tier, world, &state, trace).await
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

async fn write_representation_for_engine_tests(
    engine: &Engine,
    world: &str,
    body: &'static [u8],
    content_type: &str,
    headers: Vec<(String, String)>,
) -> WriteResult {
    engine
        .replace(
            &world_path(world),
            Representation::new(Bytes::from_static(body), content_type, headers),
            Preconditions::none(),
            AccessTier::Write,
        )
        .await
        .expect("test write should succeed")
}

#[tokio::test]
async fn get_and_head_require_read_token_when_enabled() {
    let (engine, dir) = test_engine_for_server_with_read_token("read-token-handlers", b"reader");
    write_text_world_for_tests(&engine, "home/private", "secret").await;

    let headers = HeaderMap::new();
    let get_anon = unwrap_response(
        execute_get_with_engine_state(
            headers.clone(),
            AccessTier::Anon,
            world_path("home/private"),
            &engine,
            &TraceCtx::disabled(),
        )
        .await,
    );
    assert_eq!(get_anon.status(), StatusCode::UNAUTHORIZED);
    let head_reader = unwrap_response(
        execute_head_with_engine_state(
            headers.clone(),
            AccessTier::Read,
            world_path("home/private"),
            &engine,
            &TraceCtx::disabled(),
        )
        .await,
    );
    assert_eq!(head_reader.status(), StatusCode::OK);

    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn get_and_head_honor_single_byte_range() {
    let (engine, dir) = test_engine_for_server("range-handler");
    write_text_world_for_tests(&engine, "home/range", "abcdef").await;
    let mut headers = HeaderMap::new();
    headers.insert(header::RANGE, HeaderValue::from_static("bytes=1-3"));

    let get = unwrap_response(
        execute_get_with_engine_state(
            headers.clone(),
            AccessTier::Anon,
            world_path("home/range"),
            &engine,
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
        execute_head_with_engine_state(
            headers.clone(),
            AccessTier::Anon,
            world_path("home/range"),
            &engine,
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
    let (engine, dir) = test_engine_for_server("accept-ranges");
    write_text_world_for_tests(&engine, "home/ranges", "abcdef").await;
    let headers = HeaderMap::new();

    let get = unwrap_response(
        execute_get_with_engine_state(
            headers.clone(),
            AccessTier::Anon,
            world_path("home/ranges"),
            &engine,
            &TraceCtx::disabled(),
        )
        .await,
    );
    assert_eq!(get.status(), StatusCode::OK);
    assert_eq!(get.headers().get(header::ACCEPT_RANGES).unwrap(), "bytes");

    let head = unwrap_response(
        execute_head_with_engine_state(
            headers.clone(),
            AccessTier::Anon,
            world_path("home/ranges"),
            &engine,
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
    let (engine, dir) = test_engine_for_server("range-416");
    write_text_world_for_tests(&engine, "home/range", "abcdef").await;
    let mut headers = HeaderMap::new();
    headers.insert(header::RANGE, HeaderValue::from_static("bytes=99-100"));

    let get = unwrap_response(
        execute_get_with_engine_state(
            headers.clone(),
            AccessTier::Anon,
            world_path("home/range"),
            &engine,
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
    let (engine, dir) = test_engine_for_server("multi-range");
    write_text_world_for_tests(&engine, "home/range", "abcdef").await;
    let mut headers = HeaderMap::new();
    headers.insert(header::RANGE, HeaderValue::from_static("bytes=0-1,4-5"));

    let get = unwrap_response(
        execute_get_with_engine_state(
            headers.clone(),
            AccessTier::Anon,
            world_path("home/range"),
            &engine,
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
    let (engine, dir) = test_engine_for_server("link-headers");
    write_text_world_for_tests(&engine, "home/links", "hello").await;
    let headers = HeaderMap::new();

    let get = unwrap_response(
        execute_get_with_engine_state(
            headers.clone(),
            AccessTier::Anon,
            world_path("home/links"),
            &engine,
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
        execute_head_with_engine_state(
            headers.clone(),
            AccessTier::Anon,
            world_path("home/links"),
            &engine,
            &TraceCtx::disabled(),
        )
        .await,
    );
    assert_eq!(head.headers().get_all(header::LINK).iter().count(), 2);

    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn stale_if_range_returns_full_body() {
    let (engine, dir) = test_engine_for_server("if-range-stale");
    write_text_world_for_tests(&engine, "home/range", "abcdef").await;
    let mut headers = HeaderMap::new();
    headers.insert(header::RANGE, HeaderValue::from_static("bytes=1-3"));
    headers.insert(header::IF_RANGE, HeaderValue::from_static("\"hmac-stale\""));

    let get = unwrap_response(
        execute_get_with_engine_state(
            headers.clone(),
            AccessTier::Anon,
            world_path("home/range"),
            &engine,
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
    let (engine, dir) = test_engine_for_server("read-if-none-match");
    let write = write_representation_for_engine_tests(
        &engine,
        "home/cache",
        b"cached body",
        "text/plain",
        Vec::new(),
    )
    .await;
    let etag = format!("\"{}\"", write.etag);
    let mut headers = HeaderMap::new();
    headers.insert(header::IF_NONE_MATCH, HeaderValue::from_str(&etag).unwrap());

    let get = unwrap_response(
        execute_get_with_engine_state(
            headers.clone(),
            AccessTier::Anon,
            world_path("home/cache"),
            &engine,
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
        execute_head_with_engine_state(
            headers.clone(),
            AccessTier::Anon,
            world_path("home/cache"),
            &engine,
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
        execute_get_with_engine_state(
            headers.clone(),
            AccessTier::Anon,
            world_path("home/cache"),
            &engine,
            &TraceCtx::disabled(),
        )
        .await,
    );
    assert_eq!(get.status(), StatusCode::OK);

    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn get_returns_stored_standard_representation_headers() {
    let (engine, dir) = test_engine_for_server("representation-headers");
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
    write_representation_for_engine_tests(
        &engine,
        "home/gzip",
        b"compressed bytes",
        "application/pdf",
        headers,
    )
    .await;

    let req_headers = HeaderMap::new();
    let resp = unwrap_response(
        execute_get_with_engine_state(
            req_headers.clone(),
            AccessTier::Anon,
            world_path("home/gzip"),
            &engine,
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

#[tokio::test]
async fn put_created_returns_location() {
    let (engine, dir) = test_engine_for_server("put-location");
    let headers = HeaderMap::new();
    let resp = unwrap_response(
        execute_put_with_engine_state(
            headers.clone(),
            Bytes::from_static(b"new"),
            AccessTier::Write,
            world_path("home/created"),
            &engine,
            &TraceCtx::disabled(),
        )
        .await,
    );

    assert_eq!(resp.status(), StatusCode::CREATED);
    assert_eq!(
        resp.headers().get(header::LOCATION).unwrap(),
        "/home/created"
    );

    let resp = unwrap_response(
        execute_put_with_engine_state(
            headers.clone(),
            Bytes::from_static(b"again"),
            AccessTier::Write,
            world_path("home/created"),
            &engine,
            &TraceCtx::disabled(),
        )
        .await,
    );
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers().get(header::LOCATION).is_none());

    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn location_and_link_headers_percent_encode_world_urls() {
    let (engine, dir) = test_engine_for_server("encoded-headers");
    let headers = HeaderMap::new();
    let resp = unwrap_response(
        execute_put_with_engine_state(
            headers.clone(),
            Bytes::from_static(b"new"),
            AccessTier::Write,
            world_path("home/café report"),
            &engine,
            &TraceCtx::disabled(),
        )
        .await,
    );
    assert_eq!(resp.status(), StatusCode::CREATED);
    assert_eq!(
        resp.headers().get(header::LOCATION).unwrap(),
        "/home/caf%C3%A9%20report"
    );

    let get = unwrap_response(
        execute_get_with_engine_state(
            headers.clone(),
            AccessTier::Anon,
            world_path("home/café report"),
            &engine,
            &TraceCtx::disabled(),
        )
        .await,
    );
    let links: Vec<_> = get.headers().get_all(header::LINK).iter().collect();
    assert!(links
        .iter()
        .any(|v| *v == "</listen/home/caf%C3%A9%20report>; rel=\"monitor\""));

    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn unicode_world_get_preserves_body_headers_and_monitor_link() {
    let (engine, dir) = test_engine_for_server("unicode-roundtrip");
    let headers = vec![(
        "content-disposition".to_string(),
        "attachment; filename*=UTF-8''%E6%8A%A5%E5%91%8A.pdf".to_string(),
    )];
    write_representation_for_engine_tests(
        &engine,
        "home/销售/报告",
        "你好，世界".as_bytes(),
        "text/plain; charset=utf-8",
        headers,
    )
    .await;

    let get = unwrap_response(
        execute_get_with_engine_state(
            HeaderMap::new(),
            AccessTier::Anon,
            world_path("home/销售/报告"),
            &engine,
            &TraceCtx::disabled(),
        )
        .await,
    );
    assert_eq!(get.status(), StatusCode::OK);
    assert_eq!(
        get.headers().get(header::CONTENT_TYPE).unwrap(),
        "text/plain; charset=utf-8"
    );
    assert_eq!(
        get.headers().get(header::CONTENT_DISPOSITION).unwrap(),
        "attachment; filename*=UTF-8''%E6%8A%A5%E5%91%8A.pdf"
    );
    assert!(get
        .headers()
        .get_all(header::LINK)
        .iter()
        .any(|v| *v == "</listen/home/%E9%94%80%E5%94%AE/%E6%8A%A5%E5%91%8A>; rel=\"monitor\""));

    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn put_and_post_honor_write_preconditions_at_handler_level() {
    let (engine, dir) = test_engine_for_server("write-preconditions");
    let write = write_representation_for_engine_tests(
        &engine,
        "home/cas",
        b"one",
        "text/plain; charset=utf-8",
        Vec::new(),
    )
    .await;

    let mut stale = HeaderMap::new();
    stale.insert(header::IF_MATCH, HeaderValue::from_static("\"hmac-stale\""));
    let put = unwrap_response(
        execute_put_with_engine_state(
            stale.clone(),
            Bytes::from_static(b"two"),
            AccessTier::Write,
            world_path("home/cas"),
            &engine,
            &TraceCtx::disabled(),
        )
        .await,
    );
    assert_eq!(put.status(), StatusCode::PRECONDITION_FAILED);

    let post = unwrap_response(
        execute_post_with_engine_state(
            stale.clone(),
            Bytes::from_static(b" plus"),
            AccessTier::Write,
            world_path("home/cas"),
            &engine,
            &TraceCtx::disabled(),
        )
        .await,
    );
    assert_eq!(post.status(), StatusCode::PRECONDITION_FAILED);

    let mut good = HeaderMap::new();
    good.insert(
        header::IF_MATCH,
        HeaderValue::from_str(&format!("\"{}\"", write.etag)).unwrap(),
    );
    let post = unwrap_response(
        execute_post_with_engine_state(
            good.clone(),
            Bytes::from_static(b" plus"),
            AccessTier::Write,
            world_path("home/cas"),
            &engine,
            &TraceCtx::disabled(),
        )
        .await,
    );
    assert_eq!(post.status(), StatusCode::OK);

    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn post_audit_uses_existing_representation_metadata() {
    let (engine, dir) = test_engine_for_server("post-audit-meta");
    let headers = vec![
        ("content-encoding".to_string(), "gzip".to_string()),
        ("x-meta-author".to_string(), "ranger".to_string()),
    ];
    write_representation_for_engine_tests(
        &engine,
        "home/post-audit-meta",
        b"hello",
        "text/plain",
        headers.clone(),
    )
    .await;

    let mut req_headers = HeaderMap::new();
    req_headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/pdf"),
    );
    req_headers.insert(header::CONTENT_LANGUAGE, HeaderValue::from_static("zh-CN"));
    let resp = unwrap_response(
        execute_post_with_engine_state(
            req_headers.clone(),
            Bytes::from_static(b" world"),
            AccessTier::Write,
            world_path("home/post-audit-meta"),
            &engine,
            &TraceCtx::disabled(),
        )
        .await,
    );
    assert_eq!(resp.status(), StatusCode::OK);

    let c =
        rusqlite::Connection::open(world_db_path_for_server_tests(&dir, "home/post-audit-meta"))
            .unwrap();
    let content_type: String = c
        .query_row(
            "SELECT content_type FROM events WHERE event_type='append'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(content_type, "text/plain");
    let event_headers: Vec<(String, String)> = c
        .prepare(
            "SELECT name, value FROM event_headers \
             WHERE event_id=(SELECT id FROM events WHERE event_type='append') \
             ORDER BY name",
        )
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(event_headers, headers);

    let language_count: i64 = c
        .query_row(
            "SELECT COUNT(*) FROM event_headers WHERE name='content-language'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(language_count, 0);

    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn durable_storage_quota_returns_507_without_writing() {
    let (engine, dir) = test_engine_for_server_with_storage_quota("storage-quota", 4);
    let headers = HeaderMap::new();

    let first = unwrap_response(
        execute_put_with_engine_state(
            headers.clone(),
            Bytes::from_static(b"1234"),
            AccessTier::Write,
            world_path("home/a"),
            &engine,
            &TraceCtx::disabled(),
        )
        .await,
    );
    assert_eq!(first.status(), StatusCode::CREATED);

    let over = unwrap_response(
        execute_put_with_engine_state(
            headers.clone(),
            Bytes::from_static(b"5"),
            AccessTier::Write,
            world_path("home/b"),
            &engine,
            &TraceCtx::disabled(),
        )
        .await,
    );
    assert_eq!(over.status(), StatusCode::INSUFFICIENT_STORAGE);
    assert_eq!(over.headers().get("x-storage-usage").unwrap(), "4");
    assert_eq!(over.headers().get("x-storage-quota").unwrap(), "4");
    assert_eq!(over.headers().get("x-storage-needed").unwrap(), "1");
    assert!(engine
        .read(&world_path("home/b"), AccessTier::Read)
        .unwrap()
        .is_none());

    let append = unwrap_response(
        execute_post_with_engine_state(
            headers.clone(),
            Bytes::from_static(b"5"),
            AccessTier::Write,
            world_path("home/a"),
            &engine,
            &TraceCtx::disabled(),
        )
        .await,
    );
    assert_eq!(append.status(), StatusCode::INSUFFICIENT_STORAGE);
    assert_eq!(append.headers().get("x-storage-usage").unwrap(), "4");
    assert_eq!(append.headers().get("x-storage-quota").unwrap(), "4");
    assert_eq!(append.headers().get("x-storage-needed").unwrap(), "1");
    assert_eq!(
        engine
            .read(&world_path("home/a"), AccessTier::Read)
            .unwrap()
            .unwrap()
            .representation
            .body
            .as_ref(),
        b"1234"
    );

    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn concurrent_puts_to_distinct_worlds_do_not_overshoot_quota() {
    // Regression: under per-world locks, the previous "snapshot then
    // write then adjust" pattern let two concurrent PUTs to different
    // worlds both observe usage below quota, both commit, and only
    // afterwards push the counter past quota (lost-update race).
    // Atomic CAS reservation in `Core::reserve_storage` closes that
    // race. This test fires N concurrent PUTs each just under the
    // quota and asserts that ANY mix of accept/reject keeps the
    // counter coherent and never overshoots.
    let quota = 100;
    let (engine, dir) = test_engine_for_server_with_storage_quota("quota-race", quota);

    let workers = 16;
    let body_len = 12; // 16 * 12 = 192 > quota: definitely contention
    let mut handles = Vec::with_capacity(workers);
    for i in 0..workers {
        let engine = engine.clone();
        handles.push(tokio::spawn(async move {
            let path = format!("home/race/{i}");
            let body = Bytes::copy_from_slice(&vec![b'x'; body_len]);
            unwrap_response(
                execute_put_with_engine_state(
                    HeaderMap::new(),
                    body,
                    AccessTier::Write,
                    world_path(&path),
                    &engine,
                    &TraceCtx::disabled(),
                )
                .await,
            )
        }));
    }

    let mut accepted: usize = 0;
    for handle in handles {
        let resp = handle.await.unwrap();
        match resp.status() {
            StatusCode::CREATED | StatusCode::OK => accepted += 1,
            StatusCode::INSUFFICIENT_STORAGE => {}
            other => panic!("unexpected status: {other}"),
        }
    }

    let used = engine.df(AccessTier::Read).unwrap().storage_used;
    let counted = accepted * body_len;
    assert_eq!(used, counted, "counter must equal sum of accepted bodies");
    assert![
        used <= quota,
        "counter must never exceed quota: {used} > {quota}"
    ];

    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn concurrent_memory_puts_do_not_overshoot_max_memory_bytes() {
    // Mirror of concurrent_puts_to_distinct_worlds_do_not_overshoot_quota
    // for memory worlds. Per-world locks let writes to /tmp/a and
    // /tmp/b run concurrently; before this fix each one would read
    // total_bytes() as a snapshot, both pass the budget check, and
    // both commit -- overshooting ELASTIK_MAX_MEMORY_BYTES. With the
    // check + write fused under the MemoryStore HashMap mutex inside
    // write_with_quota, only the writes whose accept order keeps the
    // running total under the cap can commit.
    let (mut core, dir) = test_core("memory-quota-race");
    let cap = 100;
    core.max_memory_bytes = cap;
    let core = Arc::new(core);

    let workers = 16;
    let body_len = 12; // 16 * 12 = 192 > cap: forced contention
    let mut handles = Vec::with_capacity(workers);
    for i in 0..workers {
        let core = core.clone();
        handles.push(tokio::spawn(async move {
            let path = format!("tmp/race/{i}");
            let body = Bytes::copy_from_slice(&vec![b'm'; body_len]);
            unwrap_response(
                execute_put_with_test_state(
                    HeaderMap::new(),
                    body,
                    AccessTier::Write,
                    world_path(&path),
                    &core,
                    &TraceCtx::disabled(),
                )
                .await,
            )
        }));
    }

    let mut accepted: usize = 0;
    for handle in handles {
        let resp = handle.await.unwrap();
        match resp.status() {
            StatusCode::CREATED | StatusCode::OK => accepted += 1,
            StatusCode::PAYLOAD_TOO_LARGE => {}
            other => panic!("unexpected status: {other}"),
        }
    }

    let used = core.mem.total_bytes();
    let counted = accepted * body_len;
    assert_eq!(
        used, counted,
        "memory total must equal sum of accepted bodies"
    );
    assert!(
        used <= cap,
        "memory total must never exceed cap: {used} > {cap}"
    );

    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn put_and_post_enforce_world_size_cap() {
    let (mut core, dir) = test_core("world-size-cap");
    core.max_world_bytes = 4;
    let headers = HeaderMap::new();

    let too_big = unwrap_response(
        execute_put_with_test_state(
            headers.clone(),
            Bytes::from_static(b"12345"),
            AccessTier::Write,
            world_path("home/too-big"),
            &core,
            &TraceCtx::disabled(),
        )
        .await,
    );
    assert_eq!(too_big.status(), StatusCode::PAYLOAD_TOO_LARGE);

    let ok = unwrap_response(
        execute_put_with_test_state(
            headers.clone(),
            Bytes::from_static(b"1234"),
            AccessTier::Write,
            world_path("home/four"),
            &core,
            &TraceCtx::disabled(),
        )
        .await,
    );
    assert_eq!(ok.status(), StatusCode::CREATED);

    let append = unwrap_response(
        execute_post_with_test_state(
            headers.clone(),
            Bytes::from_static(b"5"),
            AccessTier::Write,
            world_path("home/four"),
            &core,
            &TraceCtx::disabled(),
        )
        .await,
    );
    assert_eq!(append.status(), StatusCode::PAYLOAD_TOO_LARGE);

    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn memory_backend_enforces_total_quota() {
    let (mut core, dir) = test_core("memory-quota");
    core.max_memory_bytes = 4;
    let headers = HeaderMap::new();

    let first = unwrap_response(
        execute_put_with_test_state(
            headers.clone(),
            Bytes::from_static(b"12"),
            AccessTier::Write,
            world_path("tmp/a"),
            &core,
            &TraceCtx::disabled(),
        )
        .await,
    );
    assert_eq!(first.status(), StatusCode::CREATED);
    let second = unwrap_response(
        execute_put_with_test_state(
            headers.clone(),
            Bytes::from_static(b"34"),
            AccessTier::Write,
            world_path("tmp/b"),
            &core,
            &TraceCtx::disabled(),
        )
        .await,
    );
    assert_eq!(second.status(), StatusCode::CREATED);
    let third = unwrap_response(
        execute_put_with_test_state(
            headers.clone(),
            Bytes::from_static(b"5"),
            AccessTier::Write,
            world_path("tmp/c"),
            &core,
            &TraceCtx::disabled(),
        )
        .await,
    );
    assert_eq!(third.status(), StatusCode::PAYLOAD_TOO_LARGE);

    let _ = std::fs::remove_dir_all(dir);
}
