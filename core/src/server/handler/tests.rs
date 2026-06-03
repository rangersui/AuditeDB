use super::*;
use crate::{etag as et, test_support::test_core, world, Core};
use axum::response::Response;
use std::sync::atomic::Ordering;
use std::sync::Arc;

impl HandlerEngineState for &Arc<Core> {
    fn engine(&self) -> Engine {
        Engine::from_core_for_tests((*self).clone())
    }

    fn persist_header_allowlist(&self) -> Arc<HeaderAllowlist> {
        // Legacy white-box tests that pass Core directly use the default HTTP
        // adapter policy. Tests for custom policy should construct ServerState.
        Arc::new(HeaderAllowlist::empty())
    }

    fn persist_header_user_deny(&self) -> Arc<HeaderAllowlist> {
        Arc::new(HeaderAllowlist::empty())
    }
}

impl HandlerEngineState for &Core {
    fn engine(&self) -> Engine {
        Engine::from_core_for_tests(Arc::new((*self).clone()))
    }

    fn persist_header_allowlist(&self) -> Arc<HeaderAllowlist> {
        // Legacy white-box tests that pass Core directly use the default HTTP
        // adapter policy. Tests for custom policy should construct ServerState.
        Arc::new(HeaderAllowlist::empty())
    }

    fn persist_header_user_deny(&self) -> Arc<HeaderAllowlist> {
        Arc::new(HeaderAllowlist::empty())
    }
}

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

#[tokio::test]
async fn put_created_returns_location() {
    let (core, dir) = test_core("put-location");
    let headers = HeaderMap::new();
    let resp = unwrap_response(
        execute_put(
            headers.clone(),
            Bytes::from_static(b"new"),
            AccessTier::Write,
            world_path("home/created"),
            &core,
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
        execute_put(
            headers.clone(),
            Bytes::from_static(b"again"),
            AccessTier::Write,
            world_path("home/created"),
            &core,
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
    let (core, dir) = test_core("encoded-headers");
    let headers = HeaderMap::new();
    let resp = unwrap_response(
        execute_put(
            headers.clone(),
            Bytes::from_static(b"new"),
            AccessTier::Write,
            world_path("home/café report"),
            &core,
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
        execute_get(
            headers.clone(),
            AccessTier::Anon,
            world_path("home/café report"),
            &core,
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
    let (core, dir) = test_core("unicode-roundtrip");
    let headers = vec![(
        "content-disposition".to_string(),
        "attachment; filename*=UTF-8''%E6%8A%A5%E5%91%8A.pdf".to_string(),
    )];
    core.write_world(
        "home/销售/报告",
        "你好，世界".as_bytes(),
        "text/plain; charset=utf-8",
        &headers,
    )
    .unwrap();

    let get = unwrap_response(
        execute_get(
            HeaderMap::new(),
            AccessTier::Anon,
            world_path("home/销售/报告"),
            &core,
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
    let (core, dir) = test_core("write-preconditions");
    let h = world::write_with_audit(
        &core.data,
        "home/cas",
        b"one",
        "text/plain; charset=utf-8",
        &[],
        &core.hmac_key,
    )
    .unwrap();

    let mut stale = HeaderMap::new();
    stale.insert(header::IF_MATCH, HeaderValue::from_static("\"hmac-stale\""));
    let put = unwrap_response(
        execute_put(
            stale.clone(),
            Bytes::from_static(b"two"),
            AccessTier::Write,
            world_path("home/cas"),
            &core,
            &TraceCtx::disabled(),
        )
        .await,
    );
    assert_eq!(put.status(), StatusCode::PRECONDITION_FAILED);

    let post = unwrap_response(
        execute_post(
            stale.clone(),
            Bytes::from_static(b" plus"),
            AccessTier::Write,
            world_path("home/cas"),
            &core,
            &TraceCtx::disabled(),
        )
        .await,
    );
    assert_eq!(post.status(), StatusCode::PRECONDITION_FAILED);

    let mut good = HeaderMap::new();
    good.insert(
        header::IF_MATCH,
        HeaderValue::from_str(&format!("\"{}\"", et::hmac_etag(&h))).unwrap(),
    );
    let post = unwrap_response(
        execute_post(
            good.clone(),
            Bytes::from_static(b" plus"),
            AccessTier::Write,
            world_path("home/cas"),
            &core,
            &TraceCtx::disabled(),
        )
        .await,
    );
    assert_eq!(post.status(), StatusCode::OK);

    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn post_audit_uses_existing_representation_metadata() {
    let (core, dir) = test_core("post-audit-meta");
    let headers = vec![
        ("content-encoding".to_string(), "gzip".to_string()),
        ("x-meta-author".to_string(), "ranger".to_string()),
    ];
    world::write_with_audit(
        &core.data,
        "home/post-audit-meta",
        b"hello",
        "text/plain",
        &headers,
        &core.hmac_key,
    )
    .unwrap();

    let mut req_headers = HeaderMap::new();
    req_headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/pdf"),
    );
    req_headers.insert(header::CONTENT_LANGUAGE, HeaderValue::from_static("zh-CN"));
    let resp = unwrap_response(
        execute_post(
            req_headers.clone(),
            Bytes::from_static(b" world"),
            AccessTier::Write,
            world_path("home/post-audit-meta"),
            &core,
            &TraceCtx::disabled(),
        )
        .await,
    );
    assert_eq!(resp.status(), StatusCode::OK);

    let c =
        rusqlite::Connection::open(world::world_db(&core.data, "home/post-audit-meta")).unwrap();
    let (content_type, meta_sha256): (String, String) = c
        .query_row(
            "SELECT content_type, meta_sha256 FROM events WHERE event_type='append'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(content_type, "text/plain");
    assert_eq!(
        meta_sha256,
        crate::audit::meta_sha256("text/plain", &headers)
    );

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
    let (mut core, dir) = test_core("storage-quota");
    core.max_storage_bytes = Some(4);
    let headers = HeaderMap::new();

    let first = unwrap_response(
        execute_put(
            headers.clone(),
            Bytes::from_static(b"1234"),
            AccessTier::Write,
            world_path("home/a"),
            &core,
            &TraceCtx::disabled(),
        )
        .await,
    );
    assert_eq!(first.status(), StatusCode::CREATED);

    let over = unwrap_response(
        execute_put(
            headers.clone(),
            Bytes::from_static(b"5"),
            AccessTier::Write,
            world_path("home/b"),
            &core,
            &TraceCtx::disabled(),
        )
        .await,
    );
    assert_eq!(over.status(), StatusCode::INSUFFICIENT_STORAGE);
    assert_eq!(over.headers().get("x-storage-usage").unwrap(), "4");
    assert_eq!(over.headers().get("x-storage-quota").unwrap(), "4");
    assert_eq!(over.headers().get("x-storage-needed").unwrap(), "1");
    assert!(core.read_world("home/b").unwrap().is_none());

    let append = unwrap_response(
        execute_post(
            headers.clone(),
            Bytes::from_static(b"5"),
            AccessTier::Write,
            world_path("home/a"),
            &core,
            &TraceCtx::disabled(),
        )
        .await,
    );
    assert_eq!(append.status(), StatusCode::INSUFFICIENT_STORAGE);
    assert_eq!(append.headers().get("x-storage-usage").unwrap(), "4");
    assert_eq!(append.headers().get("x-storage-quota").unwrap(), "4");
    assert_eq!(append.headers().get("x-storage-needed").unwrap(), "1");
    assert_eq!(
        core.read_world("home/a").unwrap().unwrap().body,
        b"1234".to_vec()
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
    let (mut core, dir) = test_core("quota-race");
    let quota = 100;
    core.max_storage_bytes = Some(quota);
    let core = Arc::new(core);

    let workers = 16;
    let body_len = 12; // 16 * 12 = 192 > quota: definitely contention
    let mut handles = Vec::with_capacity(workers);
    for i in 0..workers {
        let core = core.clone();
        handles.push(tokio::spawn(async move {
            let path = format!("home/race/{i}");
            let body = Bytes::copy_from_slice(&vec![b'x'; body_len]);
            unwrap_response(
                execute_put(
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
            StatusCode::INSUFFICIENT_STORAGE => {}
            other => panic!("unexpected status: {other}"),
        }
    }

    let used = core.storage_body_bytes.load(Ordering::Relaxed);
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
                execute_put(
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
        execute_put(
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
        execute_put(
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
        execute_post(
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
        execute_put(
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
        execute_put(
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
        execute_put(
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
