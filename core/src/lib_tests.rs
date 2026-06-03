use super::*;
use crate::etag as et;
use crate::handler::{execute_delete, execute_get, execute_post, execute_put};
use crate::test_support::test_core;
use axum::body::Bytes;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;
use std::sync::atomic::Ordering;
use std::sync::Arc;

fn server_state_for_tests(core: Arc<Core>) -> crate::server::ServerState {
    crate::server::ServerState::from_core_for_tests(core, DEFAULT_MAX_WORLD_BYTES)
}

/// PR 4c: 50 unit tests below were renamed mechanically from
/// `handle_*` (sync `&Core -> Response`) to `execute_*` (async
/// `&Core, &TraceCtx -> Phase`). The verb-handler entry point
/// returns `Phase`, but the assertions all operate on the
/// underlying `Response`. This helper unwraps the three terminal
/// `Phase` variants `execute_*` can return so tests can keep
/// asserting on `.status()` / `.headers()` without scaffolding
/// per call site.
fn unwrap_response(phase: Phase) -> Response {
    match phase {
        Phase::ExecutedRead(r) | Phase::CommittedWrite(r) | Phase::Done(r) => r,
        Phase::Error { resp, .. } => resp,
        // execute_* never returns a non-terminal Phase; reaching
        // any of these would be a bug in the handler module.
        Phase::Received { .. }
        | Phase::Authenticated { .. }
        | Phase::PathValidated { .. }
        | Phase::Dispatched { .. } => {
            panic!("execute_* returned a non-terminal Phase variant")
        }
    }
}

fn world_path(world: &str) -> crate::engine_types::ValidatedWorldPath {
    crate::engine_types::ValidatedWorldPath::new(world).unwrap()
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
            auth::Tier::Write,
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
            auth::Tier::Write,
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
            auth::Tier::Write,
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
                    auth::Tier::Write,
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
    assert!(
        used <= quota,
        "counter must never exceed quota: {used} > {quota}"
    );

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
                    auth::Tier::Write,
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
            auth::Tier::Write,
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
            auth::Tier::Write,
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
            auth::Tier::Write,
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
            auth::Tier::Write,
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
            auth::Tier::Write,
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
            auth::Tier::Write,
            world_path("tmp/c"),
            &core,
            &TraceCtx::disabled(),
        )
        .await,
    );
    assert_eq!(third.status(), StatusCode::PAYLOAD_TOO_LARGE);

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
            auth::Tier::Write,
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
            auth::Tier::Write,
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
            auth::Tier::Write,
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
            auth::Tier::Anon,
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
async fn unicode_worlds_roundtrip_body_headers_and_proc_listing() {
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

    let req_headers = HeaderMap::new();
    let get = unwrap_response(
        execute_get(
            req_headers.clone(),
            auth::Tier::Anon,
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

    let names = store::list_all(&core.data, &core.mem);
    assert_eq!(world_list_body(&names.unwrap()), "home/销售/报告\n");

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
            auth::Tier::Write,
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
            auth::Tier::Write,
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
            auth::Tier::Write,
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
            auth::Tier::Write,
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
    assert_eq!(meta_sha256, audit::meta_sha256("text/plain", &headers));

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
async fn delete_honors_if_match_before_audit_or_remove() {
    let (core, dir) = test_core("delete-if-match");
    let core = Arc::new(core);
    let state = server_state_for_tests(core.clone());
    let h = world::write_with_audit(
        &core.data,
        "home/delete-cas",
        b"alive",
        "text/plain; charset=utf-8",
        &[],
        &core.hmac_key,
    )
    .unwrap();

    let mut stale = HeaderMap::new();
    stale.insert(header::IF_MATCH, HeaderValue::from_static("\"hmac-stale\""));
    let resp = unwrap_response(
        execute_delete(
            stale.clone(),
            auth::Tier::Approve,
            world_path("home/delete-cas"),
            &state,
            &TraceCtx::disabled(),
        )
        .await,
    );
    assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
    assert!(core.read_world("home/delete-cas").unwrap().is_some());

    let mut good = HeaderMap::new();
    good.insert(
        header::IF_MATCH,
        HeaderValue::from_str(&format!("\"{}\"", et::hmac_etag(&h))).unwrap(),
    );
    let resp = unwrap_response(
        execute_delete(
            good.clone(),
            auth::Tier::Approve,
            world_path("home/delete-cas"),
            &state,
            &TraceCtx::disabled(),
        )
        .await,
    );
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(core.read_world("home/delete-cas").unwrap().is_none());
    assert!(core.read_world("var/log/deletes").unwrap().is_some());
    assert!(matches!(
        core.cached_verify_chain("var/log/deletes").unwrap(),
        Some(audit::VerifyReport::Valid(_))
    ));
    let ledger = world::open_existing(&core.data, "var/log/deletes")
        .unwrap()
        .unwrap();
    let mut stmt = ledger
        .prepare("SELECT event_type FROM events ORDER BY id")
        .unwrap();
    let events: Vec<String> = stmt
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(events, vec!["delete_intent", "delete_commit"]);

    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn delete_returns_500_when_commit_audit_fails_after_physical_delete() {
    let (core, dir) = test_core("delete-commit-audit-fail");
    let core = Arc::new(core);
    let state = server_state_for_tests(core.clone());
    core.write_world("home/delete-degraded", b"alive", "text/plain", &[])
        .unwrap();
    world::write_with_audit(
        &core.data,
        "var/log/deletes",
        b"ledger",
        "text/plain",
        &[],
        &core.hmac_key,
    )
    .unwrap();
    core.delete_ledger_created.store(true, Ordering::Relaxed);
    {
        let c = rusqlite::Connection::open(world::world_db(&core.data, "var/log/deletes")).unwrap();
        c.execute_batch(
            r#"
                CREATE TRIGGER fail_delete_commit
                BEFORE INSERT ON events
                WHEN NEW.event_type='delete_commit'
                BEGIN
                    SELECT RAISE(FAIL, 'delete_commit blocked');
                END;
                "#,
        )
        .unwrap();
    }

    let resp = unwrap_response(
        execute_delete(
            HeaderMap::new(),
            auth::Tier::Approve,
            world_path("home/delete-degraded"),
            &state,
            &TraceCtx::disabled(),
        )
        .await,
    );

    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(core.read_world("home/delete-degraded").unwrap().is_none());
    let ledger = world::open_existing(&core.data, "var/log/deletes")
        .unwrap()
        .unwrap();
    let events = ledger
        .prepare("SELECT event_type FROM events ORDER BY id")
        .unwrap()
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(events, vec!["put", "delete_intent", "delete_commit_failed"]);

    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn delete_rejects_auth_token_and_append_only_ledger() {
    let (core, dir) = test_core("delete-policy");
    let core = Arc::new(core);
    let state = server_state_for_tests(core.clone());
    world::write_with_audit(
        &core.data,
        "home/delete-policy",
        b"alive",
        "text/plain; charset=utf-8",
        &[],
        &core.hmac_key,
    )
    .unwrap();
    world::write_with_audit(
        &core.data,
        "var/log/deletes",
        b"ledger",
        "text/plain; charset=utf-8",
        &[],
        &core.hmac_key,
    )
    .unwrap();
    let headers = HeaderMap::new();

    let auth_delete = unwrap_response(
        execute_delete(
            headers.clone(),
            auth::Tier::Write,
            world_path("home/delete-policy"),
            &state,
            &TraceCtx::disabled(),
        )
        .await,
    );
    assert_eq!(auth_delete.status(), StatusCode::UNAUTHORIZED);
    assert!(core.read_world("home/delete-policy").unwrap().is_some());

    let ledger_delete = unwrap_response(
        execute_delete(
            headers.clone(),
            auth::Tier::Approve,
            world_path("var/log/deletes"),
            &state,
            &TraceCtx::disabled(),
        )
        .await,
    );
    assert_eq!(ledger_delete.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        ledger_delete
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .unwrap(),
        "Bearer realm=\"elastik\""
    );
    assert_eq!(
        ledger_delete.headers().get(header::CONTENT_TYPE).unwrap(),
        "text/plain; charset=utf-8"
    );
    assert_eq!(
        response_text(ledger_delete).await,
        "auth required: delete ledger is append-only\n"
    );
    assert!(core.read_world("var/log/deletes").unwrap().is_some());

    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn delete_missing_world_does_not_write_delete_ledger() {
    let (core, dir) = test_core("delete-missing");
    let core = Arc::new(core);
    let state = server_state_for_tests(core.clone());
    let headers = HeaderMap::new();
    let resp = unwrap_response(
        execute_delete(
            headers.clone(),
            auth::Tier::Approve,
            world_path("home/missing"),
            &state,
            &TraceCtx::disabled(),
        )
        .await,
    );
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert!(core.read_world("var/log/deletes").unwrap().is_none());

    let _ = std::fs::remove_dir_all(dir);
}

#[cfg(feature = "multi-thread")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_first_deletes_increment_world_count_exactly_once() {
    // Bug 16 race coverage. Three concurrent DELETEs on a fresh
    // Core (delete_ledger_created starts false). The ledger gets
    // created on the first DELETE that wins the
    // `swap(true, AcqRel)` edge -- exactly one of them sees
    // was_first=true and bumps `durable_world_count`. The other
    // two see the swap-already-true and skip the bump.
    //
    // Setup: PUT three distinct worlds (durable_world_count = 3).
    // Then run three concurrent DELETEs in parallel.
    // Final state: durable_world_count = 3 + 1[ledger creation,
    // exactly once] - 3[three deletes succeed] = 1.
    //
    // Without Bug 16's `swap` ordering, two or all three of the
    // racing DELETEs would each independently observe
    // delete_ledger_created==false (via world_exists_blocking)
    // and each bump the counter, leading to drift. With the
    // atomic swap, only the unique false->true transition bumps.
    let (core, dir) = test_core("concurrent-first-deletes");
    let headers = HeaderMap::new();
    for w in ["home/a", "home/b", "home/c"] {
        let put = unwrap_response(
            execute_put(
                headers.clone(),
                Bytes::from_static(b"x"),
                auth::Tier::Write,
                world_path(w),
                &core,
                &TraceCtx::disabled(),
            )
            .await,
        );
        assert_eq!(put.status(), StatusCode::CREATED);
    }
    assert_eq!(core.durable_world_count.load(Ordering::Relaxed), 3);
    assert!(!core.delete_ledger_created.load(Ordering::Relaxed));

    let state = Arc::new(core);
    let server_state = server_state_for_tests(state.clone());
    let s1 = server_state.clone();
    let s2 = server_state.clone();
    let s3 = server_state.clone();
    let h1 = headers.clone();
    let h2 = headers.clone();
    let h3 = headers.clone();
    let trace1 = TraceCtx::disabled();
    let trace2 = TraceCtx::disabled();
    let trace3 = TraceCtx::disabled();
    let (r1, r2, r3) = tokio::join!(
        execute_delete(h1, auth::Tier::Approve, world_path("home/a"), &s1, &trace1),
        execute_delete(h2, auth::Tier::Approve, world_path("home/b"), &s2, &trace2),
        execute_delete(h3, auth::Tier::Approve, world_path("home/c"), &s3, &trace3),
    );
    assert_eq!(unwrap_response(r1).status(), StatusCode::NO_CONTENT);
    assert_eq!(unwrap_response(r2).status(), StatusCode::NO_CONTENT);
    assert_eq!(unwrap_response(r3).status(), StatusCode::NO_CONTENT);

    // 3 (original) + 1 (ledger creation, exactly once) - 3 (three
    // deletes) = 1.
    assert_eq!(state.durable_world_count.load(Ordering::Relaxed), 1);
    assert!(state.delete_ledger_created.load(Ordering::Relaxed));

    let _ = std::fs::remove_dir_all(dir);
}

async fn response_text(resp: Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}
