use super::*;
use crate::etag as et;
use crate::handler::{execute_delete, execute_get, execute_put};
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
