use super::*;
use crate::handler::execute_get;
use crate::test_support::test_core;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::Response;

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
