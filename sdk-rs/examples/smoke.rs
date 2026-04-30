//! End-to-end smoke. Assumes an elastik-core running on :3146 with token "rs".
//! Start one in another terminal:
//!
//!   ELASTIK_KEY=k ELASTIK_TOKEN=rs ELASTIK_PORT=3146 \
//!     ELASTIK_DATA=/tmp/sdk-rs-smoke ./target/release/elastik-core

use elastik::Elastik;

fn main() -> Result<(), elastik::Error> {
    let e = Elastik::new("http://localhost:3146").token("rs");

    let put = e.put(
        "/home/from-rust",
        b"hello from cargo",
        &[("actor", "elastik-rs")],
    )?;
    println!("  PUT  -> v{} ({} bytes)", put.version, put.size);

    let body = e.get_raw("/home/from-rust")?;
    println!("  GET  -> {:?}", String::from_utf8_lossy(&body));

    let head = e.head("/home/from-rust")?;
    println!("  HEAD -> x-meta-actor = {:?}", head.get("x-meta-actor"));

    let env = e.get("/home/from-rust")?;
    println!(
        "  ENV  -> v{} ext={} headers={}",
        env.version, env.ext, env.headers
    );

    let worlds = e.list()?;
    println!("  LIST -> {worlds:?}");

    let deleted = e.delete("/home/from-rust")?;
    println!("  DEL  -> {deleted}");

    Ok(())
}
