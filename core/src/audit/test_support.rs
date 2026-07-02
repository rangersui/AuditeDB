use std::path::Path;

use crate::world;

pub fn latest_hmac(data_root: &Path, world_name: &str) -> Option<String> {
    let path = world::world_db(data_root, world_name);
    if !path.exists() {
        return None;
    }
    let c = rusqlite::Connection::open(path).ok()?;
    c.query_row(
        "SELECT hmac FROM events ORDER BY id DESC LIMIT 1",
        [],
        |r| r.get::<_, String>(0),
    )
    .ok()
}
