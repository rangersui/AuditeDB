//! `elastik` — Rust client for elastik servers.
//!
//! `cargo add elastik` and use it to talk to any running elastik server.
//! Same atom set as the Python SDK and `@elastikjs/client`: put / get /
//! head / delete / list / shaped. Synchronous (`reqwest::blocking`) by
//! default so the simple cases stay simple.
//!
//! ```no_run
//! use elastik::Elastik;
//!
//! let e = Elastik::new("http://localhost:3105").token("t");
//! e.put("/home/note", b"hello", &[("actor", "me")])?;
//! let body = e.get_raw("/home/note")?;
//! assert_eq!(body, b"hello");
//! # Ok::<(), elastik::Error>(())
//! ```
//!
//! What is elastik: see <https://pypi.org/project/elastik/>.
//! pip install elastik gets you the server. This crate is the client.

use serde::Deserialize;
use std::collections::HashMap;

pub const DEFAULT_URL: &str = "http://127.0.0.1:3105";

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("elastik {status}: {body}")]
    Elastik { status: u16, body: String },
    #[error("invalid header: {0}")]
    Header(String),
    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Deserialize)]
pub struct Envelope {
    pub stage_html: String,
    pub version: i64,
    pub ext: String,
    pub updated_at: String,
    #[serde(default)]
    pub headers: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct PutResponse {
    pub ok: bool,
    pub version: i64,
    pub world: String,
    pub size: u64,
}

#[derive(Debug, Deserialize)]
struct WorldEntry {
    name: String,
}

/// Pythonic, pre-bound elastik client.
///
/// `Elastik::new(url)` then chain `.token(...)` if needed. All atom
/// methods are blocking; if you need async, build with the `async`
/// feature (TODO).
pub struct Elastik {
    url: String,
    token: String,
    client: reqwest::blocking::Client,
}

impl Elastik {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into().trim_end_matches('/').to_owned(),
            token: String::new(),
            client: reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("build client"),
        }
    }

    pub fn token(mut self, t: impl Into<String>) -> Self {
        self.token = t.into();
        self
    }

    /// Build from the shared Elastik SDK environment contract.
    ///
    /// Reads `ELASTIK_URL` (default `http://127.0.0.1:3105`) and
    /// `ELASTIK_TOKEN` (default empty).
    pub fn from_env() -> Self {
        let url = std::env::var("ELASTIK_URL").unwrap_or_else(|_| DEFAULT_URL.to_owned());
        let token = std::env::var("ELASTIK_TOKEN").unwrap_or_default();
        Self::new(url).token(token)
    }

    // ── atoms ─────────────────────────────────────────────────────

    /// `PUT path` with `data` body. `meta` pairs become `X-Meta-*` headers.
    pub fn put(&self, path: &str, data: &[u8], meta: &[(&str, &str)]) -> Result<PutResponse> {
        let mut req = self.client.put(self.full(path)).body(data.to_vec());
        req = self.auth(req);
        for (k, v) in meta {
            let name = format!("X-Meta-{}", k.replace('_', "-"));
            req = req.header(&name, *v);
        }
        let r = req.send()?;
        let status = r.status().as_u16();
        let text = r.text()?;
        if status >= 400 {
            return Err(Error::Elastik { status, body: text });
        }
        Ok(serde_json::from_str(&text)?)
    }

    /// `GET path` returning the JSON envelope.
    pub fn get(&self, path: &str) -> Result<Envelope> {
        let r = self.auth(self.client.get(self.full(path))).send()?;
        let status = r.status().as_u16();
        let text = r.text()?;
        if status >= 400 {
            return Err(Error::Elastik { status, body: text });
        }
        Ok(serde_json::from_str(&text)?)
    }

    /// `GET path?raw` returning raw body bytes.
    pub fn get_raw(&self, path: &str) -> Result<Vec<u8>> {
        let r = self
            .auth(self.client.get(self.full(path) + "?raw"))
            .send()?;
        let status = r.status().as_u16();
        if status >= 400 {
            return Err(Error::Elastik {
                status,
                body: r.text().unwrap_or_default(),
            });
        }
        Ok(r.bytes()?.to_vec())
    }

    /// `HEAD path` returning headers as a flat map (lowercase keys).
    pub fn head(&self, path: &str) -> Result<HashMap<String, String>> {
        let r = self.auth(self.client.head(self.full(path))).send()?;
        if !r.status().is_success() {
            return Err(Error::Elastik {
                status: r.status().as_u16(),
                body: String::new(),
            });
        }
        let mut out = HashMap::new();
        for (k, v) in r.headers().iter() {
            if let Ok(s) = v.to_str() {
                out.insert(k.as_str().to_lowercase(), s.to_owned());
            }
        }
        Ok(out)
    }

    /// `DELETE path`. Returns `true` on 204, `false` on 404.
    pub fn delete(&self, path: &str) -> Result<bool> {
        let r = self.auth(self.client.delete(self.full(path))).send()?;
        match r.status().as_u16() {
            204 => Ok(true),
            404 => Ok(false),
            s => Err(Error::Elastik {
                status: s,
                body: r.text().unwrap_or_default(),
            }),
        }
    }

    /// `GET /proc/worlds` returning the list of world names.
    pub fn list(&self) -> Result<Vec<String>> {
        let r = self
            .auth(self.client.get(self.full("/proc/worlds")))
            .send()?;
        if !r.status().is_success() {
            return Err(Error::Elastik {
                status: r.status().as_u16(),
                body: r.text().unwrap_or_default(),
            });
        }
        let entries: Vec<WorldEntry> = r.json()?;
        Ok(entries.into_iter().map(|e| e.name).collect())
    }

    /// `GET /shaped/<path>` with content negotiation. `accept` becomes the
    /// `Accept` header; `intent` becomes `X-Semantic-Intent`. Returns body bytes.
    pub fn shaped(&self, path: &str, accept: &str, intent: &str) -> Result<Vec<u8>> {
        let route = if path.starts_with('/') {
            path.to_owned()
        } else {
            format!("/{path}")
        };
        let url = self.url.clone() + "/shaped" + &route;
        let mut req = self.client.get(&url).header("Accept", accept);
        req = self.auth(req);
        if !intent.is_empty() {
            req = req.header("X-Semantic-Intent", intent);
        }
        let r = req.send()?;
        if !r.status().is_success() {
            return Err(Error::Elastik {
                status: r.status().as_u16(),
                body: r.text().unwrap_or_default(),
            });
        }
        Ok(r.bytes()?.to_vec())
    }

    // ── helpers ───────────────────────────────────────────────────

    fn full(&self, path: &str) -> String {
        if path.starts_with('/') {
            self.url.clone() + path
        } else {
            self.url.clone() + "/" + path
        }
    }

    fn auth(&self, req: reqwest::blocking::RequestBuilder) -> reqwest::blocking::RequestBuilder {
        if self.token.is_empty() {
            req
        } else {
            req.header("Authorization", format!("Bearer {}", self.token))
        }
    }
}
