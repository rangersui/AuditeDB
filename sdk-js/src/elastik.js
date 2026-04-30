// elastikjs — atom bindings for elastik. Mirror of sdk/src/elastik/sdk.py.
//
//   import { Elastik } from 'elastikjs';
//   const e = new Elastik({ url: 'http://localhost:3105', token: 't' });
//   await e.put('/home/note', 'hello');
//   await e.get('/home/note', { raw: true });   //  → "hello"
//
// 0 deps. fetch is built into modern browsers and Node 18+. The whole
// package is one file you could read in a sitting. The atoms are
// PUT/GET/HEAD/DELETE/list/shaped — same as the Python SDK, same as
// the Rust core's HTTP surface, because the surface IS the protocol.

export class ElastikError extends Error {
  constructor(status, body) {
    super(`elastik ${status}: ${typeof body === 'string' ? body.slice(0, 200) : body}`);
    this.status = status;
    this.body = body;
  }
}

export class Elastik {
  /**
   * @param {object} opts
   * @param {string} [opts.url='http://127.0.0.1:3105']  base URL of an elastik
   * @param {string} [opts.token='']                      bearer token (T2/T3)
   */
  constructor({ url = defaultUrl(), token = defaultToken() } = {}) {
    this.url = url.replace(/\/$/, '');
    this.token = token;
  }

  /**
   * PUT body to path. extras become X-Meta-* headers.
   *   await e.put('/home/note', 'hi', { actor: 'me', confidence: 0.9 });
   */
  async put(path, data, meta = {}) {
    const headers = this._headers(meta);
    return this._json('PUT', path, data, headers);
  }

  /**
   * GET path. raw=true returns string/bytes; otherwise the JSON envelope.
   */
  async get(path, { raw = false } = {}) {
    const suffix = raw ? '?raw' : '';
    const r = await this._fetch('GET', path + suffix);
    if (!r.ok) throw new ElastikError(r.status, await r.text());
    if (raw) {
      const ct = r.headers.get('content-type') || '';
      return ct.includes('application/octet-stream') || ct.includes('image/')
        ? new Uint8Array(await r.arrayBuffer())
        : await r.text();
    }
    return r.json();
  }

  /**
   * HEAD path. Returns headers as a plain object (lowercased keys).
   */
  async head(path) {
    const r = await this._fetch('HEAD', path);
    if (!r.ok) throw new ElastikError(r.status, '');
    const out = {};
    r.headers.forEach((v, k) => { out[k] = v; });
    return out;
  }

  /**
   * DELETE path. Returns true on 204, false on 404.
   */
  async delete(path) {
    const r = await this._fetch('DELETE', path);
    if (r.status === 204) return true;
    if (r.status === 404) return false;
    throw new ElastikError(r.status, await r.text());
  }

  /**
   * GET /proc/worlds. Returns array of world names.
   */
  async list() {
    const r = await this._fetch('GET', '/proc/worlds');
    if (!r.ok) throw new ElastikError(r.status, await r.text());
    const arr = await r.json();
    return arr.map((w) => w.name);
  }

  /**
   * GET /shaped/<path> with Accept + X-Semantic-Intent. Forwards to
   * whatever shaper sidecar elastik routes /shaped/ to.
   */
  async shaped(path, { accept = 'text/html', intent = '' } = {}) {
    const headers = { Accept: accept };
    if (intent) headers['X-Semantic-Intent'] = intent;
    const r = await this._fetch('GET', '/shaped' + path, headers);
    if (!r.ok) throw new ElastikError(r.status, await r.text());
    return await r.text();
  }

  // ── transport ─────────────────────────────────────────────────

  _headers(meta) {
    const out = {};
    for (const [k, v] of Object.entries(meta || {})) {
      // foo_bar → X-Meta-Foo-Bar
      const norm = 'X-Meta-' + k.replace(/_/g, '-');
      out[norm] = String(v);
    }
    return out;
  }

  async _fetch(method, path, extraHeaders = {}) {
    const url = this.url + (path.startsWith('/') ? path : '/' + path);
    const headers = { ...extraHeaders };
    if (this.token) headers['Authorization'] = `Bearer ${this.token}`;
    return fetch(url, { method, headers });
  }

  async _json(method, path, body, headers) {
    const url = this.url + (path.startsWith('/') ? path : '/' + path);
    const h = { ...(headers || {}) };
    if (this.token) h['Authorization'] = `Bearer ${this.token}`;
    const r = await fetch(url, { method, body, headers: h });
    const text = await r.text();
    if (!r.ok) throw new ElastikError(r.status, text);
    try { return JSON.parse(text); } catch { return { raw: text }; }
  }
}

// Module-level convenience (NumPy-shaped). Reads ELASTIK_URL +
// ELASTIK_TOKEN from process.env on Node, or falls back to defaults
// in the browser. Bind your own client with `setDefault()` to override.

let _default = null;

const DEFAULT_URL = 'http://127.0.0.1:3105';

function envValue(name) {
  const env = (typeof process !== 'undefined' && process.env) ? process.env : {};
  return env[name] || '';
}

function defaultUrl() {
  return envValue('ELASTIK_URL') || DEFAULT_URL;
}

function defaultToken() {
  return envValue('ELASTIK_TOKEN');
}

function _client() {
  if (_default) return _default;
  _default = new Elastik({
    url: defaultUrl(),
    token: defaultToken(),
  });
  return _default;
}

export function setDefault(client) { _default = client; }

export const put = (...args) => _client().put(...args);
export const get = (...args) => _client().get(...args);
export const head = (...args) => _client().head(...args);
export const del = (...args) => _client().delete(...args);
export const list = () => _client().list();
export const shaped = (...args) => _client().shaped(...args);

export default Elastik;
