# Async client patterns

## One line

AuditeDB storage is synchronous (key-value read/write), but workflows are
naturally asynchronous (computation happens elsewhere). JavaScript is the most
natural business client for AuditeDB; Python is the most natural script client.

## Two operating modes

### Synchronous: pure storage

```text
PUT /path body=data   -> 201   wrote it
GET /path             -> 200 body=data   read it
DELETE /path          -> 204   deleted   (approve token)
```

Disk read/write. Any language works. Python is the most concise.

### Asynchronous: compute workflow

```text
PUT /home/jobs/task body=request    -> placed in the world
sidecar notices -> computes -> PUT /home/jobs/task/result
GET /home/jobs/task/result          -> 200 if present, 404 if not
/listen/home/jobs/task/result       -> SSE notification when the result lands
```

The store does not compute. Computation happens in the sidecar. The result
comes back into the store as another world.

Paths used here all live under `home/` so they are durable and the canonical
key is obvious. Bare paths such as `/jobs/task` would silently canonicalise
to `home/jobs/task` anyway, but explicit is better.

### Live values

For ephemeral live values (latest sensor reading, current PLC register), use
the memory-backed namespaces `tmp/*`, `dev/*`, or `sys/*`. They are
transient and not audited; the trade-off is speed and simpler semantics. A
sensor mirror typically lives under `dev/`, a debug scratch under `tmp/`, a
health snapshot under `sys/`.

## /listen/* is SSE

`/listen/<pattern>` is always a Server-Sent Events stream
(`Content-Type: text/event-stream`). There is no content negotiation:

```text
curl -N /listen/<pattern>         sees SSE frames, not bare paths
EventSource (no read token)       works natively
EventSource + Bearer token        does NOT work; native EventSource cannot
                                  set the Authorization header
fetch + ReadableStream            works; parse SSE manually
requests(stream=True)             works; parse SSE lines manually
```

Use `EventSource` only when no `Authorization` header is required. Use
`fetch` + `ReadableStream` when read tokens are enabled. See `http-worlds.md`
for the SSE frame shape.

## JavaScript client (browser / Node.js)

### Basic read/write

```javascript
const TOKEN = localStorage.getItem('token');
const BASE = 'http://localhost:3105';
const auth = {'Authorization': 'Bearer ' + TOKEN};

// write
await fetch(BASE + '/home/note', {
  method: 'PUT',
  headers: {...auth, 'Content-Type': 'text/plain'},
  body: 'hello world'
});

// read
const data = await fetch(BASE + '/home/note', {headers: auth});
const text = await data.text();

// read bytes
const buf = await (await fetch(BASE + '/dev/sensor', {headers: auth})).arrayBuffer();
```

### Async job pattern (PUT task -> await result)

This example uses `EventSource`, which only works when reads are public. For
tokened reads, see the fetch-based listener below.

```javascript
// 1. submit task
await fetch(BASE + '/home/jobs/calc', {
  method: 'PUT',
  headers: auth,
  body: 'fibonacci(42)'
});

// 2. await result via SSE (public reads only)
const result = await new Promise((resolve, reject) => {
  const timeout = setTimeout(() => reject(new Error('timeout')), 30000);
  const es = new EventSource(BASE + '/listen/home/jobs/calc/result');
  es.onmessage = async (e) => {
    clearTimeout(timeout);
    es.close();
    const r = await fetch(BASE + '/home/jobs/calc/result', {headers: auth});
    resolve(await r.text());
  };
  es.onerror = () => { clearTimeout(timeout); es.close(); reject(new Error('sse failed')); };
});
```

### fetch + ReadableStream (works with Bearer token)

```javascript
async function listen(path, onEvent) {
  const r = await fetch(BASE + '/listen' + path, {headers: auth});
  const reader = r.body.getReader();
  const dec = new TextDecoder();
  let buf = '';
  while (true) {
    const {value, done} = await reader.read();
    if (done) return;
    buf += dec.decode(value, {stream: true});
    let i;
    while ((i = buf.indexOf('\n\n')) >= 0) {
      const frame = buf.slice(0, i);
      buf = buf.slice(i + 2);
      onEvent(parseSseFrame(frame));   // event:/id:/data: lines
    }
  }
}
```

### Live monitoring (long-running SSE)

```javascript
// listen for all PLC changes under dev/plc
const es = new EventSource(BASE + '/listen/dev/plc');
es.addEventListener('put', (e) => {
  // e.data has "path: /dev/plc/x\nmethod: PUT\netag: ..."
  // parse out the path and GET the latest value
});
```

### Dashboard polling pattern (no SSE)

```javascript
// 1 Hz polling, suitable for simple dashboards
setInterval(async () => {
  const r = await fetch(BASE + '/dev/plc/main', {
    headers: auth,
    cache: 'no-store'
  });
  if (r.ok) paint(new Uint8Array(await r.arrayBuffer()));
}, 1000);
```

## Python client

### Basic read/write (scripts / one-off tasks)

```python
import requests

BASE = 'http://localhost:3105'
AUTH = {'Authorization': 'Bearer YOUR_TOKEN'}

# write
requests.put(f'{BASE}/home/note', headers=AUTH, data=b'hello world')

# read
data = requests.get(f'{BASE}/home/note', headers=AUTH).content

# batch operations
for path in ['home/a', 'home/b', 'home/c']:
    requests.put(f'{BASE}/{path}', headers=AUTH, data=b'init')
```

### Sidecar daemon (long-running)

```python
import requests
import time

BASE = 'http://localhost:3105'
AUTH = {'Authorization': 'Bearer WRITE_TOKEN'}

def iter_sse(resp):
    """Yield (event, data_lines) tuples from an SSE response."""
    event = None
    data = []
    for raw in resp.iter_lines(decode_unicode=True):
        if raw is None:
            continue
        if raw == '':
            if event or data:
                yield event, data
            event, data = None, []
            continue
        if raw.startswith(':'):
            continue  # comment / keepalive
        if raw.startswith('event:'):
            event = raw[6:].strip()
        elif raw.startswith('data:'):
            data.append(raw[5:].lstrip())

def watch_and_compute():
    """Listen on home/jobs/* and compute results."""
    with requests.get(f'{BASE}/listen/home/jobs',
                      headers=AUTH, stream=True) as r:
        for event, data in iter_sse(r):
            if event != 'put':
                continue
            # parse the "path: ..." line out of data
            path = next((d.split(': ', 1)[1]
                         for d in data if d.startswith('path: ')), None)
            if not path:
                continue
            task = requests.get(f'{BASE}{path}', headers=AUTH).text
            result = do_compute(task)
            requests.put(f'{BASE}{path}/result', headers=AUTH, data=result)

# Alternative: scheduled refresh pattern (no SSE)
def periodic_updater():
    """Update weather data every 30 seconds."""
    while True:
        data = fetch_weather_from_api()
        requests.put(
            f'{BASE}/home/api/weather/sydney',
            headers={**AUTH, 'Content-Type': 'application/octet-stream'},
            data=data,
        )
        time.sleep(30)
```

### Standard-library version (no requests)

```python
import urllib.request

BASE = 'http://localhost:3105'

def put(path, body, token):
    req = urllib.request.Request(
        f'{BASE}/{path}', data=body, method='PUT',
        headers={'Authorization': f'Bearer {token}'})
    urllib.request.urlopen(req)

def get(path, token):
    req = urllib.request.Request(
        f'{BASE}/{path}',
        headers={'Authorization': f'Bearer {token}'})
    return urllib.request.urlopen(req).read()
```

## Language selection guide

```text
Scenario                         Best choice    Reason
-----------------------------------------------------------------------------
One-off script / migration       Python         concise; synchronous is enough
Batch PUT/GET                    Python         for loop, requests
Sidecar daemon                   either         Python works, JS works
Browser dashboard                JavaScript     native fetch + EventSource
Event-driven workflow            JavaScript     async/await is the natural fit
Many SSE streams + concurrency   JavaScript     event loop does not block
PLC translation layer            Lua / Python   platform-constrained
FPGA control                     no HTTP        direct hardware
```

## Duck philosophy

```text
GET /home/weather/sydney -> returns weather data

The caller does not know and does not care whether:
  it was computed live by FastAPI
  a sidecar PUT it 30 seconds ago
  it is last year's cache

Duck typing: returning correct data = API.
What sits behind it (CPU or disk) is not the caller's concern.
```

## Traps

- SSE (`EventSource`) cannot set custom headers, so any token authentication
  needs a fetch-based reader, a cookie/proxy workaround, or public reads.
- Polling needs `cache: 'no-store'`, otherwise browser cache will lie to you.
- A sidecar writing a result should check whether the job has been deleted
  first; otherwise it races.
- Timeouts are the caller's responsibility. AuditeDB does not surface a
  "task timed out" event on its own.
- A `lag` event on `/listen/*` means the listener missed changes; if you care
  about completeness, re-`GET` the affected paths to recover state.
- Memory-backed namespaces (`tmp/*`, `dev/*`, `sys/*`) are not audited and do
  not survive a restart. Do not use them for state you cannot lose.

## Related references

- `../SKILL.md` -- the entry point, mental model, and operational checklist.
- `navigation.md` -- listing and searching worlds.
- `http-worlds.md` -- HTTP method semantics, namespace policy, ETag/CAS,
  the SSE frame shape on `/listen/*`.
- `flexible-deployment.md` -- deployment shapes and token topology.
