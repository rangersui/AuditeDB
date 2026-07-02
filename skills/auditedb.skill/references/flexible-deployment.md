# Flexible AuditeDB Deployment

AuditeDB can be one binary and one local folder. It can also run in one place
while its data lives somewhere else. The binary, the HTTP endpoint, and the
durable data root are separate deployment choices.

Use this reference when the user wants to run AuditeDB on a laptop, machine,
Raspberry Pi, NAS-backed share, overlay network, or public HTTPS endpoint
without changing the HTTP world model.

## Contents

- Core idea
- Deployment modes
- Layered security
- Cache stack
- Token topology
- AuditeDB as a protocol gateway
- Minimal verification
- Operational traps
- Related references

## Core idea

There is no fixed client/server split. There is data and there is an
entrypoint. They can be in the same place, or not. The `auditedb` binary is just
the process that happens to expose an HTTP entrypoint and point at some bytes.

AuditeDB sees a data directory. That directory can be local disk, SMB, NFS, a
FUSE mount, or a synced/overlay filesystem, as long as the operating system
presents normal file semantics.

```text
HTTP caller -> entrypoint -> AuditeDB process -> filesystem path -> SQLite world
```

The transport below the filesystem is intentionally hidden from the HTTP layer.
`PUT /home/report.html` should mean the same thing whether the backing path is
`./data`, `\\NAS\AuditeDB\data`, or `/mnt/nas/AuditeDB/data`.

## Deployment modes

Two independent choices define the basic deployment shape:

```text
                  data = local      data = remote SMB/NFS
bind = 127.0.0.1  Mode 0            Mode A
                  private local     private endpoint, remote data

bind = 0.0.0.0    Mode 1            Mode B
                  LAN-visible       LAN-visible, remote data
```

Start with these four before adding overlays, reverse proxies, or public edges.

### Mode 0: local folder

Use this first unless the user has a concrete reason not to.

```bash
export AUDITEDB_HOST=127.0.0.1
export AUDITEDB_PORT=3105
export AUDITEDB_DATA=./data
export AUDITEDB_BASE="http://${AUDITEDB_HOST}:${AUDITEDB_PORT}"
```

Properties:

- No SMB.
- No NAS.
- No network filesystem.
- No reverse proxy.
- No public endpoint.
- One process, one local data directory, one AuditeDB storage endpoint.

This is the traditional single-process model and it remains the default shape. The
fancier modes below are extensions, not replacements.

### Mode 1: directly hosted local data

Use this when an AuditeDB entrypoint should be visible to other machines on the
same LAN, but the durable data still lives beside that AuditeDB process.

```bash
export AUDITEDB_HOST=0.0.0.0
export AUDITEDB_PORT=3105
export AUDITEDB_DATA=./data
export AUDITEDB_BASE="http://LAN_IP:3105"
```

Properties:

- No SMB.
- No NAS.
- No network filesystem.
- Other LAN machines can reach the HTTP endpoint directly.
- The AuditeDB process remains the only thing touching the data directory.
- One central AuditeDB process owns the tokens for all HTTP callers.
- Require write and approve tokens.
- Use firewall rules when the LAN is not fully trusted.

This is the simplest shared deployment: expose one AuditeDB entrypoint directly,
keep the data local to that process, and let HTTP be the sharing boundary.

### Mode A: private local endpoint, remote data

Use this when one user wants a local AuditeDB storage endpoint backed by a NAS
or shared disk.

```bash
export AUDITEDB_HOST=127.0.0.1
export AUDITEDB_PORT=3105
export AUDITEDB_DATA='\\NAS\AuditeDB\data'
export AUDITEDB_BASE="http://${AUDITEDB_HOST}:${AUDITEDB_PORT}"
```

Properties:

- HTTP attack surface stays local.
- Data can live on a NAS, SMB share, NFS share, or mounted volume.
- Tokens are still recommended, but the network exposure is minimal.
- Good for personal dashboards, local agents, archives, and benchmarks.

### Mode B: temporary LAN share

Use this when another machine on the same LAN needs short-lived access.

```bash
export AUDITEDB_HOST=0.0.0.0
export AUDITEDB_PORT=3105
export AUDITEDB_DATA='\\NAS\AuditeDB\data'
export AUDITEDB_BASE="http://LAN_IP:3105"
```

Properties:

- Require write and approve tokens.
- Prefer a trusted LAN or VPN.
- Return to `127.0.0.1` when the share window ends.
- Do not expose SMB/NFS directly just because AuditeDB is reachable.

### Mode C: overlay-network endpoint

Use this when machines are far apart physically but share a private overlay
such as Tailscale, WireGuard, or ZeroTier.

```bash
export AUDITEDB_HOST=0.0.0.0
export AUDITEDB_PORT=3105
export AUDITEDB_DATA=/mnt/nas/AuditeDB/data
export AUDITEDB_BASE="http://100.x.y.z:3105"
```

Properties:

- The physical route may cross many hops, but the operator sees one logical
  HTTP endpoint.
- Overlay ACLs handle reachability.
- AuditeDB tokens handle world-level authority.
- The data path can still be beside the AuditeDB process or mounted remotely.

### Mode D: public HTTPS front door

Use this only when the endpoint must be reachable from the public internet.

```text
browser/curl
  -> Cloudflare or equivalent edge
  -> reverse proxy with TLS and login
  -> auditedb on 127.0.0.1:3105
  -> data root
```

Properties:

- Put TLS, login, rate limiting, and request-size limits in front.
- Keep AuditeDB bound to localhost behind the proxy when possible.
- Keep write and approve tokens enabled.
- Never expose SMB/NFS ports to the public internet.

## Layered security

The useful pattern is independent gates, not one giant gate.

```text
Layer 0: edge or VPN       reachability, DDoS, IP allow rules
Layer 1: reverse proxy     TLS, login, rate limits, request size
Layer 2: AuditeDB          bearer tokens (read/write/approve), ETags,
                           HMAC audit chain, namespace policy
Layer 3: filesystem share  OS credentials, NAS ACLs, LAN isolation
```

Each layer answers a different question:

- Can this HTTP caller reach the entrypoint?
- Is this user allowed through the front door?
- Is this request allowed to mutate or delete this world?
- Can the AuditeDB process touch the backing data?

This is not magic MFA. It is normal systems architecture: independent failure
domains make accidents and compromises harder to turn into full access.

### Token gate inside Layer 2

Within AuditeDB itself the write/approve split is not policy-free; it follows
the namespace.

```text
write token        ordinary writes in home/*, tmp/*, dev/*, sys/*, var/*
approve token      writes in etc/*, lib/*, boot/*, usr/*, var/log/*
                   and all DELETEs in every namespace
read token         reads, when configured (else public)
public             /proc/version and the bare root /
```

This means handing out the write token never enables a user to overwrite
config (`etc/*`), system blobs (`lib/*`, `boot/*`, `usr/*`), the audit log
(`var/log/*`), or to remove anything at all. Reserve the approve token for
operators.

## Cache stack

Remote data roots are useful because they make cache behaviour visible. A cold
read may spend time in UNC/NFS lookup, remote file open, SQLite connection
setup, schema read, and page-cache warmup. A warm read can reuse much of that.

Possible cache layers:

```text
browser cache
edge cache
reverse-proxy cache
AuditeDB read cache
SQLite page cache
OS buffer cache
SMB/NFS mount cache
remote storage cache
```

Important distinction:

- Read caching can make a remote SQLite world feel local after the first touch.
- Writes still have to reach the durable backing store.
- DELETE must close/drain cached file handles before removing a world.

Remote data is therefore a strong benchmark surface for connection pooling and
read-cache correctness. It amplifies open/metadata latency that local SSDs hide.

## Token topology

### Centralized token model

This is the normal shape for one shared AuditeDB entrypoint.

```text
caller A -> HTTP -> one AuditeDB entrypoint -> one token policy -> data root
caller B -> HTTP -> one AuditeDB entrypoint -> one token policy -> data root
caller C -> HTTP -> one AuditeDB entrypoint -> one token policy -> data root
```

Use centralized tokens for Mode 1, Mode B, Mode C, and public-proxy deployments
where one AuditeDB process is the authority boundary.

Properties:

- One AuditeDB process owns the read, write, and approve tokens.
- HTTP callers do not need filesystem access.
- HTTP callers do not run their own `auditedb` processes.
- Rotating a token happens once at the entrypoint, then callers update their env.
- If per-user identity is needed, put login or identity at the reverse proxy
  layer and keep AuditeDB tokens as capability gates.

This is the cleanest multi-caller model: centralize authority at HTTP, keep the
data root private to the AuditeDB process, and let callers use curl or browsers.

### Distributed token model

Different users can run separate `auditedb` processes pointed at the same shared data
root, but this should be treated carefully.

```text
user A: own AuditeDB process, own tokens, shared data root
user B: own AuditeDB process, own tokens, shared data root
```

Use this only when the filesystem and SQLite locking semantics are known to be
safe for the workload. For ordinary deployments, prefer one AuditeDB entrypoint as the
writer for a shared data root.

## AuditeDB as a protocol gateway

AuditeDB is useful in front of protocols that should not be exposed directly.

```text
SMB/NFS data      -> AuditeDB -> HTTP + tokens
PLC/internal bus  -> adapter -> AuditeDB worlds
local files       -> AuditeDB -> static HTML + proc surface
```

The goal is not to hide every domain detail. Domain adapters should still own
domain semantics. AuditeDB owns the common surface: world paths, bodies,
metadata, tokens, audit, proc, and static serving.

## Minimal verification

Probe the HTTP layer first:

```bash
curl -i "$AUDITEDB_BASE/proc/version"
curl -i -X PUT "$AUDITEDB_BASE/home/deploy-test" \
  -H "Authorization: Bearer $AUDITEDB_WRITE_TOKEN" \
  -H "Content-Type: text/plain; charset=utf-8" \
  --data-binary 'hello'
curl -i "$AUDITEDB_BASE/home/deploy-test"
```

Then measure remote-data behaviour:

```bash
time curl -sI "$AUDITEDB_BASE/home/deploy-test" >/dev/null
time curl -sI "$AUDITEDB_BASE/home/deploy-test" >/dev/null
curl -s "$AUDITEDB_BASE/proc/pool"
```

If the first request is slow and the second is fast, the stack is warming as
expected. Use Wireshark or OS counters only when you need proof at the SMB/NFS
layer.

## Operational traps

- Do not use SMBv1. Use SMBv3 with signing/encryption where available.
- Do not expose port 445 or NFS exports to the public internet.
- Do not assume a remote share has the same latency profile as local SSD.
- Do not treat cached reads as permission to skip durable write verification.
- Do not run many independent writers against the same SQLite worlds without
  testing lock behaviour on that filesystem.
- Do not rely on browser cache behaviour for protocol truth; verify with curl.
- Do not put secrets in world paths or public headers.

## Related references

- `deployment.md`: basic environment variables and startup checks.
- `http-worlds.md`: HTTP method semantics, ETags, header policy, and proc.
- `projection-theorem.md`: when a gateway should reuse AuditeDB primitives.
- `ui-worlds.md`: static HTML worlds and browser-facing surfaces.
