# Navigation

Use this reference when listing, finding, inspecting, reading, or searching
AuditeDB worlds.

AuditeDB has no directories, no `cd`, and no `cwd`. `/proc/worlds` plus text
filters is `ls`, `find`, and most of `tree`. `/proc/du` and `/proc/df` cover
sizing.

## Setup

```bash
BASE="${AUDITEDB_BASE:-http://127.0.0.1:3105}"
```

## List All Worlds

```bash
curl -sS "$BASE/proc/worlds"
```

One world per line, plain text.

## List One Prefix

```bash
P="home/project"
curl -sS "$BASE/proc/worlds" | grep "^$P/"
```

## List Several Prefixes

```bash
curl -sS "$BASE/proc/worlds" |
  grep -E '^(home/project|home/archive|var/log)/'
```

## Find Names

```bash
curl -sS "$BASE/proc/worlds" | grep -Ei 'skill|prompt|index'
```

## Sizing

```bash
curl -sS "$BASE/proc/du"   # world / total / current / retained CAS / events
curl -sS "$BASE/proc/df"   # storage split / memory / quota / world count
```

`/proc/du` is safe to parse as TSV: world names cannot contain control bytes,
so tabs in the line are always column separators.

## Inspect Headers

```bash
curl -sSI "$BASE/home/project/README.md"
```

Use `HEAD` before downloading large worlds. It returns `Content-Type`,
`Content-Length`, `ETag`, and `/listen/...` link headers.

## Read

```bash
curl -sS "$BASE/home/project/skills/example.skill"
```

## Search Text Bodies

Filter by likely text suffix before fetching bodies, or binary worlds will
pollute grep.

```bash
curl -sS "$BASE/proc/worlds" |
  grep '^home/project/' |
  grep -E '\.(md|txt|skill|html|json|yml|yaml|css|js)$' |
  while IFS= read -r p; do
    curl -fsS --max-time 2 "$BASE/$p" 2>/dev/null |
      grep -qi 'pattern' && printf '%s\n' "$p" || true
  done
```

## Write

```bash
curl -sS -i -X PUT "$BASE/home/path" \
  -H "Authorization: Bearer $AUDITEDB_WRITE_TOKEN" \
  -H "Content-Type: text/plain; charset=utf-8" \
  --data-binary @file.txt
```

System namespaces (`etc/`, `lib/`, `boot/`, `usr/`, `var/log/`) require the
approve token instead of the write token. See `http-worlds.md` for the full
namespace table.

## Delete

```bash
curl -sS -i -X DELETE "$BASE/home/path" \
  -H "Authorization: Bearer $AUDITEDB_APPROVE_TOKEN"
```

DELETE always requires the approve token, regardless of namespace.

## Watch

```bash
curl -sS -N "$BASE/listen/home/project/a"
```

`/listen/*` is a Server-Sent Events stream. The `-N` flag disables curl
buffering so events print as they arrive. The wire is SSE frames, not bare
paths. Use `EventSource` only when no read token is needed; otherwise use
`fetch` + `ReadableStream` and parse SSE manually. See `http-worlds.md` for the frame
shape.

## Browser

Open:

```text
/proc/worlds
```

Then use browser find.

## Traps

- No `mkdir`: writing `home/a/b` creates that key. It is not a child of
  `home/a`.
- No `cd`: every world path is absolute from the HTTP root.
- No real `ls`: use `/proc/worlds` and filters.
- Not a filesystem tree: path separators are naming convention, not real dirs.
- Do not search every body blindly; inspect or suffix-filter first.
- `/proc/worlds`, `/proc/du`, `/proc/df`, `/proc/pool` are plain text, not
  JSON.
- Unprefixed paths get `home/` prepended by the bare-path rule, so `/foo`
  silently becomes `home/foo`. Prefer explicit prefixes.

## Related

- `../SKILL.md` -- deploy and use AuditeDB.
- `flexible-deployment.md` -- token tiers across deployment shapes.
- `http-worlds.md` -- HTTP methods, namespace policy, ETags, ranges, audit,
  and listen.
