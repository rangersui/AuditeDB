# UI worlds

Use this reference when building or repairing browser pages stored as AuditeDB
worlds. Keep it generic: discover the target world set at runtime.

## Flat page topology

Prefer sibling worlds:

```text
/home/tool.html
/home/tool.html.css
/home/tool.html.js
```

HTML is the framebuffer. CSS is presentation. JS is behaviour. Splitting keeps
closure span low and makes each surface replaceable.

Slashes in the key are naming convention, not directory structure. `tool.html`
and `tool.html.css` are independent worlds; the shared prefix is a hint for
humans, not a parent-child relationship in the store.

## Dynamic navigation

Navigation pages should read `/proc/worlds` and render from that source of
truth. Do not hardcode a world list unless the page is explicitly a snapshot.

Modern browser pattern:

```js
const r = await fetch('/proc/worlds', { cache: 'no-store' });
const worlds = (await r.text()).split(/\r?\n/).filter(Boolean);
```

No-JS pattern:

```html
<meta http-equiv="refresh" content="10">
```

Generate a static list from `/proc/worlds`; refresh the whole page. Do not rely
on JavaScript when the target client cannot execute it.

## Metadata

Add accurate metadata when PUTting pages:

- `Content-Type: text/html; charset=utf-8`
- `Content-Language: en` or `zh-CN`
- `Cache-Control: no-cache`
- `X-Meta-Summary: one sentence`

Use `X-Meta-Summary` for navigation and search when custom metadata is enabled.
Keep it short and factual.

## Mock data rule

Do not make fake data look real.

Allowed:

- Empty state when endpoint is missing.
- Demo shader presets inside a shader tool.
- Placeholder text inside form inputs.

Not allowed:

- Fake commit history.
- Fake media paths.
- Fake disk tree.
- Synthetic health metrics that look live.

## Generic OS-style surfaces

Useful page categories:

- Navigation: render `/proc/worlds`.
- Shell: send HTTP requests with method, path, headers, and body.
- Upload: PUT local bytes into a chosen world.
- Editor: read, edit, and PUT text worlds.
- Viewer: browse worlds by media type.
- Disk usage: visualise `/proc/du`.
- Status: show version, capacity, and relevant proc surfaces.
