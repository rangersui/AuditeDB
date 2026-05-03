# CDN Header Quick Reference

Elastik is a byte store. It does not run a web server, enforce cache policy,
negotiate CORS, or manage browser security directives. It stores bytes and
returns bytes. Headers travel with the bytes.

Elastik provides mechanism, not policy.

This means you decide the policy. When you `PUT` a world with
`Cache-Control: public, max-age=86400`, Elastik does not cache anything. It
stores that header alongside the body. When a CDN or browser later `GET`s the
world, they see the header and act on it. Elastik already forgot about it.

Every header you `PUT` is an instruction to someone downstream: a CDN, a
reverse proxy, a browser. Elastik is the envelope. You write the instructions
on the envelope. The mail carrier reads them. The envelope does not.

This is why Elastik has no cache configuration page, no CORS toggle, no CSP
builder. You do not configure Elastik. You configure the HTTP chain by
`PUT`ting the right headers with the right bytes. One `PUT` programs every node
between your data and the user.

Optional. Unmaintained. Vendor behavior changes; vendor documentation is the
source of truth.

## PUT Strategy

| Goal                                           | Header                                                 |
| ---------------------------------------------- | ------------------------------------------------------ |
| Cache a static asset for one day               | `Cache-Control: public, max-age=86400`               |
| Do not cache an API result                     | `Cache-Control: no-store`                            |
| CDN caches one hour, browser caches one minute | `Cache-Control: max-age=60, s-maxage=3600`           |
| Cloudflare cache, not browser cache            | `Cloudflare-CDN-Cache-Control: max-age=3600`         |
| Fastly surrogate cache, not browser cache      | `Surrogate-Control: max-age=3600`                    |
| SSE should not buffer                          | `X-Accel-Buffering: no`, `Cache-Control: no-store` |
| Tag purge on Fastly                            | `Surrogate-Key: tag1 tag2`                           |
| Tag purge on Cloudflare                        | `Cache-Tag: tag1,tag2`                               |
| Trigger browser download                       | `Content-Disposition: attachment; filename="x.csv"`  |
| Allow browser CORS                             | `Access-Control-Allow-Origin: *`                     |

Example:

```http
PUT /home/static/logo.png
Authorization: Bearer write-token
Content-Type: image/png
Cache-Control: public, max-age=86400
Surrogate-Key: static assets

[png bytes]
```

What happens:

- Elastik stores bytes plus safe response metadata.
- Cloudflare can read `Cache-Control`.
- Fastly can read `Surrogate-Key`.
- nginx can read standard cache headers or configured `X-Accel-*` headers.
- Browsers can read `Cache-Control`, `Content-Type`, CORS, CSP, and friends.

One `PUT` programs the HTTP chain. Elastik still only stores and returns bytes.

## Standard Layer

These are the first headers to reach for. Most CDNs and reverse proxies
understand them.

```http
Cache-Control: public, max-age=3600
Cache-Control: no-store
Cache-Control: private
Cache-Control: max-age=60, s-maxage=86400
Cache-Control: max-age=300, stale-while-revalidate=60, stale-if-error=3600
Vary: Accept-Encoding
Vary: Authorization
Content-Encoding: gzip
Content-Disposition: attachment; filename="data.csv"
```

Notes:

- `Cache-Control` programs browser and shared-cache behavior.
- `s-maxage` targets shared caches such as CDNs without forcing the same TTL on
  browsers.
- `Vary: Authorization` matters when a cache could otherwise mix public,
  anonymous, and token-bearing reads.
- `Content-Encoding: gzip` says the stored bytes are already encoded.
- `Content-Disposition: attachment` asks the browser to download instead of
  rendering inline.
- Elastik's own `ETag` is core-generated. Do not `PUT` it; use the `ETag`
  returned by `HEAD`/`GET` for conditional requests.

## Cloudflare

Headers you may store when Cloudflare is in front:

```http
CDN-Cache-Control: max-age=86400
Cloudflare-CDN-Cache-Control: max-age=86400
Cache-Tag: tag1,tag2
```

Headers Cloudflare returns itself:

```http
CF-Cache-Status: HIT
CF-Ray: 12345-SYD
CF-IPCountry: AU
```

Notes:

- `CDN-Cache-Control` targets CDN caches rather than browsers.
- `Cloudflare-CDN-Cache-Control` is Cloudflare-specific.
- Cloudflare cache behavior depends on zone settings, cache rules, origin
  headers, cookies, and whether strong ETags are respected.
- Cloudflare Tunnel is a simple way to expose a local Elastik core, but it is
  still an edge deployment decision outside the core.

Docs: [https://developers.cloudflare.com/cache/](https://developers.cloudflare.com/cache/)

## nginx

Headers nginx can consume when configured to do so:

```http
X-Accel-Redirect: /internal/file
X-Accel-Buffering: no
X-Accel-Expires: 300
X-Accel-Charset: utf-8
```

Headers nginx deployments often add:

```http
X-Cache-Status: HIT
X-Cache-Status: MISS
X-Cache-Status: BYPASS
X-Cache-Status: EXPIRED
X-Cache-Status: STALE
X-Cache-Status: UPDATING
X-Cache-Status: REVALIDATED
```

Useful config shape:

```nginx
proxy_cache_valid 200 1h;
proxy_cache_use_stale error timeout updating;
proxy_cache_key "$scheme$request_method$host$uri";
```

Notes:

- `X-Accel-Buffering: no` is important for SSE/EventSource. If nginx buffers,
  the stream may not flush until enough bytes accumulate.
- A plain `proxy_pass` commonly forwards headers as received, but actual
  behavior is configuration-dependent.
- `add_header` usually applies only to selected status classes unless configured
  with `always`.

Docs: [https://nginx.org/en/docs/](https://nginx.org/en/docs/)

## AWS CloudFront

CloudFront primarily follows standard HTTP cache headers:

```http
Cache-Control: max-age=86400
Cache-Control: s-maxage=86400
Surrogate-Control: max-age=600
```

Headers CloudFront returns itself:

```http
X-Cache: Hit from cloudfront
X-Cache: Miss from cloudfront
X-Amz-Cf-Id: request-trace-id
X-Amz-Cf-Pop: SYD1-C1
```

Notes:

- Forwarding `Authorization` is a distribution/behavior policy decision.
- ETags can be used for origin revalidation.
- Custom request/response headers depend on CloudFront policies.

Docs: [https://docs.aws.amazon.com/AmazonCloudFront/](https://docs.aws.amazon.com/AmazonCloudFront/)

## Fastly

Headers Fastly commonly consumes at the edge:

```http
Surrogate-Control: max-age=3600
Surrogate-Key: page-1 homepage
```

Headers Fastly returns itself:

```http
X-Served-By: cache-syd-001
X-Cache: HIT, HIT
X-Cache-Hits: 3
X-Timer: S1234567890.123456,VS0,VE5
```

Notes:

- `Surrogate-Control` targets the surrogate cache and is typically not meant as
  browser policy.
- `Surrogate-Key` is space-separated and enables tag-based purge workflows.
- `Vary` behavior is generally more complete than edge products that only vary
  on a short allowlist, but always check your service configuration.

Docs: [https://docs.fastly.com/en/guides/](https://docs.fastly.com/en/guides/)

## Vercel

Vercel edge caching mostly follows standard cache directives:

```http
Cache-Control: s-maxage=86400
Cache-Control: stale-while-revalidate=60
```

Headers Vercel returns itself:

```http
X-Vercel-Id: syd1::xxxxx-xxx
X-Vercel-Cache: HIT
X-Vercel-Cache: MISS
X-Vercel-Cache: STALE
X-Vercel-Cache: PRERENDER
```

Notes:

- `s-maxage` targets shared edge cache.
- `max-age` targets browsers.
- Cookies and dynamic serverless behavior can change cacheability.

Docs: [https://vercel.com/docs/](https://vercel.com/docs/)

## Akamai

Headers Akamai deployments may consume:

```http
Surrogate-Control: max-age=3600
Edge-Control: max-age=600
Cache-Tag: page-1
```

Headers Akamai returns itself:

```http
X-Akamai-Request-ID: request-trace-id
X-Cache: TCP_HIT
X-Cache: TCP_MISS
```

Notes:

- `Edge-Control` is Akamai-specific.
- `Cache-Tag` is a tag-style cache-control convention.
- Exact behavior depends heavily on Akamai property configuration.

Docs: [https://techdocs.akamai.com/](https://techdocs.akamai.com/)

## Rules Of Thumb

- Prefer standard headers first.
- Add vendor dialect headers only for the edge product you actually deploy.
- If a vendor-specific header conflicts with a standard header, the vendor's
  product may prefer its own dialect.
- Unknown headers usually pass through, do nothing, and stay harmless.
- This file is not maintained as a compatibility matrix. Treat it as a quick
  memory aid, not a contract.
- Elastik does not know or care which CDN you use. It stores your headers. Your
  CDN reads your headers. The bytes flow through. That is the entire model.
