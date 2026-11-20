# Site icons of outbound links

On the vulnerability page every link that leaves the site starts with the
target site's small icon ("favicon"). The icons are fetched by the server in
the background, stored in the database and served from our own origin, so a
reader's browser never contacts the third party.

Code: `internal/siteicon` (fetching, validation, the job, lookups),
`internal/webui/siteicons.go` (decoration and the `/icon/` route),
`internal/site/icons.go` (store methods), `internal/cli/siteicons.go`
(command). Migration `migrations/0028_site_icon.sql`.

## Table `site_icon`

One row per host: the lower-case ASCII (punycode) host name of a link, no
port, no trailing dot (`siteicon.ValidHost`; the same pattern is the
table's CHECK).

| Column | Meaning |
| --- | --- |
| `status` | `ok` an icon is stored; `none` the host has no usable icon (or is an address); `error` transient failures and no stored icon |
| `content_type`, `image`, `hash` | the validated bytes (at most 64 KiB), their type decided from the bytes, and the first 16 hex digits of their SHA-256; set exactly when `status = 'ok'` |
| `source_url` | where the bytes came from (after redirects); for operators |
| `fetched_at`, `next_try_at` | the last attempt; the host is due again from `next_try_at` |
| `failures`, `last_error` | consecutive transient failures; the last reason for `none`/`error` (for operators) |

## Which links

Exactly the anchors of the rendered vulnerability page's `<main>` that are
marked as leaving the site (`target="_blank"`, see the "Open links that
leave the site in a new tab" change; a test keeps every external link and
no internal one marked). They are found in the rendered page
(`webui.OutboundLinks`) because many are built as HTML in Go (summary
source, CVSS source, tag reasons, the implied-event basis) next to the
template's own: event sources, GHSA aliases, advisories and fix commits,
PoC items, CWE definitions, researcher profiles on X and the resources
panel (resolved post links and GitHub repositories). Internal links (raw
records, tags, other pages) get nothing.

The job cannot render pages, so it picks hosts with SQL over the tables the
page draws its URLs from (`siteicon.Due`): `event.url`, the PoC URL in
`event.detail`, the fix-commit URLs of patch events and the resolved
targets of researcher post links (`x_post_link.final_url`, status `ok`),
plus the hosts the page builds links to in Go (`siteicon.LinkedHosts`:
github.com, cwe.mitre.org, x.com). Hosts without a row come first, then by
how many distinct vulnerabilities link them. `TestSiteIconHostsCovered` renders every seeded
vulnerability page and fails when an outbound host is not one `Due` picks.

## The job (`nday site-icons [--limit N]`, timer `nday-site-icons.timer`)

Daily (deploy/README.md). Per run: at most `--limit` due hosts (default
200, at most 2000), one at a time, 1 s apart, at most 15 s a host and 15
minutes in all (hosts not reached stay due). Due hosts are new ones first,
then those linked by the most distinct vulnerabilities (a post link without
a CVE counts as its own); at most 5 hosts a run share the same last two
labels ("bucket"), so subdomains of one site cannot fill a run. At the end
of a run (also after the time budget) at most 1000 rows are deleted whose
host no page links any more and whose last attempt is over 90 days old.
Per host:

1. `https://<host>/favicon.ico`; a valid icon is stored.
2. Otherwise `https://<host>/`: the first of its `<link rel="icon">`,
   `"shortcut icon"` or `"apple-touch-icon"` (document order, relative URLs
   resolved against the final page URL, SVG candidates skipped, https only,
   another host allowed) that is a valid icon, at most 3 candidates.

Every request goes through `internal/pagefetch` with `HTTPSOnly`: the URL
rules, the connect-time address guard on every connection (public unicast
addresses only, so DNS rebinding cannot reach the inside), at most 3
redirects each re-checked (a redirect to http or to a non-public address is
refused without a connection), no proxy, no cookies, no Referer, 10 s a
request, bodies capped (64 KiB for images, 512 KiB for the home page).
The systemd unit also denies private, CGNAT, link-local and unique-local
addresses (`IPAddressDeny=`; PostgreSQL is reached over its unix socket). The
User-Agent is the other fetchers' (`nday-linkresolver/1`).

Outcomes and back-off:

| Outcome | Stored | Tried again |
| --- | --- | --- |
| valid icon | `ok` with the bytes | after 30 days |
| no valid icon, 4xx, refused | `none`, any stored icon dropped | after 30 days |
| transport error, 5xx, 408, 429 | `failures + 1`; `error`, or `ok` kept when an icon is stored | after 1 h, 4 h, 16 h, ... at most 30 days |

After the icons the same command runs the X avatar pass (`internal/xavatar`,
at most 100 avatars and 3 minutes, through a pagefetch client pinned to
`pbs.twimg.com`; its counts are under `avatars` in the output). It shares
this unit, its sandbox and `siteicon.ValidateImage`; see docs/xposts.md
"Author profiles and avatars".

## Validation (`siteicon.Validate`)

The bytes are served from our origin, so only these are accepted, decided
from the bytes (never the response's Content-Type): ICO, PNG, GIF, JPEG and
WebP, recognised by their magic bytes and a successful header decode
(`image.DecodeConfig` of the standard library, `golang.org/x/image/webp`
for WebP; an ICO's directory is parsed and every entry must lie inside the
file and be a PNG that decodes or a sane BITMAPINFOHEADER), 1 to 512 pixels
a side, at most 64 KiB. SVG, HTML and everything else is refused.

## Serving (`GET /icon/{host}`)

Locale-independent, on the site host, reserved as a handle (`icon`). It
returns only a stored row: the host must already be in normalised form
(anything else is 404, nothing is normalised, fetched or redirected). The
row is read from the database on each request (one primary-key read; the
CDN and browsers cache the response), not kept in the in-process page
cache, so made-up names cannot evict pages or pin icon bytes in memory.

| Header | Value |
| --- | --- |
| `Content-Type` | the stored type |
| `X-Content-Type-Options` | `nosniff` |
| `Content-Security-Policy` | `default-src 'none'; sandbox` |
| `Cross-Origin-Resource-Policy` | `same-origin` |
| `Cache-Control` | `public, max-age=86400, immutable` when `?v=` is the stored hash; `public, max-age=86400` without `?v=`; `public, max-age=300` for any other `?v=` and for 404 |
| `ETag` | the hash (304 on a match) |

## Rendering

The page looks its hosts up in one query per render (`site.Store.SiteIcons`,
through the shared 30 s cache), so it stays the same for every visitor and
publicly cacheable. Each outbound anchor gets `data-fav=""` and, as its
first child, either
`<img class="fav" src="/icon/<host>?v=<hash>" alt="" width="16" height="16" loading="lazy" decoding="async"/>`
or the placeholder `<span class="fav" aria-hidden="true"></span>`, a 16x16
box drawn in CSS. The stylesheet reserves 20 px at the start of the link
and places the icon in it, so the icon cannot wrap away from the link's
first word and nothing shifts when it loads. Decorative: no text, no
accessible name. A failed lookup is logged and gives placeholders.
