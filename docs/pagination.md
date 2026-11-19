# Pagination

Every paginated list, public and admin, uses one pager (`internal/webui/pager.go`, `parts.tmpl` "pager"): the position, then first / previous / next as links (a disabled span where one does not apply). The links are plain links: without scripts every page is a full, server-rendered page, and a reload of any page URL renders that page.

## Position

The position says the page and the number of pages, then, where the list's rows have positions, the rows shown and the list's length: "page 2 of 15" "51–100 of 726" (`pager.page_of`, `pager.range_total`; zh-Hans "第 2 页，共 15 页" "第 51–100 条，共 726 条"). Back-office lists show the first part only. After an in-place page change the two parts are announced together ("page 2 of 15, 51–100 of 726").

Each list's length is counted with exactly the list's filters, never per position, and may be a few seconds older than the rows:

| List | Length from | Cost |
| --- | --- | --- |
| hot list (and tag pages) | `site.Store.HotCount`: the ordinary rows of the window / minimum stage / rejected / tag filters, pinned CVEs left out as the list leaves them out, plus the pinned rows; pages = ⌈ordinary rows / 50⌉ (page 1 also holds the pinned rows) | a range of `vuln_state_mat_hot_idx` from the window start; cached as the list (`CacheTTL`), key `site.Store.HotCountKey` (every filter and the pinning numbers) |
| catalogue, no year or tag | the whole-database counts of `/stats` (`catTotal`) | none (cached already) |
| catalogue with a year and/or tags | `site.Store.CatalogueCount` | a year: a bitmap scan of `vuln_state_mat_year_idx` / `_stage_year_idx` (the densest years may be one pass over the view); a tag: its entries of `vuln_tag_tag_idx`, joined to the view; cached 2×`CacheTTL`, key `CatalogueParams.CountKey` |
| /discussed | the ranking's window count (free); a page past the end takes it from the first page | — |
| back office | numbered lists: their total; keyset lists: one count per view (`docs/admin.md`) | — |

A hot list or catalogue filtered by a tag with more CVEs than `site.TagCountMax` (50,000; the smallest selected tag in the precomputed `vuln_tag_count`, one lookup inside the cached count) is not counted, and no count query runs: on the catalogue counting it reads the tag's index entries and the whole view in a hash join (≈170 ms for `network` at 425k rows); on the hot list a long window probes the tag for every row of the window (546 ms on production for `since=366d`, every stage, `tag=network`). On production that leaves out network, no-auth, no-interaction, remote-unauth, local, operating-system and xss. Its pager shows "page 2" "51–100" (`pager.page`, `pager.range`), as does a page whose length cannot be known.

The page number in a link (`?p=`, admin `?rp=` `?pp=` …) only labels the page; which rows are shown never depends on it. With a known length it is clamped (`clampPage`): never past the last page, never the last page while a next page exists; a length that is a moment older than the rows grows to fit, so "page 3 of 2" cannot appear. Whether there is a next page is always decided by the rows (the next control is disabled on the last page as before). A link without a page number shows no position.

The JSON API is unchanged: its list endpoints do not carry the length.

## Regions

Each paged list and its pager sit in one **region**: an element with a stable id and `data-page-region="<id>"`.

- Public: `r-hot` (the hot list, also on tag pages), `r-cat` (the catalogue and search results), `r-discussed`, `r-poc` (the "PoC / exploit code" group of a vulnerability page's resources: 10 links per page, most stars first, links without a shown star count last; `?pocp=`; the lifecycle chart always draws every link), `r-pocu` (on the same page, inside the collapsed `<details>` of the unreviewed repositories, so an in-place swap leaves it open: 10 per page; `?pocu=` on every page link, page 1 too, and the server renders the `<details>` open when `?pocu=` is present, so paging without script keeps it open; never on the chart).
- Admin: one per list (`r-queue`, `r-recent`, `r-users`, `r-accounts`, …; `internal/webui/admin_paging.go`). Admin pager links end in `#<id>`.

A region holds nothing that depends on an id outside it.

## Paging in place (`static/app.js` "paging")

A plain left click (no modifier key, no `target`, no `download`) on a page link of a region (a link of its pager, or a link to `#<id>` of that region, such as the status filter of the admin "latest comments" list) does not reload the page:

1. The region gets `aria-busy="true"` (dimmed by CSS) and ignores further clicks; a navigation already in flight is aborted.
2. The link's URL is fetched (same-origin GET of the same path, `credentials: 'same-origin'`, normal HTTP cache), parsed with `DOMParser`, and the region with the same id is imported in place of the current one. Nothing is inserted as a markup string.
3. `history.pushState` sets the link's URL (admin URLs keep their `#<id>`, as without scripts; `pushState` does not scroll). Back / forward fetch the URL popped to (or reuse a page loaded earlier in this page view) and swap back the regions whose page differs; the browser restores the scroll position.
4. Focus moves to the region (`tabindex="-1"`, no outline); the page scrolls only if the region's top is above the viewport; the pager's position words are announced in the status bar's live region.
5. What the page script set up at load is set up again for the new region only: local times, copy buttons, the row cursor (j/k, `#pos`), the hot list's followed rows, the signed-in-only parts, and `nday.adminInit(region)` on admin pages.

Outside the region, what depends on the list's position is taken from the loaded page: the title, `meta robots` (later pages of `/discussed` are `noindex`), canonical, `og:url`, the language links and `hreflang` alternates, the catalogue's search area (compact after page 1), and every other link to the same page and every hidden form field (the other lists' pagers and filters on admin pages carry this list's position). Those are updated in place, so the other regions keep their rows and selections; if the loaded page differs there (a list changed meanwhile), the other regions are replaced too. `TestPublicPageRegions` fails if anything else outside a public region starts to depend on the page.

Anything unexpected (network error, a status other than 200, a redirect, a type other than `text/html`, the region missing from the response) falls back to a normal navigation to the link (or a reload, for back / forward).

Filter chips outside a region (the hot list's since / stage, the catalogue's stage / year / tags) are not pagination and stay full navigations.
