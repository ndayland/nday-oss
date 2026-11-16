# Following vendors and products, and the first-sign-in page

Implementation: `migrations/0010_follows.sql` (table `user_follows`), `internal/auth/store_follow.go` (all the SQL),
`internal/auth/service.go` (`POST /account/follows`, `POST /account/follows/match`, and `follows` in `/api/me`),
`internal/site/suggest.go` + `internal/web/api.go` (`GET /api/affected/suggest`),
`internal/webui/welcome.go` + `templates/welcome.tmpl` + `static/account.js` (the `/welcome` page),
and `static/app.js` (pinning on the home page). For the endpoint contracts see `docs/auth.md` §3.2 and §3.4; for the suggest endpoint see `docs/api.md`.

## 1. What a follow is

- A follow is a free-text term. It's stored in two columns: `label` (the spelling the user picked, such as `Palo Alto Networks`) and `term_key`
  (`lower(label)`, computed by the database).
- Matching rule: some `affected` row of a vulnerability has `lower(vendor) = term_key` **or** `lower(product) = term_key`.
  The whole name is compared, not a substring: following `fortinet` matches the vendor `Fortinet` but not the product `FortiOS`; following `openssh`
  matches the product `OpenSSH` (whose vendor is `OpenBSD`).
- The vendor and product names in `affected` are the upstream text as written (the CNA's spelling in the CVE record, KEV's `vendorProject`/`product`), and there's no normalized key.
  So the same thing can be spelled several ways. For example, most Windows CVEs are recorded under versioned product names like `Windows 11 Version 24H2`,
  so following `Windows` only matches the ones written as `Windows` (see the table in §4). This is deliberately kept simple: once vendors/products have canonical keys, the matching can be swapped out,
  and the table doesn't need to change (`term_key` is still the term the user picked).
- Each user can have at most 50, checked inside the transaction that replaces the whole list. A `label` is 1–200 characters, with leading and trailing whitespace removed and runs of whitespace collapsed to one space,
  and it can't contain control or format characters (C0/C1, bidi overrides, zero-width characters). Duplicates that differ only in case keep just the first.
- Follows are part of the account: they're deleted along with the row in `users` when the account is deleted (`ON DELETE CASCADE`).

## 2. Pinning on the home page

When a signed-in user follows at least one thing, `app.js` sends the CVE ids of the rows visible on the current page of the home page (the hot list), up to 200, to
`POST /account/follows/match`, and moves the matching rows into one group at the top of the table. The group header looks like the date group headers (`## following`),
the matching rows keep their original order, a date group header left empty by the move is removed, and the keyboard `j`/`k` keys and the selection cursor keep working.

- **Pinning only happens within the current page of results**: it doesn't fetch vulnerabilities from other pages or other time windows. After you change pages, matching runs again on the new page.
- If the user isn't signed in, follows nothing, or the request fails, nothing is touched (the page doesn't shift at all). The HTML itself is the same for everyone and can be publicly cached.
- "Reached a new stage" is simply what the hot list means (it's ordered by the latest stage change); pinning doesn't change which rows are in the list.
- It's unrelated to pinning rows by researcher discussion (server side, `pinned`, see `/api/hot` in `docs/api.md`): those rows are already first in the HTML (with a small "Pinned" label),
  and any of them that match a follow are moved into the "following" group as well.

## 3. The first-sign-in page `/welcome`

- When it appears: when the OAuth callback **creates** an account, it answers 303 to `/welcome` (keeping the return path's language prefix, with the original return path in `?next=`; see
  `auth.WelcomeReturn`. If the return path is itself the welcome page, its `next` is reused rather than nesting, and the `auth=` parameter isn't carried over). After a passkey-only sign-up succeeds,
  the sign-in page's script navigates to the address computed by the same function. Existing users signing in don't pass through here. There's no "onboarding done" flag column:
  the page can be opened at any time (the "add or change" link on the account page points to it).
- It's one screen with three items, all optional:
  1. Handle: if there's already one, it's shown (and not submitted unless changed); otherwise the input is **left empty**, and an empty field isn't submitted. The first linked identity with a valid handle
     (GitHub login, X username) is offered only as a button, "Use GitHub username ada". Clicking it fills the input, and you still have to click "done" to save.
     The format is checked live on the client with the same rule as the server; reserved names are known only to the server (`409 handle_reserved` on save).
  2. Follows: preset buttons (`aria-pressed`, with a text marker `[x]`/`[ ]`) plus a search box (at least 3 characters, debounced 250 ms, calling `/api/affected/suggest`).
     Click a search result to add it; selected items that aren't presets also show as pressed buttons.
  3. Community rules: shown only if `NDAY_TERMS_VERSION` is configured; shown as accepted if the current version is already accepted.
- The command echo line `$ nday init --handle … --follow … --accept-rules` changes live with the form. It's display only and doesn't correspond to a real command.
- "done" saves only the items that were changed (handle, follow list, rules), and each section shows its own errors. When everything succeeds it goes to `next` or that language's home page. `next` is validated by the server using the return-path rules,
  and also rejects non-canonical forms (empty segments `//`, `.`/`..`; one trailing slash is allowed) and any spelling of the welcome page itself.
  "skip all" is a plain link.
- The discussion comparison in the right column isn't shown for now (`WelcomeData.DiscussDemo` is false): posts don't have a display feature for signed-in users yet (`docs/xposts.md`), and showing it would promise a feature that doesn't exist. It'll be turned on once that feature ships. The rest of this item describes how it's implemented.
- The discussion comparison in the right column is sample content (the page says so). The signed-out column is drawn with CSS as wavy lines: the placeholder characters are transparent, each word gets its own `line-through wavy`,
  and it's `aria-hidden`. The placeholder word is a meaningless `x`, not sample body text; screen readers read one sentence, "Signed-out visitors do not see the text of this post."

## 4. Presets

Defined in `followPresets` in `internal/webui/welcome.go` (the only source), with `term` = `lower(label)`.
On 2026-11-14, against a local database (`affected` 85,065 rows, `vuln` 45,940 rows), the number of CVEs in which each term appears as a whole vendor name or product name was checked read-only:

| Shown as | term | Vendor | Product | Notes |
|---|---|---|---|---|
| Linux | `linux` | 2355 | 2333 | The kernel CNA writes both vendor and product as `Linux`; `linux kernel` appears only 2 times |
| Windows | `windows` | — | 184 | Poor coverage: most Windows CVEs are recorded under versioned product names |
| Chrome | `chrome` | — | 266 | |
| iOS and iPadOS | `ios and ipados` | — | 74 | The product `iOS` also appears 32 times and isn't listed separately |
| macOS | `macos` | — | 90 | |
| Android | `android` | 17 | 195 | |
| OpenSSH | `openssh` | — | 4 | |
| Fortinet | `fortinet` | 169 | — | |
| Ivanti | `ivanti` | 51 | — | |
| Cisco | `cisco` | 148 | — | |
| Palo Alto Networks | `palo alto networks` | 47 | — | |
| Citrix | `citrix` | 27 | — | The vendor `NetScaler` also appears 7 times |
| VMware | `vmware` | 32 | — | The vendor `Broadcom` also appears 6 times |
| Atlassian | `atlassian` | 14 | — | |
| GitLab | `gitlab` | 7 | 7 | |
| Kubernetes | `kubernetes` | 1 | — | Poor coverage: most are recorded under distribution product names |
| WordPress | `wordpress` | 8 | 6 | Plugin CVEs are recorded under the plugin author or plugin name and don't match |

## 5. Privacy and caching

- The follow list appears only in `/api/me` (`no-store`) and in the responses of the two signed-in endpoints; the HTML pages contain no personal data.
- `/api/affected/suggest` is public data (everything in `affected` comes from public sources, and vulnerability pages and search already show it), and it's publicly cached like search;
  it doesn't read cookies. In two-host mode the site host **also** answers this path directly (without a 308 to the API host), because the page's CSP is
  `connect-src 'self'`, so the script can't follow a redirect to the API host.
