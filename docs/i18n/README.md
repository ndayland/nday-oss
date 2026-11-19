# Writing a locale for nday

nday shows each vulnerability's lifecycle — disclosed → patch → analysis → PoC →
exploited in the wild → CISA KEV — honestly, including what is unknown. It is
read by IT and security practitioners. English is the primary language; every
other language is **written for its own security community**, not translated
from English or Chinese.

This kit is everything you need. You never touch Go code or templates.

| What | Where |
| --- | --- |
| Your catalog (all words of the site) | `internal/webui/i18n/catalogs/<tag>.json` — **you create this** |
| Your registry entry (numbers, plural rule, fonts, typography) | `internal/webui/i18n/locales.json` — **already filled in; review it** |
| Your notes (terminology, tone, doubts) | `docs/i18n/<tag>.md` — **you create this** |
| What every message is for (machine-readable key reference) | `internal/webui/i18n/keys.json` — read only |
| Reference catalogs (orientation, not a source text) | `catalogs/en.json`, `catalogs/zh-Hans.json` |
| Example notes | `docs/i18n/en.md`, `docs/i18n/zh-Hans.md` |
| Your generated sentences, for review | `internal/webui/testdata/golden/<tag>.txt` — created by a command below |

Tags and URL prefixes (already in the registry): `en` (root), `zh-Hans`
(`/zh-hans/`), `zh-Hant` (`/zh-hant/`), `ja` (`/ja/`), `ko` (`/ko/`), `es`
(`/es/`), `fr` (`/fr/`). A locale is served as soon as its catalog file exists
and passes every check; until then its prefix is a 404.

## 1. Principles

1. **Write natively, from the intent.** Each key in `keys.json` has `where`
   (page/section), `intent` (what the reader must understand) and
   `constraints`. Write what a practitioner in your community would write in
   that spot. Do not follow the English sentence structure; do not follow the
   Chinese one either. Read `en.json` only to see how one community solved the
   same problem.
2. **Use your community's established vocabulary** — the words your national
   CERT, vendors' advisories and practitioners actually use (e.g. for
   "exploited in the wild", "proof of concept", "patch", "advisory",
   "remediation due date", "forensic triage", CVSS severity names). When in
   doubt, prefer the term in your CERT's / national agency's advisories and
   record the choice and its source in your notes file.
3. **Keep language-neutral tokens exactly as they are**, in every locale:
   stage codes `DIS PAT ANA POC ITW KEV`, diff notation `+KEV` `~ITW`,
   `T+8d` `T-20d` `T+?`, `n/3` counts, ISO 8601 UTC times
   (`2026-11-09T22:15Z`, `2026-11-09`, `≤ 2026-11-09`), CLI flags
   (`--since`, `--min-stage`, `--include-rejected`), paths (`~/hot`,
   `~/vuln`, `~/src`), API parameter and field names (`since`, `min_stage`,
   `snake_case`, `null`), source names (`cvelist`, `kev`, `ghsa`,
   `exploitdb`, `metasploit`, `nuclei`), status tokens (`ok`, `partial`,
   `error`, `REJECTED`, SSVC values `active`, `poc`), `NORMAL`, `rss`, `api`.
   Their **legends and explanations** are yours to write.
4. **Honesty wording must be unambiguous.** These four ideas recur and must
   never be softened or confused:
   - *unknown* — the source gave no time/value; we do not know (≠ "none", ≠ "never");
   - *inferred* — derived from another fact (exploitation inferred from a KEV listing), not reported directly;
   - *not later than* (`≤`) — only an upper bound is known;
   - *not listed* / *no record yet* — nday has no record (≠ "does not exist", ≠ "safe").
   Pick one wording for each in your notes and use it consistently.
5. **One message = one complete unit.** Code never glues fragments: it picks
   which complete message applies and fills placeholders. So you control word
   order, particles, spacing, punctuation, quotation marks and the joiner
   between sentences. If a message cannot be written well in your language
   because of how it is split, write it as well as you can and record the
   problem in your notes ("Open doubts") — that is how the split gets fixed.
6. **Register:** concise, precise, terminal-flavoured; no marketing tone, no
   exclamation marks. Labels are short; sentences are complete.

## 2. Catalog format

A catalog is one JSON file, plain text only (never HTML, never entities):

```json
{
  "locale": "ja",
  "messages": {
    "sbar.utc": "…",
    "statusline.vulns": "… {n}",
    "sbar.events": "{n} …",
    "stage.name": {"DIS": "…", "PAT": "…", "ANA": "…", "POC": "…", "ITW": "…", "KEV": "…"},
    "sentence.joiner": ""
  }
}
```

- **Placeholders** are named: `{days}`, `{version}`, `{time}`. Each key's
  `placeholders` in `keys.json` lists them with `kind`, `meaning` and
  `example`. Put them wherever your grammar needs them. Placeholders are
  required unless marked `"optional": true`. Kinds:
  - `text` / `number` — plain values (numbers are formatted with your registry's grouping);
  - `token` — language-neutral (codes, times, versions, IDs): never wrap or translate;
  - `upstream` — record text in its original language (English); the page marks it `lang="en"`;
  - `html` — an inline element the page builds (a `<kbd>`, `<code>`, a link,
    a coloured stage code). You only place `{name}`; never type markup.
- **Plural messages** (`"plural": "<count placeholder>"` in the reference)
  are an object keyed by the CLDR categories your registry's plural rule needs:
  - `one_other` (en, es): `{"one": "…", "other": "…"}`;
  - `zero_one_other_fr` (fr: 0 and 1 are singular): `{"one": "…", "other": "…"}`;
  - `none` (zh-Hans, zh-Hant, ja, ko): a plain string (or `{"other": "…"}`).
  The count placeholder must appear in `other`; `one` may spell the number out.
  Some plural keys select on a count you need not print (e.g. `{more}` in
  `status.patch.fixed_many`) — the reference marks those placeholders optional.
- **Select messages** (`"select": {"var": …, "values": […]}`) are an object
  with exactly one entry per listed value, e.g. `ev.kev.added` has
  `plain`, `due`, `forensic`, `due_forensic`; `stage.name` has one entry per
  stage code; `ev.generic` has an `other` fallback. Each variant is a whole
  sentence/label of its own, so you can change grammar per variant (gender,
  verb, word order).
- **Lists** are yours: `list.and.*` (in prose: "a, b and c") and `list.seq.*`
  (compact UI lists: "a, b, c"), as CLDR list patterns `two`, `start`,
  `middle`, `end` with `{a}` `{b}`. `sentence.joiner` goes between generated
  sentences (English: a space; Chinese/Japanese: empty). `strip.sep` joins
  the clauses of the lifecycle-strip screen-reader label.
- **Kinds** in the reference: `label` (UI label, no final punctuation unless
  your language needs it), `title` (heading or `<title>`), `phrase`
  (fragment-like text such as a tooltip), `sentence` (must end with one of
  your registry's `sentence_final` characters), `pattern` (a frame around
  values), `joiner`.
- **`max_cols`**: display width limit for tight spots (table headers, status
  bar, buttons), counted without placeholders; CJK characters count 2.

## 3. Typography you are responsible for

Checked automatically when your registry entry asks for it:

- **zh-Hans / zh-Hant / ja** (`fullwidth_punct`): full-width punctuation
  next to Han/Kana (`，。：；！？（）`), sentences end in `。`. Leave a space
  between CJK text and Latin tokens/placeholders where your community's
  convention wants it (be consistent; note it).
- **fr** (`nbsp_before`, `nbsp_after`): a no-break space before `: ; ? ! »`
  and after `«` — U+202F (narrow) before `; ? !`, U+00A0 before `:` and
  inside guillemets are both accepted. Write them as the characters, not as
  `&nbsp;`.
- **es**: opening `¿ ¡` where needed; quotation marks « » or “ ” as your
  community prefers (note the choice).
- **ko**: Korean uses ASCII punctuation; sentences end with `.`.
- Quotation marks around upstream titles (e.g. `ev.edb.added`): use your
  language's own (“…”, «…», 「…」, 《…》…).
- Numbers: grouping comes from the registry (`45,965` en/zh/ja/ko,
  `45.965` es — but `1000` without grouping, `45 965` with U+202F fr). Don't
  type separators yourself.

## 4. The registry entry

`internal/webui/i18n/locales.json` already has an entry for every language;
check yours and fix it if your community's conventions differ:

```json
{
  "tag": "fr",
  "prefix": "fr",
  "native_name": "Français",
  "match": ["fr"],
  "plural": "zero_one_other_fr",
  "number": {"group": " ", "min_group_digits": 1},
  "fonts_cjk": [],
  "typography": {"sentence_final": [".", "!", "?", "…"], "nbsp_before": ";:!?»", "nbsp_after": "«"}
}
```

- `match`: lower-case browser language tags that prefer this locale (used by
  the optional "read this page in …" line). The longest match wins; `zh`
  alone goes to zh-Hans, `zh-tw`/`zh-hk` to zh-Hant.
- `fonts_cjk`: font families for Han/Kana/Hangul, in order; they are turned
  into `:root:lang(<tag>) { --cjk: … }` so Han characters get the right
  regional glyphs. Latin text stays in JetBrains Mono / the system UI font.
- Changing `tag` or `prefix` changes URLs; don't, unless asked.

## 5. Validate and preview

From the repository root:

```sh
# 1. catalog checks (all keys, no unknown keys, placeholders, plural/select
#    variants, no HTML/entities, no empty strings, max_cols, typography)
go test ./internal/webui/i18n -run TestCatalogs -count=1 -v

# 2. generate your sentence file for review, then run every page test
#    in every enabled locale (needs the local Postgres on 127.0.0.1:54329)
go test ./internal/webui -run TestGolden -update -count=1
go test ./internal/webui ./internal/webui/i18n -count=1

# 3. preview: real pages + the catalog preview page
go build -o /tmp/nday ./cmd/nday
NDAY_I18N_DEBUG=1 NDAY_DATABASE_URL=postgresql://nday:nday@127.0.0.1:54329/nday \
  /tmp/nday serve --listen 127.0.0.1:18090
```

Open (replace `ja` with your prefix):

- `http://127.0.0.1:18090/__i18n/ja` — **catalog preview**: every message
  with example values highlighted, every plural and select variant, the
  status paragraph for 21 data scenarios and the event text for 37 event
  shapes, plus validation problems at the top. It works while your catalog
  is still incomplete (missing messages show as `⟦key⟧`). Add `?ref=en` to see
  another locale under each message — for orientation only.
- `http://127.0.0.1:18090/ja/` (home), `/ja/vuln/CVE-2026-102895`,
  `/ja/vuln?q=barracuda`, `/ja/src`, `/ja/stats`, `/ja/about`,
  `/ja/feed.xml`, `/ja/no/such/page` (404), `/ja/vuln/not-a-cve` (400).
- Check at 1440px and 390px wide: the nav, table headers, status bars, flag
  rows and legends must not break or overflow.

The preview page and pages are only served for your locale once the catalog
passes; the preview page (`/__i18n/<tag>`) always works with
`NDAY_I18N_DEBUG=1`, which is never set in production.

## 6. Your notes file

Create `docs/i18n/<tag>.md` with these sections (see `en.md`, `zh-Hans.md`):

1. **Audience and register** — who reads it, tone, formality, how you
   address the reader.
2. **Terminology** — a table: concept → chosen wording → why / source
   (CERT advisories, vendor docs, standard glossaries).
3. **Honesty vocabulary** — your fixed wordings for unknown / inferred /
   not later than / not listed / no record yet.
4. **Typography decisions** — spacing around Latin tokens, quotation marks,
   punctuation, numbers.
5. **Open doubts** — anything you could not write well, with the key and why
   (e.g. a split that forces an unnatural order, a too-tight `max_cols`).

## 7. Out of scope for now

Vulnerability titles and descriptions come from upstream in English and are
shown as is (marked `lang="en"`; `note.upstream_original` says so once per
page). Per-language summaries of the record content are a later milestone.
The JSON API and `/raw/` are language-neutral and unchanged.

## 8. Pending keys (English shown for now)

Translation of the sign-in and account pages, the discussion section of
vulnerability pages and the community rules page is **on hold**, and so are the staff back office (`/admin`) and, since
2026-11-14, the CVE tags (`docs/tags.md`) and the credits panel of
vulnerability pages (who the CVE record and GitHub advisories credit).
`internal/webui/i18n/pending.json` lets `zh-Hant`, `ja`,
`ko`, `es` and `fr` leave out every key starting with `acct.`, `disc.`,
`rules.`, `admin.`, `tag.`, `credit.` or (since 2026-11-15, the readers'
corrections of vulnerability pages, `docs/corrections.md`) `corr.`, plus the single key
`sbar.local_time` (the status-bar note shown when the page script has
converted times to the reader's time zone) and, since 2026-11-14, the three
single keys of the NVD source (its row on the sources page and the NVD
attribution notice on the about page, see `docs/nvd.md`) and, since
2026-11-15, the change-in-words of hot list rows and the home page link to
the list rules (two single keys), the about page section on how the home
list is ordered and pinned (prefix `about.hot.`), the source line under an
untranslated summary (a single key) and the exploit conditions block of
vulnerability pages (prefix `vuln.cvss.`) and, since 2026-11-16, the three
sentences for a withdrawn GitHub advisory that has no CVE (its banner, with
and without a date, and its status sentence; single keys); those locales stay
enabled and show the English text for these keys (marked `lang="en"`). Every
other key stays mandatory, and an `acct.` key you do add is checked like any
other. When your catalog has all of them, remove your tag from the entry in
`pending.json` (`TestPendingNotStale` tells you); an entry is either a
`prefix` (ending in `.`) or a single `key`. `en` and `zh-Hans` are
complete. The pending keys (771; their `where`/`intent` are in `keys.json`,
groups `account`, `welcome`, `discuss`, `corrections`, `rules`, `admin`, `tags` and `credits`, except the single keys above:
the status-bar note is in group `chrome`, the two NVD source keys in group `src`,
the NVD notice and the `about.hot.` keys in group `about`, the two `hot.` keys in
group `hot`, the `vuln.` keys in group `vuln` and the withdrawn-advisory status sentence in group `status`):

- `src.nvd.what`, `src.nvd.produces`
- `about.nvd_notice`
- `hot.change`, `hot.rules_link`
- `about.hot.h2`, `about.hot.order`, `about.hot.repeat`, `about.hot.window`, `about.hot.pin`, `about.hot.pin_count`, `about.hot.pin_recent`, `about.hot.pin_wave`, `about.hot.pin_filter`, `about.hot.pin_order`, `about.hot.pin_settings`, `about.hot.pin_off`
- `vuln.summary.upstream`
- `vuln.withdrawn.banner`, `vuln.withdrawn.banner_at`, `status.withdrawn`
- `vuln.cvss.h2`, `vuln.cvss.note`, `vuln.cvss.metric`, `vuln.cvss.av`, `vuln.cvss.ac`, `vuln.cvss.ac4`, `vuln.cvss.at`, `vuln.cvss.pr`, `vuln.cvss.ui`, `vuln.cvss.ui4`, `vuln.cvss.av2`, `vuln.cvss.ac2`, `vuln.cvss.au`, `vuln.cvss.unknown_value`, `vuln.cvss.unknown_version`, `vuln.cvss.source`
- `tag.name`, `tag.desc`, `tag.desc_product`, `tag.dim`, `tag.dim_desc`, `tag.source`, `tag.basis.cwe`, `tag.basis.cvss`, `tag.basis.kev`, `tag.basis.poc`, `tag.basis.poc_more`, `tag.basis.ghsa`, `tag.basis.ghsa_nopkg`, `tag.basis.none`, `tag.basis.affected`, `tag.basis.cpe`, `tag.basis.more`, `tag.basis.products`, `tag.basis.type_rule`, `tag.vuln.label`, `tag.vuln.why`, `tag.vuln.derived`, `tag.vuln.v2_note`, `tag.filter.remove`, `tag.filter.empty`, `tag.page.title`, `tag.page.description`, `tag.page.h1`, `tag.page.lede`, `tag.page.counts_never`, `tag.page.more`, `tag.counts_at`, `tag.sbar`, `tag.one.title`, `tag.one.count`, `tag.one.cwes`, `tag.one.derived`, `tag.feed.title`, `tag.api`
- `credit.h2`, `credit.role`
- `acct.slot.signin`, `acct.slot.account`, `acct.menu.signout`
- `acct.role.badge`, `acct.role.name`
- `acct.banner.ok`, `acct.banner.linked`, `acct.banner.denied`, `acct.banner.conflict`, `acct.banner.error`, `acct.banner.signed_in_as_other`, `acct.banner.reauth_required`, `acct.banner.suspended`, `acct.banner.dismiss`
- `acct.login.title`, `acct.login.description`, `acct.login.h1`, `acct.login.lede`, `acct.login.first_time`, `acct.login.providers_h2`, `acct.login.provider`, `acct.login.passkey_h2`, `acct.login.passkey`, `acct.login.passkey_note`, `acct.login.signup_h2`, `acct.login.signup_name`, `acct.login.signup_submit`, `acct.login.signed_in`, `acct.login.go_account`, `acct.login.go_back`, `acct.login.switch_note`, `acct.login.nojs`
- `acct.page.title`, `acct.page.description`, `acct.page.h1`, `acct.page.loading`, `acct.page.unknown`, `acct.page.signed_out`, `acct.page.nojs`
- `acct.suspended.until`, `acct.suspended.open`, `acct.suspended.reason`, `acct.suspended.limits`
- `acct.security.h2`, `acct.developer.h2`, `acct.account.h2`
- `acct.profile.h2`, `acct.profile.handle`, `acct.profile.display_name`, `acct.profile.role`, `acct.profile.member_since`, `acct.profile.not_set`, `acct.profile.readonly`
- `acct.handle.label`, `acct.handle.submit`, `acct.handle.rules`, `acct.handle.next`, `acct.handle.saved`
- `acct.methods.h2`, `acct.methods.linked`, `acct.methods.linked_as`, `acct.methods.not_linked`, `acct.methods.link`, `acct.methods.unlink`, `acct.methods.unlinked`, `acct.methods.note`
- `acct.passkeys.h2`, `acct.passkeys.none`, `acct.passkeys.name`, `acct.passkeys.created`, `acct.passkeys.last_used`, `acct.passkeys.backed_up`, `acct.passkeys.never`, `acct.passkeys.add_label`, `acct.passkeys.add`, `acct.passkeys.added`, `acct.passkeys.rename`, `acct.passkeys.rename_label`, `acct.passkeys.renamed`, `acct.passkeys.delete`, `acct.passkeys.deleted`, `acct.passkeys.limit`, `acct.passkeys.unsupported`
- `acct.save`
- `acct.cancel`
- `acct.yes`
- `acct.no`
- `acct.busy`
- `acct.sessions.h2`, `acct.sessions.current`, `acct.sessions.recent`, `acct.sessions.not_recent`, `acct.sessions.signout`, `acct.sessions.signout_all`, `acct.sessions.signout_all_note`, `acct.sessions.signed_out`, `acct.sessions.signed_out_all`
- `acct.terms.h2`, `acct.terms.accepted`, `acct.terms.pending`, `acct.terms.accept`, `acct.terms.saved`
- `acct.delete.h2`, `acct.delete.note`, `acct.delete.confirm_label`, `acct.delete.submit`, `acct.delete.done`
- `acct.reauth.h2`, `acct.reauth.provider`, `acct.reauth.passkey`, `acct.reauth.none`, `acct.reauth.done`
- `acct.err.suspended`, `acct.err.reauth_required`, `acct.err.last_identity`, `acct.err.last_usable_method`, `acct.err.passkey_limit`, `acct.err.passkey_exists`, `acct.err.display_name_reserved`, `acct.err.invalid_handle`, `acct.err.handle_reserved`, `acct.err.handle_taken`, `acct.err.signup_limit`, `acct.err.rate_limited`, `acct.err.busy`, `acct.err.csrf`, `acct.err.ticket_invalid`, `acct.err.cross_site`, `acct.err.not_signed_in`, `acct.err.webauthn_cancelled`, `acct.err.ceremony_invalid`, `acct.err.passkey_rejected`, `acct.err.not_linked`, `acct.err.not_found`, `acct.err.terms_version_mismatch`, `acct.err.network`, `acct.err.handle_change_too_soon`, `acct.err.generic`
- `acct.welcome.title`, `acct.welcome.description`, `acct.welcome.h1`, `acct.welcome.lede`, `acct.welcome.handle_h2`, `acct.welcome.handle_rules`, `acct.welcome.handle_use`, `acct.welcome.handle_ok`, `acct.welcome.handle_empty`, `acct.welcome.handle_current`, `acct.welcome.follows_h2`, `acct.welcome.follows_count`, `acct.welcome.follows_note`, `acct.welcome.presets_label`, `acct.welcome.search_label`, `acct.welcome.search_hint`, `acct.welcome.search_none`, `acct.welcome.search_count`, `acct.welcome.search_failed`, `acct.welcome.rules_accept`, `acct.welcome.rules_note`, `acct.welcome.rules_link`, `acct.welcome.rules_done`, `acct.welcome.cmd_label`, `acct.welcome.finish`, `acct.welcome.finish_next`, `acct.welcome.skip`, `acct.welcome.partial`, `acct.welcome.side_h2`, `acct.welcome.side_out`, `acct.welcome.side_in`, `acct.welcome.sample_hidden`, `acct.welcome.sample_author`, `acct.welcome.sample_text`, `acct.welcome.sample_note`
- `acct.follows.h2`, `acct.follows.none`, `acct.follows.note`, `acct.follows.add`, `acct.follows.remove`, `acct.follows.remove_label`, `acct.follows.saved`, `acct.follows.pinned`
- `acct.err.invalid_follow`, `acct.err.too_many_follows`
- `acct.api.tokens_h3`, `acct.api.create`, `acct.api.once`, `acct.api.deleted`, `acct.api.feed_h3`, `acct.api.feed_reset`, `acct.api.feed_reset_confirm`, `acct.api.feed_reset_done`, `acct.api.ref_h3`, `acct.err.token_limit`
- `disc.h2`, `disc.count`, `disc.empty`, `disc.unavailable`, `disc.more`, `disc.more_replies`, `disc.first`, `disc.replies_label`, `disc.nojs`, `disc.state_unknown`, `disc.signin`, `disc.no_handle`, `disc.no_handle_link`, `disc.suspended`, `disc.limit`, `disc.reported`, `disc.cancel`, `disc.delete_confirm`, `disc.hidden_reason`, `disc.busy`
- `disc.comment.deleted_account`, `disc.comment.edited`, `disc.comment.lang`, `disc.comment.permalink`, `disc.comment.hidden`, `disc.comment.deleted`
- `disc.compose.label`, `disc.compose.submit`
- `disc.purpose_label`, `disc.purpose_none`, `disc.purpose`, `disc.purpose_hint`
- `disc.guest.loading`, `disc.guest.nojs`, `disc.guest.signin_note`
- `disc.terms.agree`, `disc.terms.needed`, `disc.terms.updated`
- `disc.md.summary`, `disc.md.paragraph`, `disc.md.break`, `disc.md.em`, `disc.md.strong`, `disc.md.code`, `disc.md.fence`, `disc.md.quote`, `disc.md.list`, `disc.md.olist`, `disc.md.link`, `disc.md.autolink`, `disc.md.cve`, `disc.md.escape`, `disc.md.unsupported`, `disc.md.new_links`
- `disc.act.reply`, `disc.act.edit`, `disc.act.delete`, `disc.act.report`, `disc.act.hide`, `disc.act.unhide`
- `disc.reply.label`, `disc.reply.submit`
- `disc.edit.label`, `disc.edit.submit`
- `disc.report.reason_label`, `disc.report.reason`, `disc.report.note_label`, `disc.report.submit`, `disc.report.done`, `disc.report.already`
- `disc.hide.reason_label`, `disc.hide.submit`
- `disc.mod.source`, `disc.mod.revisions`, `disc.mod.revision_at`
- `disc.err.not_signed_in`, `disc.err.cross_site`, `disc.err.csrf`, `disc.err.suspended`, `disc.err.handle_required`, `disc.err.terms_required`, `disc.err.forbidden`, `disc.err.not_author`, `disc.err.own_comment`, `disc.err.wrong_status`, `disc.err.not_found`, `disc.err.bad_cve`, `disc.err.bad_parent`, `disc.err.thread_full`, `disc.err.duplicate`, `disc.err.invalid_body`, `disc.err.bad_lang`, `disc.err.bad_purpose`, `disc.err.bad_reason`, `disc.err.bad_note`, `disc.err.bad_resolution`, `disc.err.bad_cursor`, `disc.err.bad_request`, `disc.err.too_large`, `disc.err.rate_limited`, `disc.err.rate_limited_later`, `disc.err.daily_limit`, `disc.err.busy`, `disc.err.wrong_host`, `disc.err.internal`, `disc.err.network`, `disc.err.terms_version_mismatch`, `disc.err.empty`, `disc.err.too_long`, `disc.err.terms_unchecked`, `disc.err.generic`
- `corr.h2`, `corr.lede`, `corr.open`, `corr.nojs`, `corr.state_unknown`, `corr.signin`, `corr.no_handle`, `corr.no_handle_link`, `corr.terms_needed`, `corr.terms_link`, `corr.suspended`, `corr.category`, `corr.status`, `corr.busy`, `corr.done`
- `corr.form.category`, `corr.form.body`, `corr.form.limit`, `corr.form.url`, `corr.form.private`, `corr.form.submit`
- `corr.mine.h3`, `corr.mine.at`, `corr.mine.note`
- `corr.log.h2`, `corr.log.count`, `corr.log.note`, `corr.log.by`, `corr.log.by_deleted`
- `corr.err.not_signed_in`, `corr.err.suspended`, `corr.err.handle_required`, `corr.err.terms_required`, `corr.err.csrf`, `corr.err.cross_site`, `corr.err.bad_category`, `corr.err.invalid_body`, `corr.err.bad_url`, `corr.err.too_many_open`, `corr.err.queue_full`, `corr.err.daily_limit`, `corr.err.rate_limited`, `corr.err.not_found`, `corr.err.too_large`, `corr.err.network`, `corr.err.empty`, `corr.err.generic`, `corr.err.too_long`
- `rules.title`, `rules.page_title`, `rules.description`, `rules.version`, `rules.about`, `rules.account`, `rules.contact`
- `rules.r1.title`, `rules.r1.body`, `rules.r2.title`, `rules.r2.body`, `rules.r3.title`, `rules.r3.body`, `rules.r4.title`, `rules.r4.body`, `rules.r5.title`, `rules.r5.body`, `rules.r6.title`, `rules.r6.body`, `rules.r7.title`, `rules.r7.body`, `rules.r8.title`, `rules.r8.body`
- `admin.slot`
- `admin.page_title`
- `admin.description`
- `admin.signed_in_as`
- `admin.nav_label`
- `admin.nav`
- `admin.none`
- `admin.stats.range_label`, `admin.stats.days`, `admin.stats.fresh`, `admin.stats.never`, `admin.stats.note`, `admin.stats.zone`, `admin.stats.cards_h2`, `admin.stats.card`, `admin.stats.today`, `admin.stats.human`, `admin.stats.cards_note`, `admin.stats.charts_h2`, `admin.stats.chart`, `admin.stats.series`, `admin.stats.bar`, `admin.stats.chart_aria`, `admin.stats.gap`, `admin.stats.gap_day`, `admin.stats.chart_empty`, `admin.stats.tops_h2`, `admin.stats.bot_share`, `admin.stats.tops_note`, `admin.stats.top`, `admin.stats.col`, `admin.stats.count`, `admin.stats.none`, `admin.stats.map_h2`, `admin.stats.map_note`, `admin.stats.map_aria`, `admin.stats.map_item`, `admin.stats.map_nodata`, `admin.stats.map_range`, `admin.stats.map_none`, `admin.stats.map_unplaced`
- `admin.mod.read_only`, `admin.mod.queue_h2`, `admin.mod.queue_empty`, `admin.mod.recent_h2`, `admin.mod.recent_empty`, `admin.mod.filter_label`, `admin.mod.all`, `admin.mod.status`, `admin.mod.gone`, `admin.mod.edited`, `admin.mod.open_reports`, `admin.mod.hidden`, `admin.mod.hidden_by`, `admin.mod.history`, `admin.mod.replaced`, `admin.mod.reports`, `admin.mod.reporters`, `admin.mod.open`, `admin.mod.hide_reason`
- `admin.act.hide`, `admin.act.unhide`, `admin.act.dismiss`
- `admin.users.search_label`, `admin.users.search`, `admin.users.empty`
- `admin.user.field`, `admin.user.status`, `admin.user.no_handle`, `admin.user.limited`, `admin.user.profile_h2`, `admin.user.until`, `admin.user.until_lifted`, `admin.user.methods_h2`, `admin.user.actions_h2`, `admin.user.self`, `admin.user.protected`, `admin.user.recent_note`, `admin.user.suspend_reason`, `admin.user.suspend_for`, `admin.user.duration`, `admin.user.suspend`, `admin.user.resuspend`, `admin.user.unsuspend`, `admin.user.grant_mod`, `admin.user.revoke_mod`, `admin.user.signout_all`, `admin.user.signout_note`, `admin.user.comments_h2`, `admin.user.reports_about_h2`, `admin.user.reports_filed_h2`, `admin.user.audit_h2`
- `admin.rep.col`, `admin.rep.state`
- `admin.audit.filter`, `admin.audit.any`, `admin.audit.apply`, `admin.audit.empty`, `admin.audit.col`, `admin.audit.cli`, `admin.audit.role`, `admin.audit.action`, `admin.audit.target`
- `admin.sys.collectors_h2`, `admin.sys.col`, `admin.sys.state_at`, `admin.sys.state_never`, `admin.sys.state_error`, `admin.sys.db_h2`, `admin.sys.db_size`, `admin.sys.rows_note`, `admin.sys.stats_h2`, `admin.sys.stats_line`, `admin.sys.stats_never`, `admin.sys.logs_h2`, `admin.sys.logs_off`, `admin.sys.logs_missing`, `admin.sys.logs_files`, `admin.sys.logs_nofile`, `admin.sys.logs_unreadable`, `admin.sys.logs_cut`, `admin.sys.logs_none`, `admin.sys.process_h2`, `admin.sys.field`, `admin.sys.modified`, `admin.sys.not_public`, `admin.sys.jobs_h2`, `admin.sys.job`, `admin.sys.job_status`, `admin.sys.backlog`
- `admin.x.lede`, `admin.x.status_h2`, `admin.x.field`, `admin.x.last_run_h3`, `admin.x.skipped`, `admin.x.stopped`, `admin.x.never_ran`, `admin.x.token_note`, `admin.x.cost_h2`, `admin.x.price`, `admin.x.last_cost`, `admin.x.worst`, `admin.x.worst_posts`, `admin.x.schedule_note`, `admin.x.settings_h2`, `admin.x.settings_at`, `admin.x.settings_none`, `admin.x.setting`, `admin.x.onoff`, `admin.x.use_default`, `admin.x.range`, `admin.x.save`, `admin.x.field_err`, `admin.x.accounts_h2`, `admin.x.accounts_note`, `admin.x.search_label`, `admin.x.search`, `admin.x.search_clear`, `admin.x.accounts_range`, `admin.x.search_found`, `admin.x.search_none`, `admin.x.col`, `admin.x.state`, `admin.x.gh_linked`, `admin.x.enable`, `admin.x.disable`, `admin.x.edit`, `admin.x.profiles`, `admin.x.profiles_done`, `admin.x.add_h3`, `admin.x.add`, `admin.x.lookup_on`, `admin.x.lookup_off`, `admin.x.add_id`, `admin.x.add_done`, `admin.x.add_renamed`, `admin.x.import_h3`, `admin.x.import_note`, `admin.x.preview`, `admin.x.import`, `admin.x.import_preview`, `admin.x.import_line`, `admin.x.import_found`, `admin.x.posts_h2`, `admin.x.per_account_h3`, `admin.x.posts_none`, `admin.x.on_x`, `admin.x.seen`, `admin.x.cand_h2`, `admin.x.cand_col`, `admin.x.cand_kind`, `admin.x.cand_add`, `admin.x.cand_dismiss`, `admin.x.cand_restore`, `admin.x.cand_dismissed`
- `admin.gh.list`, `admin.gh.col`, `admin.gh.more`, `admin.gh.flag`, `admin.gh.source`, `admin.gh.act`, `admin.gh.owner`, `admin.gho.h2`, `admin.gho.pending`, `admin.gho.col`
- `admin.xd.lede`, `admin.xd.run`, `admin.xd.run_never`, `admin.xd.run_deferred`, `admin.xd.pending_h2`, `admin.xd.open_note`, `admin.xd.empty`, `admin.xd.created`, `admin.xd.body_label`, `admin.xd.length`, `admin.xd.save`, `admin.xd.open`, `admin.xd.save_first`, `admin.xd.post_url`, `admin.xd.mark_posted`, `admin.xd.discard`, `admin.xd.restore`, `admin.xd.history_h2`, `admin.xd.history_empty`, `admin.xd.col`, `admin.xd.status`, `admin.xd.form_label`, `admin.xd.form`, `admin.xd.length_alone`, `admin.xd.copy_image`, `admin.xd.download_image`, `admin.xd.copy_link`, `admin.xd.copied`, `admin.xd.copy_failed`, `admin.xd.body_label_alone`, `admin.xd.over_link`
- `admin.ti.h2`, `admin.ti.lookup`, `admin.ti.find`, `admin.ti.not_found`, `admin.ti.filter_label`, `admin.ti.filter`, `admin.ti.col`, `admin.ti.counts`, `admin.ti.edit`, `admin.ti.ref`, `admin.ti.staff_label`, `admin.ti.save`, `admin.ti.clear`
- `admin.set.lede`, `admin.set.unavailable`, `admin.set.warnings`, `admin.set.group_h2`, `admin.set.group_note`, `admin.set.empty_note`, `admin.set.desc`, `admin.set.jump_label`, `admin.set.name`, `admin.set.effect`, `admin.set.source`, `admin.set.restart`, `admin.set.not_stored`, `admin.set.save`, `admin.set.secrets_h3`, `admin.set.secrets_note`, `admin.set.no_key`, `admin.set.secret_state`, `admin.set.secret_set_hint`, `admin.set.secret_save`, `admin.set.secret_clear`, `admin.set.clear_on_save`, `admin.set.saved`, `admin.set.saved_restart`, `admin.set.unchanged`, `admin.set.secret_empty`, `admin.set.field_err`
- `admin.msg.done`, `admin.msg.reason_needed`
- `admin.row.more`, `admin.bulk.select_all`, `admin.bulk.selected`, `admin.bulk.clear`, `admin.bulk.result`, `admin.bulk.result_failed`
- `admin.err.reauth_required`, `admin.err.self`, `admin.err.protected`, `admin.err.no_change`, `admin.err.not_found`, `admin.err.forbidden`, `admin.err.bad_reason`, `admin.err.bad_duration`, `admin.err.bad_role`, `admin.err.rate_limited`, `admin.err.csrf`, `admin.err.cross_site`, `admin.err.not_signed_in`, `admin.err.wrong_status`, `admin.err.suspended`, `admin.err.network`, `admin.err.generic`, `admin.err.exists`, `admin.err.no_handle`, `admin.err.too_many`, `admin.err.duplicate`, `admin.err.bad_user_id`, `admin.err.bad_handle`, `admin.err.bad_note`, `admin.err.bad_setting`, `admin.err.bad_import`, `admin.err.too_large`, `admin.err.stale_version`, `admin.err.too_long`, `admin.err.bad_body`, `admin.err.bad_title`, `admin.err.bad_post_url`, `admin.err.bad_form`, `admin.err.link_too_long`, `admin.err.x_lookup_off`, `admin.err.x_not_found`, `admin.err.bad_login`, `admin.err.no_owner`, `admin.err.x_not_listed`, `admin.err.owner_exists`, `admin.err.github_not_found`, `admin.err.x_unavailable`, `admin.err.x_rate_limited`, `admin.err.x_auth`, `admin.err.x_upstream`, `admin.err.settings_off`, `admin.err.no_master_key`, `admin.err.unknown_setting`, `admin.err.secret_setting`, `admin.err.not_secret`, `admin.err.bad_secret`, `admin.err.invalid_config`, `admin.err.sign_in_off`, `admin.err.not_applied`
- `admin.corr.h2`, `admin.corr.lede`, `admin.corr.filter_label`, `admin.corr.pending`, `admin.corr.decided`, `admin.corr.evidence`, `admin.corr.decided_by`, `admin.corr.public_note`, `admin.corr.internal_note`, `admin.corr.accept_label`, `admin.corr.accept_note`, `admin.corr.accept`, `admin.corr.reject_label`, `admin.corr.reject`, `admin.corr.empty_pending`, `admin.corr.empty_decided`, `admin.corr.note_needed`

### Shortened on purpose, to revisit at language review

These keys are complete in every catalog (not pending), but on 2026-11-13
five catalogs were only shortened, not rewritten, because a statement in them
had become untrue and translation is on hold:

- `about.p3` — `en` and `zh-Hans` now say cookies are set only when the
  visitor signs in. `zh-Hant`, `ja`, `ko`, `es` and `fr` simply lost the "no
  cookies" clause and say nothing about cookies; add the sign-in statement
  when the language is reviewed (see the key's intent).
- `hot.side.collectors_note`, `src.read.exact`, `about.p3` — the words naming
  UTC were removed in all seven catalogs when page times started following
  the reader's time zone.
