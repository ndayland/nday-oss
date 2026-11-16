# nday

**nday tracks what happens to a vulnerability after it's disclosed.** When did the patch ship? Is there a public PoC yet? Is it on CISA's exploited list? Every answer is a dated event from a public source, and the vulnerability's current stage is worked out from those events.

This is the code behind [nday.land](https://www.nday.land): the collectors, the pipeline, the website and the JSON API.

[Website](https://www.nday.land) · [API](https://api.nday.land/v1) · [Docs](docs/) · [Deploy guide](deploy/README.md)

## Why

A CVE feed tells you a vulnerability exists. That's rarely the question. The question is usually "how far along is this one?", because a bug with a patch and no exploit is a different job from one that already has a working PoC.

That information is public, but it's spread across a dozen places that each know one piece. nday pulls the pieces into one timeline per vulnerability and keeps it up to date.

## The timeline

A vulnerability moves through up to six stages. Each one is an event with a source you can click through to:

| Stage | Event | Where it comes from |
|---|---|---|
| Disclosed | `disclosed` | CVE List |
| Patch released | `patch_released` | GitHub Security Advisories |
| Analysis published | `analysis_published` | no source wired up yet |
| Public PoC | `poc_published` | Exploit-DB, Metasploit, Nuclei templates |
| Exploited in the wild | `exploited_in_wild` | no source wired up yet |
| Added to CISA KEV | `kev_added` | CISA KEV |

On top of that, NVD supplies the classification (CWE, CVSS, affected products), and posts from an allow-list of security researchers on X are attached as discussion. Those aren't stages; they don't move a vulnerability along.

Two rules keep the timeline honest:

- **Nothing is maintained by hand.** The current stage is derived from the events. Fix the events and the stage follows.
- **Every event has two timestamps.** `occurred_at` is when the source says it happened; it can be empty, and we never make one up. `observed_at` is when our collector first saw it. Events from a collector's first bulk import are marked `is_backfill`, because their `observed_at` says nothing about when they became visible.

## What's here

- **Collectors** for eight sources: `cvelist`, `nvd`, `ghsa`, `kev`, `exploitdb`, `metasploit`, `nuclei`, `xposts`. Each one fetches, stores the raw record first, then normalizes it. Runs are idempotent, so you can re-run one without duplicating anything.
- **The website**, in seven languages (English, 简体中文, 繁體中文, 日本語, 한국어, Español, Français): what moved to a new stage recently, what researchers are discussing, a filterable catalogue of every CVE, and a page per vulnerability with its timeline, patches, PoCs and tags.
- **Accounts and community**: sign-in with Google, GitHub, Apple or X, or with a passkey; discussions under each vulnerability; a form for readers to report a wrong or missing fact; following vendors and products.
- **A read-only JSON API** with no key and no sign-up.
- **A back office** for moderation, corrections, settings and usage stats.

It's one static Go binary and a PostgreSQL database. No queue, no cache server, no JavaScript build step.

## Try the API

```sh
curl -s https://api.nday.land/v1/vuln/CVE-2021-44228
```

```jsonc
{
  "cve_id": "CVE-2021-44228",
  "title": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints",
  "events": [
    {
      "type": "disclosed",
      "source": "cvelist",
      "url": "https://www.cve.org/CVERecord?id=CVE-2021-44228",
      "occurred_at": "2021-12-10T00:00:00Z",
      "observed_at": "2026-11-12T15:01:53.938848Z",
      "is_backfill": true
      // ...
    }
    // ... the rest of the timeline
  ]
  // ... stage, products, patches, poc, kev, cvss, cwes, tags, raw_records
}
```

| Endpoint | What you get |
|---|---|
| `/v1/hot` | Vulnerabilities that recently moved into a new stage |
| `/v1/discussed` | CVEs that researchers posted about in the last 7 days |
| `/v1/vulns` | The whole catalogue, with filters and paging |
| `/v1/vuln/{cve}` | One vulnerability: timeline, patches, PoCs, classification |
| `/v1/search` | Search (`?q=`) |
| `/v1/tags`, `/v1/affected/suggest` | The tag vocabulary with counts, and vendor/product lookup |
| `/v1/sources`, `/v1/stats` | Collector status, and counts by stage |
| `/v1/raw/{source}/{key}.json` | The raw record an event was built from |

Parameters, response shapes and caching are in [docs/api.md](docs/api.md).

## Run it locally

You need Go (the version in `go.mod`) and Docker.

```sh
docker compose up -d                 # PostgreSQL 16 on host port 54329
cp .env.example .env
go run ./cmd/nday migrate
go run ./cmd/nday collect kev        # a small source, good for a first run
go run ./cmd/nday status
go run ./cmd/nday serve --listen 127.0.0.1:8080
```

Then open http://127.0.0.1:8080. The other sources are collected the same way (`collect cvelist`, `collect ghsa`, and so on); `.env.example` lists the optional settings and tokens. Run `go run ./cmd/nday -h` for every subcommand.

```sh
go test ./...        # each test gets its own schema in the nday_test database; nothing touches the network
```

A production build is `CGO_ENABLED=0 go build -o nday ./cmd/nday`. [deploy/README.md](deploy/README.md) walks through running it on a server: systemd units, timers for the collectors, TLS behind Cloudflare, backups.

## Layout

| Path | What's in it |
|---|---|
| `cmd/nday/` | The entry point. It only calls `internal/cli`. |
| `internal/cli/` | The command line: `migrate`, `collect`, `serve` and the admin commands. |
| `internal/collector/` | The collector contract (read the package doc before writing one) and a package per source. `internal/registry/` lists them. |
| `internal/pipeline/` | Fetch, store raw, normalize, write idempotently, record collection state. |
| `internal/site/`, `internal/web/`, `internal/webui/` | The query layer, the JSON API and the HTML site. |
| `internal/auth/`, `internal/discuss/`, `internal/corrections/`, `internal/admin/` | Accounts, discussions, reader corrections, the back office. |
| `internal/tags/`, `internal/classify/` | Tagging rules and the NVD classification layer. |
| `migrations/` | SQL migrations, run in order and embedded in the binary. |
| `docs/` | A reference doc per area. |
| `deploy/` | Server setup: systemd units, firewall and backup scripts. |
| `src/nday/`, `tests/` | The Python reference implementation (see below). |

## Docs

| Doc | Covers |
|---|---|
| [docs/go.md](docs/go.md) | How the Go implementation is put together. Start here. |
| [docs/api.md](docs/api.md) | The JSON API |
| [docs/nvd.md](docs/nvd.md), [docs/tags.md](docs/tags.md) | NVD data, classification and CVE tags |
| [docs/xposts.md](docs/xposts.md), [docs/webpages.md](docs/webpages.md) | Researcher posts from X and the pages they link to |
| [docs/auth.md](docs/auth.md), [docs/follows.md](docs/follows.md) | Accounts, sign-in, following vendors and products |
| [docs/discuss.md](docs/discuss.md), [docs/corrections.md](docs/corrections.md) | Discussions and reader corrections |
| [docs/admin.md](docs/admin.md), [docs/settings.md](docs/settings.md), [docs/stats.md](docs/stats.md), [docs/logging.md](docs/logging.md) | Back office, settings, usage stats, log files |
| [docs/i18n/](docs/i18n/README.md) | Writing or improving a translation |

## The Python reference

`src/nday/` is the original Python implementation. It isn't what runs in production, but it's kept as the behavioural reference: the Go collectors are checked against goldens generated from it (`tools/dump_golden.py`, see [docs/go.md](docs/go.md)). It has its own test suite:

```sh
python3.13 -m venv .venv && .venv/bin/pip install -e '.[dev]' && .venv/bin/pytest
```

## Contributing

Bug reports, ideas and patches are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) first: this repository is a published snapshot, so pull requests are applied by hand rather than merged with the button.

Found a security problem? Please don't open an issue. [SECURITY.md](SECURITY.md) says where to send it.

## License

nday is free software under the GNU Affero General Public License v3.0 (AGPL-3.0-only); see [LICENSE](LICENSE). If you run a modified version as a network service, you have to offer its source to the people using it.

The nday name and the logos under `assets/brand/` aren't covered by that license. Please don't use them for your own deployment.
