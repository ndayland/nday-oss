-- 0035_job_run: the last run of each background job that is not a
-- collector (internal/jobrun, docs/admin.md "Jobs"). Collectors keep
-- theirs in collector_state; these jobs had nothing run-level before, only
-- per-row state (github_repo.state, web_page.status, site_icon.next_try_at)
-- and log lines. One row per job, overwritten on every run:
--   github-discover  nday github-discover (nday-github-discover.timer)
--   github-poc       the PoC repair at the end of nday github-discover
--   github-fetch     nday github-fetch, and the GitHub step after
--                    nday collect xposts
--   pages-fetch      nday pages-fetch, and the web page step after
--                    nday collect xposts
--   site-icons       nday site-icons (nday-site-icons.timer)
-- started_at is set when a run starts (finished_at, ok and error cleared);
-- finished_at, ok and error when it ends. last_success_at is only ever moved
-- by a run that ended ok. error is sanitised and capped by the writer
-- (no URL query strings or credentials). detail is the run's counters
-- (numbers and booleans only).
--
-- Additive: a new table nothing else reads or writes, so an older binary
-- runs unchanged with it in place.

SET LOCAL lock_timeout = '5s';

CREATE TABLE job_run (
    name            text PRIMARY KEY CHECK (name ~ '^[a-z][a-z0-9-]{0,31}$'),
    started_at      timestamptz NOT NULL,
    finished_at     timestamptz,
    ok              boolean,
    error           text CHECK (char_length(error) <= 500),
    last_success_at timestamptz,
    detail          jsonb,
    CHECK ((finished_at IS NULL) = (ok IS NULL)),
    CHECK (error IS NULL OR ok = false)
);
