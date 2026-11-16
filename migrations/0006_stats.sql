-- 0006_stats: operations statistics rolled up from the web access logs by
-- `nday stats-rollup` (Go only; see docs/stats.md). Additive: new tables only.
-- Every row is derived from the log files and can be recomputed from them,
-- except stats_salt (and days whose log files were deleted afterwards).

-- One-row table: the per-installation secret mixed into visitor hashes,
-- generated (32 random bytes) by the first rollup. Never exported.
CREATE TABLE stats_salt (
    id         boolean PRIMARY KEY DEFAULT true CHECK (id),
    salt       bytea NOT NULL CHECK (octet_length(salt) = 32),
    created_at timestamptz NOT NULL DEFAULT now()
);

-- One row per access-YYYY-MM-DD.log file, as of its last successful rollup.
-- size/mtime decide whether the file changed since; other_days lists the
-- dates of lines in this file whose own "time" is another day (normally
-- empty), so recomputing such a day reads this file too.
CREATE TABLE stats_files (
    file       text PRIMARY KEY,            -- base name, e.g. access-2026-11-13.log
    day        date NOT NULL,               -- the date in the file name
    size       bigint NOT NULL,
    mtime      timestamptz NOT NULL,
    lines      bigint NOT NULL,
    bad_lines  bigint NOT NULL,
    other_days date[] NOT NULL DEFAULT '{}',
    rolled_at  timestamptz NOT NULL DEFAULT now()
);

-- Generic daily counters: metric + dim -> value (vocabulary in docs/stats.md).
-- Kept forever.
CREATE TABLE stats_daily (
    day    date NOT NULL,
    metric text NOT NULL,
    dim    text NOT NULL,
    value  bigint NOT NULL,
    PRIMARY KEY (day, metric, dim)
);
CREATE INDEX stats_daily_metric_idx ON stats_daily (metric, dim, day);

-- Daily top lists: at most 100 keys per (day, kind). Kept forever.
CREATE TABLE stats_top (
    day   date NOT NULL,
    kind  text NOT NULL,
    key   text NOT NULL,
    value bigint NOT NULL,
    PRIMARY KEY (day, kind, key)
);
CREATE INDEX stats_top_kind_idx ON stats_top (kind, day);

-- Daily pseudonymous page visitors: first 8 bytes of
-- SHA-256(salt ‖ day ‖ client_ip ‖ user_agent); unrelated across days.
-- Deleted by the rollup once older than 90 days (the unique counts stay in
-- stats_daily).
CREATE TABLE stats_visitors (
    day     date NOT NULL,
    visitor bytea NOT NULL CHECK (octet_length(visitor) = 8),
    human   boolean NOT NULL,
    PRIMARY KEY (day, visitor)
);
