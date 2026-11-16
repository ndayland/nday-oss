-- 0001_init: core schema for nday.
-- Applied inside a single transaction by nday.db.migrate().

-- Raw source data, kept verbatim so normalization can be re-run.
-- One row per distinct content version of a source record.
CREATE TABLE raw_record (
    id           bigserial PRIMARY KEY,
    source       text        NOT NULL,
    source_key   text        NOT NULL,
    -- When this content version was fetched (bumped if upstream reverts to it).
    fetched_at   timestamptz NOT NULL DEFAULT now(),
    content_hash text        NOT NULL,
    payload      jsonb       NOT NULL,
    CONSTRAINT raw_record_uniq UNIQUE (source, source_key, content_hash)
);
-- "Latest version per key" lookups.
CREATE INDEX raw_record_latest_idx ON raw_record (source, source_key, fetched_at DESC, id DESC);

CREATE TABLE vuln (
    cve_id        text PRIMARY KEY
                  CONSTRAINT vuln_cve_id_format CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
    title         text,
    description   text,
    -- Chinese fields are filled later by a separate component.
    title_zh      text,
    summary_zh    text,
    published_at  timestamptz,
    modified_at   timestamptz,
    -- When any nday collector first saw this CVE.
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE vuln_alias (
    id         bigserial PRIMARY KEY,
    cve_id     text NOT NULL REFERENCES vuln (cve_id) ON DELETE CASCADE,
    alias      text NOT NULL,
    alias_type text NOT NULL,   -- ghsa, cnvd, vendor, ...
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT vuln_alias_uniq UNIQUE (alias_type, alias)
);
CREATE INDEX vuln_alias_cve_idx ON vuln_alias (cve_id);

CREATE TABLE affected (
    id         bigserial PRIMARY KEY,
    cve_id     text NOT NULL REFERENCES vuln (cve_id) ON DELETE CASCADE,
    vendor     text NOT NULL,
    product    text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT affected_uniq UNIQUE (cve_id, vendor, product)
);
CREATE INDEX affected_vendor_product_idx ON affected (vendor, product);

-- Lifecycle timeline. A vuln's current stage is derived from these rows.
CREATE TABLE event (
    id          bigserial PRIMARY KEY,
    cve_id      text NOT NULL REFERENCES vuln (cve_id) ON DELETE CASCADE,
    type        text NOT NULL CONSTRAINT event_type_check CHECK (type IN (
                    'disclosed', 'patch_released', 'analysis_published',
                    'poc_published', 'exploited_in_wild', 'kev_added')),
    -- Time claimed by the source; NULL when unknown. Never fabricated.
    occurred_at timestamptz,
    -- When our collector first saw this event.
    observed_at timestamptz NOT NULL,
    source      text NOT NULL,
    url         text,
    detail      jsonb NOT NULL DEFAULT '{}'::jsonb,
    -- true = imported in a collector's first/bulk run; observed_at is then
    -- NOT the time the event actually became visible.
    is_backfill boolean NOT NULL DEFAULT false,
    -- NOT NULL (default '') so the unique constraint below actually dedupes;
    -- NULLs would be treated as distinct.
    dedupe_key  text NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT event_uniq UNIQUE (cve_id, type, source, dedupe_key)
);
CREATE INDEX event_cve_idx ON event (cve_id, occurred_at);
CREATE INDEX event_type_occurred_idx ON event (type, occurred_at DESC);
CREATE INDEX event_observed_idx ON event (observed_at DESC);

CREATE TABLE collector_state (
    source          text PRIMARY KEY,
    cursor          jsonb,
    last_run_at     timestamptz,
    last_status     text,
    last_error      text,
    -- NULL until the first successful run; drives is_backfill.
    last_success_at timestamptz
);
