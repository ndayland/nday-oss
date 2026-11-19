-- 0025_github_discovery: GitHub PoC monitoring, phase 2 (Go only;
-- internal/ghrepo, docs/github.md): repositories found through the GitHub
-- search API, their review status, and the search bookkeeping.
--
-- Additive: new columns of github_repo and x_post_link, three new tables,
-- two triggers, and a wider id format on github_repo_cve (0023). Independent
-- of 0024; after 0026 only in that it uses the same two id forms.
--
-- Identity. A github_repo row whose github_id is set IS that GitHub
-- repository for good: github_id never changes and the row is never
-- deleted (triggers github_repo_keep_id, github_repo_keep_row) or merged. A row
-- with github_id NULL is only a placeholder for a queued name: it holds no
-- review status (CHECK github_repo_status_identity) and is listed nowhere.
--
-- github_repo.status: who vouches for a repository identity.
--   'unverified' nobody (the default; every repository found by search
--                starts here); shown publicly with a mark, never changes a
--                lifecycle stage;
--   'trusted'    by rule ('rule': a researcher's post links its ROOT and
--                the link is stamped with this identity, see below) or by
--                an admin;
--   'rejected'   by an admin, or by rule for an identity that appears under
--                a name key an admin's rejection is recorded for
--                (github_rejected_name); never shown as a PoC.
-- status_by: 'rule' or 'admin'; NULL while nobody decided. An admin
-- decision is never changed by any automatic path.
-- status_at: when status_by was last written.
-- seen_at: the last time search or a fetch returned the repository (a
-- search find not seen for 14 days is no longer listed).
--
-- github_repo_name (0023) now maps a name key to at most one row: the
-- identity that most recently answered for that key from the API (its
-- current lower-cased full_name), or a placeholder. An identity holds no
-- other key: no alias history is kept.
--
-- x_post_link, vouching on the link:
--   repo_swept_url  the sweep marker of this release: the final_url the
--                   enqueue sweep last handled. A new column on purpose:
--                   repo_queued_url (0023) is still written by the phase-1
--                   binary, which may run between this migration and the
--                   binary swap and knows nothing of root keys; the new
--                   sweep ignores it, so every link is swept once by the
--                   new code whatever the old one did;
--   repo_root_key   the name key of the link when it points at a repository
--                   ROOT (ghrepo.RootKeyOf, computed in Go by the enqueue
--                   sweep), NULL for deep links and other URLs;
--   repo_checked_at when a request for that key BY NAME, made after the
--                   link was stored, got a definite answer;
--   repo_github_id  the stamp: the identity that answered, set only when it
--                   was a public repository created no later than the link
--                   row's created_at; never written from stored data;
--   repo_check_attempts transient failures of that check so far.
-- A changed final_url with the same root key keeps them; another root key
-- resets them. Rule trust is derived from stamps only.
--
-- github_rejected_name: name keys recorded for an identity an admin
-- rejected (repo_id: which identity recorded the key, so lifting one
-- rejection does not undo another's).
--
-- Ids (github_repo_cve.cve_id, github_search_cve.cve_id): a CVE id or a
-- GHSA id, the two forms vuln.cve_id accepts since 0026 ("GHSA-" then
-- three lower-case groups). An id is stored as found in the repository's
-- name, description or topics; which vulnerability a GHSA id belongs to is
-- resolved when read (vuln_alias), so nothing here moves when a
-- GHSA-keyed vulnerability gets its CVE.
--
-- github_search_cve: the targeted search per id: searched_at / total_count
-- of the last parsed page; failures / failed_at count failed requests
-- since (backoff), reset by a success.
--
-- github_search_scan: the cursor of the new-repository scan, one row per
-- scan key ('name:CVE-2026', or 'name:GHSA'): created_after (everything created before it
-- was read), window_end (the end of the window being read: halved
-- windows persist across runs), next_page (the page to read next in that
-- window, 1 = start), and what the pages of that window read so far
-- reported: window_total (the largest total_count) and window_incomplete
-- (some page came back with incomplete_results); window_retries counts the
-- consecutive runs that ended a one-minute window incomplete.
--
-- Backfill: nothing is computed in SQL. Names an identity no longer
-- answers for (aliases of phase 1, and the names of 'gone' identities) are
-- dropped. Every github.com code link has repo_swept_url NULL, so the Go
-- sweep (nday github-enqueue) derives its root key; phase-1 repositories
-- become trusted by rule only when the fetch pass (nday github-fetch) has
-- checked their links. Until then their links render plain.
--
-- A phase-1 binary running after this migration: its sweep only queues
-- names and writes repo_queued_url (harmless). Its fetch pass asks by
-- name; where that would give a row another GitHub id, or delete a row
-- that has one (its rename merge), the triggers refuse and that pass ends
-- with an error, nothing changed. Names it adds as aliases are dropped
-- again by the next answer the new code stores for that repository.

ALTER TABLE github_repo
    ADD COLUMN status    text NOT NULL DEFAULT 'unverified' CHECK (status IN ('unverified', 'trusted', 'rejected')),
    ADD COLUMN status_by text CHECK (status_by IS NULL OR status_by IN ('rule', 'admin')),
    ADD COLUMN status_at timestamptz,
    ADD COLUMN seen_at   timestamptz,
    ADD CONSTRAINT github_repo_status_at_check CHECK ((status_by IS NULL) = (status_at IS NULL)),
    ADD CONSTRAINT github_repo_status_decided CHECK (status = 'unverified' OR status_by IS NOT NULL),
    ADD CONSTRAINT github_repo_status_rule CHECK (status_by IS DISTINCT FROM 'rule' OR github_id IS NOT NULL),
    ADD CONSTRAINT github_repo_status_identity CHECK (github_id IS NOT NULL OR (status = 'unverified' AND status_by IS NULL));

CREATE FUNCTION github_repo_keep_id() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.github_id IS NOT NULL AND NEW.github_id IS DISTINCT FROM OLD.github_id THEN
        RAISE EXCEPTION 'github_repo %: github_id is immutable', OLD.id USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER github_repo_keep_id BEFORE UPDATE OF github_id ON github_repo
    FOR EACH ROW EXECUTE FUNCTION github_repo_keep_id();

CREATE FUNCTION github_repo_keep_row() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.github_id IS NOT NULL THEN
        RAISE EXCEPTION 'github_repo %: a row with a github_id is never deleted', OLD.id USING ERRCODE = 'check_violation';
    END IF;
    RETURN OLD;
END $$;
CREATE TRIGGER github_repo_keep_row BEFORE DELETE ON github_repo
    FOR EACH ROW EXECUTE FUNCTION github_repo_keep_row();

ALTER TABLE github_repo_cve DROP CONSTRAINT github_repo_cve_cve_id_check;
ALTER TABLE github_repo_cve ADD CONSTRAINT github_repo_cve_cve_id_check CHECK (
    cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'
    OR cve_id ~ '^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$');

UPDATE github_repo SET seen_at = fetched_at WHERE state = 'ok';

DELETE FROM github_repo_name n USING github_repo r
WHERE r.id = n.repo_id AND r.github_id IS NOT NULL
  AND (r.state = 'gone' OR r.full_name IS NULL OR n.name_key <> lower(r.full_name));

CREATE INDEX github_repo_status_idx ON github_repo (status, created_at);

ALTER TABLE x_post_link
    ADD COLUMN repo_swept_url      text,
    ADD COLUMN repo_root_key       text CHECK (repo_root_key IS NULL OR (char_length(repo_root_key) BETWEEN 3 AND 140 AND repo_root_key = lower(repo_root_key))),
    ADD COLUMN repo_github_id      bigint REFERENCES github_repo (github_id),
    ADD COLUMN repo_checked_at     timestamptz,
    ADD COLUMN repo_check_attempts integer NOT NULL DEFAULT 0 CHECK (repo_check_attempts >= 0),
    ADD CONSTRAINT x_post_link_repo_stamp CHECK (repo_github_id IS NULL OR (repo_root_key IS NOT NULL AND repo_checked_at IS NOT NULL));
CREATE INDEX x_post_link_repo_root_idx ON x_post_link (repo_root_key) WHERE repo_root_key IS NOT NULL;
CREATE INDEX x_post_link_repo_unchecked_idx ON x_post_link (created_at) WHERE repo_root_key IS NOT NULL AND repo_checked_at IS NULL;
CREATE INDEX x_post_link_repo_stamp_idx ON x_post_link (repo_github_id) WHERE repo_github_id IS NOT NULL;

CREATE TABLE github_rejected_name (
    name_key    text NOT NULL CHECK (char_length(name_key) BETWEEN 3 AND 140 AND name_key = lower(name_key)),
    repo_id     bigint NOT NULL REFERENCES github_repo (id) ON DELETE CASCADE,
    rejected_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (name_key, repo_id)
);
CREATE INDEX github_rejected_name_repo_idx ON github_rejected_name (repo_id);

CREATE TABLE github_search_cve (
    cve_id      text PRIMARY KEY CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'
                                        OR cve_id ~ '^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$'),
    searched_at timestamptz,
    total_count integer CHECK (total_count IS NULL OR total_count >= 0),
    failures    integer NOT NULL DEFAULT 0 CHECK (failures >= 0),
    failed_at   timestamptz
);
CREATE INDEX github_search_cve_searched_idx ON github_search_cve (searched_at);

CREATE TABLE github_search_scan (
    scan_key          text PRIMARY KEY CHECK (scan_key ~ '^name:(CVE-[0-9]{4}|GHSA)$'),
    created_after     timestamptz NOT NULL,
    window_end        timestamptz,
    next_page         integer NOT NULL DEFAULT 1 CHECK (next_page BETWEEN 1 AND 10),
    window_total      integer CHECK (window_total IS NULL OR window_total >= 0),
    window_incomplete boolean NOT NULL DEFAULT false,
    window_retries    integer NOT NULL DEFAULT 0 CHECK (window_retries >= 0),
    updated_at        timestamptz NOT NULL DEFAULT now()
);
