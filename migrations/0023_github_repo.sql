-- 0023_github_repo: GitHub repositories linked from allowlisted researchers'
-- X posts, their metadata from the GitHub REST API, and the CVEs they are
-- associated with (Go only; internal/ghrepo, docs/github.md).
--
-- Additive: three new tables and one new column of x_post_link.
--
-- 1. github_repo: one row per repository. Our own id is the primary key;
--    github_id (GitHub's numeric repository id) is UNIQUE once known. A
--    repository is first queued by its lower-cased "owner/name"
--    (queued_name) with github_id NULL and state 'pending', so a row that
--    was never fetched is representable. When a fetch returns an id that
--    another row already has (the same repository queued under an old and a
--    new name), the newer row is merged into the older one and deleted
--    (internal/ghrepo storeOK), so a rename never leaves two rows.
--      'pending' not fetched yet, or a transient failure with attempts left;
--      'ok'      metadata stored; refreshed at most once every 7 days;
--      'gone'    404 / 410 / 451 or not a public repository (final; any
--                metadata from an earlier fetch is kept but never shown);
--      'failed'  3 transient failures; tried again once a day (fetched_at
--                older than 24 h) up to 6 attempts in all.
--    Every text column is third-party text from the API, cleaned
--    (pagefetch.CleanText) and cut, but untrusted: escape when displayed.
--    Only full_name, stars and repo_created_at of an 'ok' row are public.
--
-- 2. github_repo_name: every lower-cased "owner/name" a row is known by
--    (the name it was queued under, and the full_name GitHub returned).
--    Links are matched to a repository through this table, so a link to an
--    old name still finds the renamed repository.
--
-- 3. github_repo_cve: repository <-> CVE, with the basis of the
--    association: 'name', 'description', 'topic' (a CVE id in that field of
--    the API response; recomputed on every fetch) or 'post' (the repository
--    was linked from a researcher post about the CVE; written by the
--    enqueue sweep, never removed by a fetch). No foreign key to vuln: a
--    CVE id may be known only from a post.
--
-- x_post_link.repo_queued_url: the enqueue sweep's marker (as
-- page_queued_url, migration 0020): the final_url last handed to the
-- repository queue (queued, already known, or not a repository URL). A link
-- is swept again only when its final_url differs from this.

CREATE TABLE github_repo (
    id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    github_id       bigint UNIQUE CHECK (github_id IS NULL OR github_id > 0),
    queued_name     text NOT NULL CHECK (char_length(queued_name) BETWEEN 3 AND 140 AND queued_name = lower(queued_name)),
    -- as GitHub returns it ("Owner/Repo")
    full_name       text CHECK (full_name IS NULL OR char_length(full_name) BETWEEN 3 AND 140),
    owner_login     text CHECK (owner_login IS NULL OR char_length(owner_login) BETWEEN 1 AND 39),
    owner_type      text CHECK (owner_type IS NULL OR owner_type IN ('User', 'Organization', 'Bot')),
    description     text CHECK (description IS NULL OR char_length(description) BETWEEN 1 AND 500),
    stars           integer CHECK (stars IS NULL OR stars >= 0),
    forks           integer CHECK (forks IS NULL OR forks >= 0),
    language        text CHECK (language IS NULL OR char_length(language) BETWEEN 1 AND 64),
    topics          text[] NOT NULL DEFAULT '{}' CHECK (cardinality(topics) <= 20),
    is_fork         boolean,
    is_archived     boolean,
    -- GitHub's created_at / pushed_at of the repository
    repo_created_at timestamptz,
    pushed_at       timestamptz,
    state           text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'ok', 'gone', 'failed')),
    -- requests made since the last success
    attempts        integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    -- the ETag of the last 200 (for If-None-Match on refreshes)
    etag            text CHECK (etag IS NULL OR char_length(etag) BETWEEN 1 AND 200),
    -- time of the last request (attempt)
    fetched_at      timestamptz,
    -- who enqueued it first (e.g. 'xposts')
    first_source    text NOT NULL CHECK (first_source ~ '^[a-z][a-z0-9_]{0,31}$'),
    created_at      timestamptz NOT NULL DEFAULT now(),
    CHECK (state <> 'ok' OR (github_id IS NOT NULL AND full_name IS NOT NULL))
);
CREATE INDEX github_repo_state_idx ON github_repo (state, created_at);
CREATE INDEX github_repo_refresh_idx ON github_repo (state, fetched_at);

CREATE TABLE github_repo_name (
    name_key text PRIMARY KEY CHECK (char_length(name_key) BETWEEN 3 AND 140 AND name_key = lower(name_key)),
    repo_id  bigint NOT NULL REFERENCES github_repo (id) ON DELETE CASCADE
);
CREATE INDEX github_repo_name_repo_idx ON github_repo_name (repo_id);

CREATE TABLE github_repo_cve (
    repo_id    bigint NOT NULL REFERENCES github_repo (id) ON DELETE CASCADE,
    cve_id     text NOT NULL CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,19}$'),
    basis      text NOT NULL CHECK (basis IN ('name', 'description', 'topic', 'post')),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (repo_id, cve_id, basis)
);
CREATE INDEX github_repo_cve_cve_idx ON github_repo_cve (cve_id);

ALTER TABLE x_post_link ADD COLUMN repo_queued_url text;
