-- 0028_site_icon: the small icons of the third-party sites the
-- vulnerability page links to (Go only; internal/siteicon,
-- docs/siteicons.md).
--
-- Additive. `nday site-icons` (deploy/systemd/nday-site-icons.timer)
-- fetches the icon of each linked host through internal/pagefetch (https
-- only, public addresses only), validates the bytes (ICO, PNG, GIF, JPEG
-- or WebP, at most 512 pixels a side, at most 64 KiB) and records the
-- outcome; the site serves the bytes from its own origin at
-- /icon/<host>?v=<hash>, so readers never contact the third party.
--   'ok'    an icon is stored (also kept while later attempts fail);
--   'none'  the host has no usable icon (or is an address): tried again
--           after 30 days;
--   'error' transient failures without a stored icon: tried again after
--           1 h, 4 h, 16 h, ... (failures), at most 30 days.
-- The image is third-party content: served only with the stored content
-- type, nosniff and a sandboxing CSP.

CREATE TABLE site_icon (
    -- lower-case ASCII (punycode) host name, no port, no trailing dot
    host         text PRIMARY KEY CHECK (char_length(host) <= 253
                 AND host ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$'),
    status       text NOT NULL CHECK (status IN ('ok', 'none', 'error')),
    content_type text CHECK (content_type IN ('image/x-icon', 'image/png', 'image/gif', 'image/jpeg', 'image/webp')),
    image        bytea CHECK (octet_length(image) BETWEEN 1 AND 65536),
    -- first 16 hex digits of the image's SHA-256 (the ?v= of its URL)
    hash         text CHECK (hash ~ '^[0-9a-f]{16}$'),
    -- where the image came from (after redirects); for operators only
    source_url   text CHECK (char_length(source_url) <= 2048),
    -- time of the last attempt
    fetched_at   timestamptz NOT NULL,
    -- the host is due again from then on
    next_try_at  timestamptz NOT NULL,
    -- consecutive transient failures (0 after any final outcome)
    failures     integer NOT NULL DEFAULT 0 CHECK (failures >= 0),
    -- short reason of the last 'none' or failed attempt; for operators only
    last_error   text CHECK (char_length(last_error) <= 200),
    CHECK ((status = 'ok') = (image IS NOT NULL)),
    CHECK ((image IS NULL) = (content_type IS NULL) AND (image IS NULL) = (hash IS NULL))
);
CREATE INDEX site_icon_next_try_idx ON site_icon (next_try_at);
