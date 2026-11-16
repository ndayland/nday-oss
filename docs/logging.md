# Log files for nday serve

Implementation: `internal/web/logfiles.go` (the files, the access lines, and the slog handler for the error file). It's wired up in `internal/cli/serve.go`.

## Switch

| Variable | Description |
|---|---|
| `NDAY_LOG_DIR` | An absolute path. The directory must already exist (it isn't created for you). If unset, behaviour is exactly as before: access lines (slog INFO `msg=http`) and application logs both go to stderr. |

Once it's set, `nday serve` fails at startup with an explanation if the directory doesn't exist, isn't a directory, or today's file can't be opened.

## Files

| File | Contents |
|---|---|
| `access-YYYY-MM-DD.log` | One JSON line per request (both the site host and the API host are logged). Access lines go **only** here, no longer to stderr. |
| `error-YYYY-MM-DD.log` | Every slog record at WARN or above from the process (site, API, sign-in, connection pool, ... still written to stderr as well); panics recorded by `Recover` (including `stack`); and one `msg="http 5xx"` entry (`method`, `host`, `path`, `status`, `dur_ms`, `cf_ray`) for every response with status ≥ 500. One JSON object per line (slog JSON format). |

- **Split by local date**: the date comes from the process's local timezone (`time.Local`, i.e. `/etc/localtime`; that's the server's local timezone).
  Each line's `time` is RFC 3339 with milliseconds and the local offset (`2026-11-13T15:30:00.123+02:00`), taken from the same instant as the filename,
  so a line is always in the file for the date it shows. When a write (under the lock) finds the date has changed, it opens the new file first and then closes the old one. If the new file can't be opened, it keeps writing to the old one
  and reports the error on stderr (at most once a minute).
- Files are opened with `O_APPEND|O_CREATE|O_WRONLY` and mode 0640; a restart on the same day keeps appending.
- **nday never deletes, compresses, or renames any log file.** Delete old files by hand. There's no signal handling, and you don't need logrotate.

## Access line fields (fixed order, every key always present)

| Key | Type | Meaning |
|---|---|---|
| `time` | string | When the line was written, RFC 3339, milliseconds, local offset |
| `client_ip` | string | The visitor's address: `CF-Connecting-IP` (only if it looks like an IP; same logic as `cf_ip` in the stderr log). If that header is missing (a direct connection that doesn't go through Cloudflare), it's `remote_addr` |
| `remote_addr` | string | The TCP peer's IP (no port); behind Cloudflare this is the edge node's address |
| `domain` | string | The configured site that matched: the canonical host of `NDAY_PUBLIC_URL` or `NDAY_API_URL` (lowercase, default port removed); `""` if neither matches |
| `host` | string | The request's `Host`, lowercased, truncated to 255 |
| `method` | string | Request method |
| `uri` | string | The escaped path, followed by `?` and the query string (passed through `RedactQuery`) if there is one (like nginx `$request_uri` with the secrets removed), truncated to 2000 |
| `status` | number | Response status code |
| `referer` | string | `Referer` as sent, truncated to 500; if its host is one of this site's two hosts, the query string also goes through `RedactQuery` (the fragment is removed) |
| `http_x_forwarded_for` | string | The original `X-Forwarded-For` value; multiple headers are joined with `, `, truncated to 500 |
| `server_port` | number | The local port the connection arrived on, 0 if unavailable |
| `request_length` | number | Request size in bytes (see the limitations below) |
| `request_time` | number | Processing time in seconds, millisecond precision (for example `0.012`) |
| `ssl_protocol` | string | `TLSv1.2`, `TLSv1.3`; `""` for plain HTTP |
| `ssl_cipher` | string | `tls.CipherSuiteName`, for example `TLS_AES_128_GCM_SHA256`; `""` for plain HTTP |
| `bytes_sent` | number | Response body size in bytes |
| `proto` | string | `HTTP/1.1`, `HTTP/2.0` |
| `user_agent` | string | Truncated to 300 |
| `cf_ray` | string | `CF-Ray` |
| `country` | string | `CF-IPCountry` |

## Redaction and safety

- Every value is encoded with `encoding/json`: CR/LF, quotes, and control characters sent by the client are escaped, so they can't be used to forge log lines.
- Cookies, `Authorization`, and request bodies are never logged.
- Under `/auth/`, every query parameter value except `return`, `intent`, and `error` is logged as `REDACTED` (`code`, `state`, `ticket`, ...),
  both in `uri` and in a same-site `referer`.
- Access logs contain visitor IP addresses (`client_ip`, `remote_addr`, `http_x_forwarded_for`), which is personal data.

## Limitations

- `request_length` is a **reconstructed value**: Go doesn't expose the bytes on the wire, so it's computed as "request line + each header as `Name: value\r\n` (including Host) + blank line + the request body bytes actually read (or `Content-Length` if the body wasn't read)".
  For ordinary HTTP/1.1 requests it's exact; for HTTP/2 it's only approximate because of header compression and pseudo-headers.
- `ssl_protocol` / `ssl_cipher` describe the **connection that reached the origin** (Cloudflare → origin), not the visitor's connection to Cloudflare.
