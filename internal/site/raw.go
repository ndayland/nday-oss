package site

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// RawRecord is the latest stored upstream payload of (Source, Key).
type RawRecord struct {
	Source      string
	Key         string
	FetchedAt   time.Time
	ContentHash string // sha256 of the canonical JSON (stable ETag)
	Payload     []byte // JSON text, as stored (jsonb rendering)
}

// Keys are CVE ids, GHSA ids, EDB ids, Metasploit module names
// ("exploit/linux/http/x") and Nuclei template ids.
var rawKeyRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,299}$`)

// ValidateRawKey checks source and key before any query. A non-public
// source (public.go) is rejected exactly like an unknown one.
func ValidateRawKey(source, key string) error {
	if !IsPublicSource(source) {
		return &InputError{Param: "source", Msg: "unknown source"}
	}
	if !rawKeyRe.MatchString(key) || strings.Contains(key, "..") || strings.Contains(key, "//") || strings.HasSuffix(key, "/") {
		return &InputError{Param: "key", Msg: "invalid record key"}
	}
	return nil
}

// Raw returns the latest raw record for (source, key); found=false if none.
func (s *Store) Raw(ctx context.Context, source, key string) (*RawRecord, bool, error) {
	if err := ValidateRawKey(source, key); err != nil {
		return nil, false, err
	}
	r := &RawRecord{Source: source, Key: key}
	var payload string
	err := s.db.WithConn(ctx, func(conn *pgx.Conn) error {
		return conn.QueryRow(ctx, `SELECT fetched_at, content_hash, payload::text FROM raw_record
            WHERE source = $1 AND source_key = $2
            ORDER BY fetched_at DESC, id DESC LIMIT 1`, source, key).Scan(&r.FetchedAt, &r.ContentHash, &payload)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	r.FetchedAt = r.FetchedAt.UTC()
	r.Payload = []byte(payload)
	return r, true, nil
}
