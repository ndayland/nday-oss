package cvelist_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/collector"
	"nday.land/nday/internal/model"
	"nday.land/nday/internal/pyjson"
	"nday.land/nday/internal/testutil"
)

// TestNormalizeAllMatchesPython compares Go and Python normalize output
// (sha256 of the canonical golden rendering) for the latest raw record of
// every cvelist key in a database snapshot. It catches differences that
// `nday renormalize --dry-run` cannot see (e.g. values already present).
//
//	CVELIST_NORM_PARITY="<db url>=<out of testdata/normalize_all_py.py>" go test -run NormalizeAll ./internal/collector/cvelist/
func TestNormalizeAllMatchesPython(t *testing.T) {
	spec := os.Getenv("CVELIST_NORM_PARITY")
	if spec == "" {
		t.Skip("CVELIST_NORM_PARITY not set")
	}
	url, pyOut, _ := strings.Cut(spec, "=")
	b, err := os.ReadFile(pyOut)
	if err != nil {
		t.Fatal(err)
	}
	pv, err := pyjson.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	py := pv.(*pyjson.Object)
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	rows, err := tx.Query(ctx, `SELECT DISTINCT ON (source_key) source_key, payload::text FROM raw_record
           WHERE source = 'cvelist' ORDER BY source_key, fetched_at DESC, id DESC`)
	if err != nil {
		t.Fatal(err)
	}
	c := plain(t)
	total, diff := 0, 0
	for rows.Next() {
		var key, payload string
		if err := rows.Scan(&key, &payload); err != nil {
			t.Fatal(err)
		}
		total++
		v, err := pyjson.DecodeString(payload)
		if err != nil {
			t.Fatal(err)
		}
		var got string
		n, nerr := c.Normalize(model.RawRecord{Source: "cvelist", SourceKey: key, Payload: v})
		var ne *collector.NormalizeError
		switch {
		case errors.As(nerr, &ne):
			got = "NormalizeError: " + ne.Msg
		case nerr != nil:
			got = "fatal"
		default:
			sum := sha256.Sum256([]byte(canon(t, testutil.NormalizedValue(n))))
			got = hex.EncodeToString(sum[:])
		}
		want, _ := py.Get(key).(string)
		if strings.HasPrefix(want, "fatal") && got == "fatal" {
			continue
		}
		if got != want {
			diff++
			if diff <= 20 {
				t.Errorf("%s: go %s, python %s", key, got, want)
			}
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	t.Logf("compared %d keys (python file has %d): %d differ", total, py.Len(), diff)
	if total != py.Len() {
		t.Errorf("key count %d vs %d", total, py.Len())
	}
}
