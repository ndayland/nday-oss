// Command hashparity proves that the Go content hash equals Python's
// content_hash(canonical_json(payload)) by recomputing it from
// raw_record.payload::text for every stored row and comparing it with the
// stored raw_record.content_hash. Read-only (one SELECT).
//
//	go run ./tools/hashparity -db postgresql://nday:nday@127.0.0.1:54329/nday_parity [-source kev] [-show 5]
//
// What can be recovered from jsonb: strings, booleans, null, key sets and
// integers exactly; key order is irrelevant (canonical JSON sorts keys).
// Python floats were sent as repr() text and jsonb keeps the decimal value
// with its scale, so a value printed with a '.' (e.g. 100.0, 0.00001) is
// re-parsed as a float and re-rendered with repr (100.0, 1e-05). What jsonb
// LOSES: a Python float whose repr uses a positive exponent (|x| >= 1e16,
// e.g. 1e+16) is stored as the integer 10000000000000000 and comes back as an
// int. Such rows are reported in class "float>=1e16 stored as integer" when
// re-typing those integers as floats reproduces the stored hash.
package main

import (
	"context"
	"flag"
	"fmt"
	"math"
	"math/big"
	"os"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/pyjson"
)

type counts struct {
	rows, match, mismatch, latestRows, latestMismatch int
	classes                                           map[string]int
	examples                                          []string
}

func main() {
	dbURL := flag.String("db", os.Getenv("NDAY_DATABASE_URL"), "database URL")
	source := flag.String("source", "", "only this source")
	show := flag.Int("show", 5, "example mismatches to print per source")
	flag.Parse()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, *dbURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer conn.Close(ctx)

	q := `SELECT r.id, r.source, r.source_key, r.content_hash, r.payload::text,
                 r.id = (SELECT l.id FROM raw_record l
                         WHERE l.source = r.source AND l.source_key = r.source_key
                         ORDER BY l.fetched_at DESC, l.id DESC LIMIT 1) AS is_latest
          FROM raw_record r WHERE ($1 = '' OR r.source = $1) ORDER BY r.source, r.id`
	rows, err := conn.Query(ctx, q, *source)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	per := map[string]*counts{}
	var (
		id                    int64
		src, key, stored, txt string
		latest                bool
	)
	for rows.Next() {
		if err := rows.Scan(&id, &src, &key, &stored, &txt, &latest); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		c := per[src]
		if c == nil {
			c = &counts{classes: map[string]int{}}
			per[src] = c
		}
		c.rows++
		if latest {
			c.latestRows++
		}
		class, ok := check(txt, stored)
		if ok {
			c.match++
			continue
		}
		c.mismatch++
		if latest {
			c.latestMismatch++
		}
		c.classes[class]++
		if len(c.examples) < *show {
			c.examples = append(c.examples, fmt.Sprintf("id=%d key=%s class=%s", id, key, class))
		}
	}
	if err := rows.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	srcs := make([]string, 0, len(per))
	for s := range per {
		srcs = append(srcs, s)
	}
	sort.Strings(srcs)
	tot := counts{}
	fmt.Printf("%-12s %8s %8s %9s %12s %16s\n", "source", "rows", "matched", "mismatch", "latest_rows", "latest_mismatch")
	for _, s := range srcs {
		c := per[s]
		fmt.Printf("%-12s %8d %8d %9d %12d %16d\n", s, c.rows, c.match, c.mismatch, c.latestRows, c.latestMismatch)
		tot.rows += c.rows
		tot.match += c.match
		tot.mismatch += c.mismatch
		tot.latestRows += c.latestRows
		tot.latestMismatch += c.latestMismatch
	}
	fmt.Printf("%-12s %8d %8d %9d %12d %16d\n", "TOTAL", tot.rows, tot.match, tot.mismatch, tot.latestRows, tot.latestMismatch)
	for _, s := range srcs {
		c := per[s]
		if c.mismatch == 0 {
			continue
		}
		fmt.Printf("\n%s mismatch classes:\n", s)
		for k, n := range c.classes {
			fmt.Printf("  %-45s %d\n", k, n)
		}
		for _, e := range c.examples {
			fmt.Printf("  e.g. %s\n", e)
		}
	}
	if tot.mismatch > 0 {
		os.Exit(3)
	}
}

// check recomputes the hash; on mismatch it tries the known lossy jsonb
// transformation to classify the row.
func check(payloadText, stored string) (string, bool) {
	v, err := pyjson.DecodeString(payloadText)
	if err != nil {
		return "decode error: " + err.Error(), false
	}
	h, err := pyjson.ContentHash(v)
	if err != nil {
		return "encode error: " + err.Error(), false
	}
	if h == stored {
		return "", true
	}
	if n := bigIntsToFloat(&v); n > 0 {
		if h2, err := pyjson.ContentHash(v); err == nil && h2 == stored {
			return "float>=1e16 stored as integer", false
		}
	}
	if strings.Contains(payloadText, `\u0000`) {
		return "contains \\u0000 text", false
	}
	return "unexplained", false
}

// bigIntsToFloat re-types integers with |x| >= 1e16 that are exactly
// representable as float64 (what a Python float with exponent repr becomes in
// jsonb) back to float64. Returns how many were changed.
func bigIntsToFloat(v *any) int {
	switch x := (*v).(type) {
	case pyjson.Int:
		b, ok := new(big.Int).SetString(string(x), 10)
		if !ok {
			return 0
		}
		f, acc := new(big.Float).SetInt(b).Float64()
		if acc != big.Exact || math.Abs(f) < 1e16 {
			return 0
		}
		*v = f
		return 1
	case []any:
		n := 0
		for i := range x {
			n += bigIntsToFloat(&x[i])
		}
		return n
	case *pyjson.Object:
		n := 0
		for _, k := range x.Keys() {
			e := x.Get(k)
			if k := bigIntsToFloat(&e); k > 0 {
				n += k
			}
			x.Set(k, e)
		}
		return n
	}
	return 0
}
