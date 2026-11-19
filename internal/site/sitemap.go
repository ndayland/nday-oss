package site

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// SitemapSpan is how many consecutive CVE sequence numbers of one year share
// a sitemap bucket: CVE-YYYY-N is in bucket (YYYY, N / SitemapSpan). The
// mapping depends on the id alone, so a vulnerability never moves to another
// bucket when data is added, and a bucket holds at most SitemapSpan ids.
// SitemapSpan divides 10^4, so a bucket never mixes ids of different digit
// counts (needed by the range scan in SitemapVulns).
const SitemapSpan = 5000

// SitemapBucket names one bucket of vulnerability ids: CVE ids by year and
// sequence number (Year, Bucket), or, when GHSA is set, the GHSA-keyed
// vulnerabilities whose id starts "GHSA-<GHSA>" (one character of GitHub's
// alphabet; Year and Bucket are 0). GitHub picks advisory ids at random, so
// the 20 GHSA buckets fill evenly; reviewed advisories without a CVE are a
// few thousand, far below what 20 buckets of SitemapSpan hold.
type SitemapBucket struct {
	Year   int
	Bucket int
	GHSA   string
}

// GHSAAlphabet is the alphabet of the groups of a GHSA id (ParseGHSAID).
const GHSAAlphabet = "23456789cfghjmpqrvwx"

// SitemapEntry is one vulnerability of a bucket. LastMod is when its page
// content last changed as far as the database records it: the later of the
// vuln row's updated_at and the newest event's created_at (zero when
// neither is known; vuln.updated_at is NOT NULL, so in practice never).
type SitemapEntry struct {
	CVEID   string
	LastMod time.Time
}

// Rejected CVEs (vuln_state_mat.is_rejected; a CVE without a state row has
// no events and is not rejected) are left out of the sitemap. CVE ids longer
// than 21 characters (sequence numbers over 12 digits; real ones have at
// most 7) are left out too, so the bigint cast cannot overflow. GHSA-keyed
// rows are bucketed by the first character after "GHSA-" and sort after
// every CVE bucket (their third column is never empty).
const sitemapBucketsSQL = `
SELECT DISTINCT substr(v.cve_id, 5, 4)::int, substr(v.cve_id, 10)::bigint / $1, ''
FROM vuln v
LEFT JOIN vuln_state_mat m ON m.cve_id = v.cve_id
WHERE NOT COALESCE(m.is_rejected, false) AND v.cve_id LIKE 'CVE-%' AND length(v.cve_id) <= 21
UNION
SELECT DISTINCT 0, 0::bigint, substr(v.cve_id, 6, 1)
FROM vuln v
LEFT JOIN vuln_state_mat m ON m.cve_id = v.cve_id
WHERE NOT COALESCE(m.is_rejected, false) AND v.cve_id LIKE 'GHSA-%'
ORDER BY 3, 1, 2`

// The lastmod reads public events only (public.go): a researcher post must
// not move a CVE's <lastmod> (that would publish when it was collected).
// $1..$2 is a bytewise id range; $3 the id length (0: any).
var sitemapVulnsSQL = `
SELECT v.cve_id,
       GREATEST(v.updated_at, (SELECT max(e.created_at) FROM event e WHERE e.cve_id = v.cve_id AND ` + publicEventSQL("e") + `))
FROM vuln v
LEFT JOIN vuln_state_mat m ON m.cve_id = v.cve_id
WHERE v.cve_id COLLATE "C" >= $1 AND v.cve_id COLLATE "C" <= $2 AND ($3 = 0 OR length(v.cve_id) = $3)
  AND NOT COALESCE(m.is_rejected, false)
ORDER BY v.cve_id COLLATE "C"`

// SitemapBuckets lists the non-empty buckets: the CVE buckets in (year,
// bucket) order, then the GHSA buckets.
func (s *Store) SitemapBuckets(ctx context.Context) ([]SitemapBucket, error) {
	var out []SitemapBucket
	err := s.db.WithConn(ctx, func(conn *pgx.Conn) error {
		rows, err := conn.Query(ctx, sitemapBucketsSQL, SitemapSpan)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (SitemapBucket, error) {
			var b SitemapBucket
			var n int64
			err := r.Scan(&b.Year, &n, &b.GHSA)
			b.Bucket = int(n)
			return b, err
		})
		return err
	})
	return out, err
}

// SitemapVulns lists the vulnerabilities of bucket b in CVE id order (an
// index range scan on vuln_cve_id_c_idx; no OFFSET). An empty result means
// the bucket does not exist.
func (s *Store) SitemapVulns(ctx context.Context, b SitemapBucket) ([]SitemapEntry, error) {
	var from, to string
	n := 0 // id length; 0 for the GHSA ranges, whose ids all have one length
	if b.GHSA != "" {
		if len(b.GHSA) != 1 || !strings.Contains(GHSAAlphabet, b.GHSA) || b.Year != 0 || b.Bucket != 0 {
			return nil, nil
		}
		// "GHSA-c" < every "GHSA-cxxx-…" < "GHSA-c~" bytewise
		from, to = "GHSA-"+b.GHSA, "GHSA-"+b.GHSA+"~"
	} else {
		if b.Year < 1000 || b.Year > 9999 || b.Bucket < 0 || int64(b.Bucket) >= 1e12/SitemapSpan {
			return nil, nil
		}
		lo, hi := int64(b.Bucket)*SitemapSpan, int64(b.Bucket+1)*SitemapSpan-1
		digits := len(strconv.FormatInt(hi, 10))
		if digits < 4 {
			digits = 4 // sequence numbers have at least four digits (CVE-1999-0001)
		}
		from = fmt.Sprintf("CVE-%04d-%0*d", b.Year, digits, lo)
		to = fmt.Sprintf("CVE-%04d-%0*d", b.Year, digits, hi)
		n = len(from)
	}
	var out []SitemapEntry
	err := s.db.WithConn(ctx, func(conn *pgx.Conn) error {
		rows, err := conn.Query(ctx, sitemapVulnsSQL, from, to, n)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (SitemapEntry, error) {
			var e SitemapEntry
			var t *time.Time
			err := r.Scan(&e.CVEID, &t)
			if t != nil {
				e.LastMod = t.UTC()
			}
			return e, err
		})
		return err
	})
	return out, err
}
