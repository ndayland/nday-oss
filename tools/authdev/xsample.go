package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/xconfig"
)

// Sample X posts collector data for /admin/x and the researcher section,
// the @N badges of /hot and /discussed (-x-sample): allowlisted
// accounts and settings (through internal/xconfig, like the CLI), a
// collector_state row whose cursor reports a run that stopped early, and a
// few social_post events over the last days. Development only: it never
// calls the X API and needs no token. Re-running it is harmless (upserts,
// ON CONFLICT DO NOTHING).
func xSample(ctx context.Context, dbURL string, log *slog.Logger) error {
	conn, err := pgx.Connect(ctx, dbURL)
	if err != nil {
		return err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	return pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		for _, a := range [][3]string{{"1001", "alice_sec", "exploit researcher"}, {"1002", "bob_sec", ""}, {"1003", "carol_ir", "incident response"}} {
			if _, err := xconfig.UpsertAccount(ctx, tx, a[0], a[1], a[2]); err != nil {
				return err
			}
		}
		if err := xconfig.SetAccountEnabled(ctx, tx, "1003", false); err != nil {
			return err
		}
		posts, reqs := 200, 10
		if err := xconfig.SaveSettings(ctx, tx, xconfig.Stored{MaxPosts: &posts, MaxRequests: &reqs}); err != nil {
			return err
		}
		now := time.Now().UTC()
		cur, _ := json.Marshal(map[string]any{"since_id": "1856000000000000000", "last_run": map[string]any{
			"at": now.Add(-40 * time.Minute).Format(time.RFC3339), "mode": "since_id", "accounts": 2, "batches": 1, "batches_done": 0,
			"http_requests": 10, "posts": 180, "kept": 6, "kept_no_cve": 160, "dropped_author": 14,
			"stopped": "max_requests", "stop_info": map[string]any{"limit": 10}}})
		if _, err := tx.Exec(ctx, `INSERT INTO collector_state (source, cursor, last_run_at, last_status, last_success_at)
			VALUES ('xposts', $1, $2, 'ok', $2) ON CONFLICT (source) DO UPDATE SET cursor = EXCLUDED.cursor,
			last_run_at = EXCLUDED.last_run_at, last_status = 'ok', last_success_at = EXCLUDED.last_success_at`, string(cur), now.Add(-40*time.Minute)); err != nil {
			return err
		}
		texts := []string{"PoC for CVE-2024-3094 is public now, patch your xz.", "CVE-2025-1974 exploited in the wild? Watching closely.",
			"Writeup: CVE-2024-3094 and CVE-2025-1974 compared.", "New advisory CVE-2026-0001, details soon.",
			"Reminder: CVE-2024-3094 detection rules updated.", "Thread on CVE-2025-1974 mitigations (1/5)"}
		cves := [][]string{{"CVE-2024-3094"}, {"CVE-2025-1974"}, {"CVE-2024-3094", "CVE-2025-1974"}, {"CVE-2026-0001"}, {"CVE-2024-3094"}, {"CVE-2025-1974"}}
		for i, text := range texts {
			author, handle := "1001", "alice_sec"
			if i%2 == 1 {
				author, handle = "1002", "bob_sec"
			}
			id := fmt.Sprintf("18560000000000000%02d", i)
			at := now.Add(-time.Duration(i*13+1) * time.Hour)
			detail, _ := json.Marshal(map[string]any{"post_id": id, "author_id": author, "author_handle": handle, "text": text, "lang": "en", "cves": cves[i]})
			for _, c := range cves[i] {
				if _, err := tx.Exec(ctx, `INSERT INTO vuln (cve_id) VALUES ($1) ON CONFLICT DO NOTHING`, c); err != nil {
					return err
				}
				if _, err := tx.Exec(ctx, `INSERT INTO event (cve_id, type, occurred_at, observed_at, source, url, detail, dedupe_key)
					VALUES ($1, 'social_post', $2, $3, 'xposts', $4, $5, $6) ON CONFLICT DO NOTHING`,
					c, at, at.Add(5*time.Minute), "https://x.com/"+handle+"/status/"+id, string(detail), id); err != nil {
					return err
				}
			}
		}
		if err := researcherSample(ctx, tx, now); err != nil {
			return err
		}
		if err := candidateSample(ctx, tx, now); err != nil {
			return err
		}
		log.Info("authdev: sample X collector data inserted (accounts, settings, cursor, posts, candidates)")
		return nil
	})
}

// researcherSample adds posts of the last days from four more enabled
// accounts (and one disabled) about up to five CVEs that the local database
// already lists on /hot (most recent transitions first), plus two stub CVEs
// known only from posts, so the researcher section, the badges and
// /discussed show something. Each run moves these posts to the last hours
// again (they are matched by post id), so the 7-day window never empties.
func researcherSample(ctx context.Context, tx pgx.Tx, now time.Time) error {
	accounts := [][3]string{{"2001", "dana_vr", "vulnerability research"}, {"2002", "eve_poc", ""},
		{"2003", "frank_dfir", "forensics"}, {"2004", "grace_kev", ""}, {"2005", "heidi_old", "disabled sample"}}
	for _, a := range accounts {
		if _, err := xconfig.UpsertAccount(ctx, tx, a[0], a[1], a[2]); err != nil {
			return err
		}
	}
	if err := xconfig.SetAccountEnabled(ctx, tx, "2005", false); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT cve_id FROM vuln_state_mat ORDER BY last_transition_at DESC NULLS LAST, cve_id LIMIT 5`)
	if err != nil {
		return err
	}
	cves, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	cves = append(cves, "CVE-2026-990001", "CVE-2026-990002") // stubs: known only from posts
	texts := []string{"Quick triage notes on %s: the advisory understates the impact.",
		"%s: patched build tested, regression in the auth path. Details in thread.",
		"Seeing scanning for %s since this morning.",
		"PoC for %s reproduces on the default config. Not sharing until the vendor ships.",
		"%s looks like a variant of last year's bug in the same parser; same mitigation applies. Long write-up coming, with timelines and detection ideas for blue teams."}
	n := 0
	for ci, cve := range cves {
		if _, err := tx.Exec(ctx, `INSERT INTO vuln (cve_id) VALUES ($1) ON CONFLICT DO NOTHING`, cve); err != nil {
			return err
		}
		// CVE i gets posts from len(cves)-i authors (so /discussed has a ranking)
		for k := 0; k < len(accounts) && k < len(cves)-ci; k++ {
			a := accounts[k]
			n++
			id := fmt.Sprintf("1957%015d", n)
			at := now.Add(-time.Duration(n*37) * time.Minute)
			text := fmt.Sprintf(texts[(ci+k)%len(texts)], cve)
			// resolved links (x_post_link): every other post carries one,
			// shared by several posts so the resources show researcher counts
			var links [][3]string // short, final, kind
			if n%2 == 0 {
				links = append(links, sampleLinks[(ci+n/2)%len(sampleLinks)])
				links[0][0] = fmt.Sprintf("https://t.co/smpl%06d", n)
				text += " " + links[0][0]
			}
			detail, _ := json.Marshal(map[string]any{"post_id": id, "author_id": a[0], "author_handle": a[1], "text": text, "lang": "en",
				"cves": []string{cve}})
			if _, err := tx.Exec(ctx, `INSERT INTO event (cve_id, type, occurred_at, observed_at, source, url, detail, dedupe_key)
				VALUES ($1, 'social_post', $2, $3, 'xposts', $4, $5, $6)
				ON CONFLICT ON CONSTRAINT event_uniq DO UPDATE SET occurred_at = EXCLUDED.occurred_at, observed_at = EXCLUDED.observed_at`,
				cve, at, at.Add(5*time.Minute), "https://x.com/"+a[1]+"/status/"+id, string(detail), id); err != nil {
				return err
			}
			for pos, l := range links {
				if _, err := tx.Exec(ctx, `INSERT INTO x_post_link (post_id, pos, short_url, expanded_url, final_url, host, kind, origin, status)
					VALUES ($1, $2, $3, $4, $4, $5, $6, 'api', 'ok') ON CONFLICT (post_id, pos) DO NOTHING`,
					id, pos, l[0], l[1], sampleHost(l[1]), l[2]); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// candidateSample adds allowlist candidates for /admin/x (tables of
// migrations/0019): two with a handle, one without (it cannot be added),
// one already dismissed, each referred to by sample posts above. Rows that
// exist are left as they are (ON CONFLICT DO NOTHING), so what an admin did
// with a sample candidate survives a re-run.
func candidateSample(ctx context.Context, tx pgx.Tx, now time.Time) error {
	for _, c := range []struct {
		id     string
		handle any // nil: the API sent no valid handle
		status string
		refs   [][2]string // referring post id (one of the sample posts), kind
	}{
		{"4001", "ivan_re", "pending", [][2]string{{"1856000000000000000", "quoted"}, {"1856000000000000001", "mentioned"}, {"1957000000000000001", "replied_to"}}},
		{"4002", "judy_bugs", "pending", [][2]string{{"1856000000000000002", "mentioned"}}},
		{"4003", nil, "pending", [][2]string{{"1856000000000000003", "quoted"}}},
		{"4004", "mallory_x", "dismissed", [][2]string{{"1856000000000000004", "mentioned"}}},
	} {
		seen := now.Add(-2 * time.Hour)
		var decided any
		if c.status == "dismissed" {
			decided = now.Add(-time.Hour)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO x_account_candidate (user_id, handle, first_seen_at, last_seen_at, status, decided_at)
			VALUES ($1, $2, $3, $3, $4, $5) ON CONFLICT (user_id) DO NOTHING`, c.id, c.handle, seen, c.status, decided); err != nil {
			return err
		}
		for _, r := range c.refs {
			// the referrer is the sample post's author: 1001/1002 alternate, 1957… is 2001
			referrer := map[bool]string{true: "1001", false: "1002"}[(r[0][len(r[0])-1]-'0')%2 == 0]
			if strings.HasPrefix(r[0], "1957") {
				referrer = "2001"
			}
			if _, err := tx.Exec(ctx, `INSERT INTO x_account_candidate_ref (user_id, post_id, referrer_id, kind, posted_at)
				VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING`, c.id, r[0], referrer, r[1], seen); err != nil {
				return err
			}
		}
	}
	return nil
}

// sampleLinks are the final URLs of the sample posts' links (the short
// link is set per post).
var sampleLinks = [][3]string{
	{"", "https://github.com/example/project/commit/0123456789abcdef", "patch"},
	{"", "https://www.exploit-db.com/exploits/52001", "poc"},
	{"", "https://msrc.microsoft.com/update-guide/vulnerability/sample", "advisory"},
	{"", "https://blog.example.com/2026/11/a-long-write-up-with-timelines-and-detection-ideas", "other"},
}

// sampleHost is the host column of a sample link (lower case, no "www.").
func sampleHost(u string) string {
	h := strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "www.")
	h, _, _ = strings.Cut(h, "/")
	return h
}
