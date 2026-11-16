package xlinks

import (
	"context"
	"errors"
	"log/slog"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/pagefetch"
	"nday.land/nday/internal/webpages"
)

// PageSource is the producer name of the X post links in the web page
// queue (web_page.first_source).
const PageSource = "xposts"

// PageKinds are the link kinds whose pages are queued for metadata: the
// kinds the public resources panel shows (site.ResourceKinds).
var PageKinds = []string{KindPoC, KindPatch, KindAdvisory, KindCode, KindOther}

// EnqueueResult counts one EnqueuePages sweep.
type EnqueueResult struct {
	Candidates int `json:"candidates"` // link rows swept (new or with a changed final URL)
	Added      int `json:"added"`      // new queue rows
	Refused    int `json:"refused"`    // distinct URLs not queueable (pagefetch URL rules)
}

// enqueueBatch is the number of link rows read per round.
const enqueueBatch = 1000

// EnqueuePages hands the links of stored X posts to the web page queue
// (internal/webpages): every x_post_link row with status 'ok' and a kind of
// PageKinds whose final_url differs from its page_queued_url (never swept,
// or the URL changed since) is swept, oldest first: its final URL is given
// to webpages.Enqueue (which de-duplicates by key and refuses URLs that
// break the URL rules, without writing), then page_queued_url = final_url
// marks the row done whatever the outcome. So each link is looked at once
// per final URL: refused URLs and other spellings of a queued key are not
// re-read on later sweeps. Idempotent: it is the backfill too. Fetching is
// webpages.FetchPending's job.
func EnqueuePages(ctx context.Context, db DB, log *slog.Logger) (EnqueueResult, error) {
	var res EnqueueResult
	if log == nil {
		log = slog.Default()
	}
	type link struct {
		postID, url string
		pos         int
	}
	done := map[string]bool{} // URLs handled in this sweep
	for {
		rows, err := db.Query(ctx, `SELECT l.post_id, l.pos, l.final_url FROM x_post_link l
            WHERE l.status = 'ok' AND l.kind = ANY($1) AND l.final_url IS NOT NULL AND l.final_url <> ''
              AND l.page_queued_url IS DISTINCT FROM l.final_url
            ORDER BY l.created_at, char_length(l.post_id), l.post_id, l.pos
            LIMIT $2`, PageKinds, enqueueBatch)
		if err != nil {
			return res, err
		}
		links, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (link, error) {
			var l link
			return l, r.Scan(&l.postID, &l.pos, &l.url)
		})
		if err != nil {
			return res, err
		}
		for _, l := range links {
			if err := ctx.Err(); err != nil {
				return res, err
			}
			res.Candidates++
			if !done[l.url] {
				added, err := webpages.Enqueue(ctx, db, l.url, PageSource)
				switch {
				case errors.Is(err, pagefetch.ErrRefused):
					res.Refused++
					log.Debug("x link not queued for its page", "why", err.Error())
				case err != nil:
					return res, err
				case added:
					res.Added++
				}
				done[l.url] = true
			}
			if _, err := db.Exec(ctx, `UPDATE x_post_link SET page_queued_url = final_url
                WHERE post_id = $1 AND pos = $2 AND final_url = $3`, l.postID, l.pos, l.url); err != nil {
				return res, err
			}
		}
		if len(links) < enqueueBatch {
			return res, nil
		}
	}
}
