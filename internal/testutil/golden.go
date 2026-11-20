package testutil

import (
	"bytes"
	"context"
	"errors"
	"io"
	"path/filepath"
	"testing"
	"time"

	"nday.land/nday/internal/collector"
	"nday.land/nday/internal/model"
	"nday.land/nday/internal/pyjson"
)

func ioNopCloser(b []byte) io.ReadCloser { return io.NopCloser(bytes.NewReader(b)) }

// GoldenTime is the datetime format of tools/dump_golden.py.
const GoldenTime = "2006-01-02T15:04:05.000000Z"

func gTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UTC().Format(GoldenTime)
}

func gStr(s *string) any {
	if s == nil {
		return nil
	}
	return *s
}

// NormalizedValue renders a Normalized like Python's dataclasses.asdict in
// tools/dump_golden.py, as a pyjson value (so Canonical() can compare it).
func NormalizedValue(n *model.Normalized) any {
	vulns, aliases, affected, events := []any{}, []any{}, []any{}, []any{}
	for _, v := range n.Vulns {
		vulns = append(vulns, map[string]any{
			"cve_id": v.CVEID, "title": gStr(v.Title), "description": gStr(v.Description),
			"published_at": gTime(v.PublishedAt), "modified_at": gTime(v.ModifiedAt),
			"authoritative": v.Authoritative,
		})
	}
	for _, a := range n.Aliases {
		aliases = append(aliases, map[string]any{"cve_id": a.CVEID, "alias": a.Alias, "alias_type": a.AliasType})
	}
	for _, a := range n.Affected {
		affected = append(affected, map[string]any{"cve_id": a.CVEID, "vendor": a.Vendor, "product": a.Product})
	}
	for _, e := range n.Events {
		detail := map[string]any{}
		for k, v := range e.Detail {
			detail[k] = v
		}
		events = append(events, map[string]any{
			"cve_id": e.CVEID, "type": e.Type, "source": e.Source, "occurred_at": gTime(e.OccurredAt),
			"url": gStr(e.URL), "detail": detail, "dedupe_key": e.DedupeKey,
		})
	}
	out := map[string]any{"vulns": vulns, "aliases": aliases, "affected": affected, "events": events}
	// Go only (xposts); omitted when empty so the goldens shared with the
	// Python ports are unchanged.
	if len(n.PostsNoCVE) > 0 {
		posts := []any{}
		for _, p := range n.PostsNoCVE {
			posts = append(posts, map[string]any{
				"post_id": p.PostID, "author_id": p.AuthorID, "author_handle": gStr(p.AuthorHandle),
				"text": p.Text, "lang": gStr(p.Lang), "posted_at": gTime(&p.PostedAt), "url": p.URL,
			})
		}
		out["posts_no_cve"] = posts
	}
	if len(n.PostLinks) > 0 {
		links := []any{}
		for _, l := range n.PostLinks {
			links = append(links, map[string]any{
				"post_id": l.PostID, "pos": l.Pos, "short_url": l.ShortURL, "expanded_url": gStr(l.ExpandedURL),
				"final_url": gStr(l.FinalURL), "host": gStr(l.Host), "kind": l.Kind, "title": gStr(l.Title),
				"origin": l.Origin, "status": l.Status,
			})
		}
		out["post_links"] = links
	}
	if len(n.CandidateRefs) > 0 {
		refs := []any{}
		for _, r := range n.CandidateRefs {
			refs = append(refs, map[string]any{
				"user_id": r.UserID, "handle": gStr(r.Handle), "post_id": r.PostID, "referrer_id": r.ReferrerID,
				"kind": r.Kind, "posted_at": gTime(&r.PostedAt),
			})
		}
		out["candidate_refs"] = refs
	}
	if len(n.XUsers) > 0 {
		users := []any{}
		for _, u := range n.XUsers {
			users = append(users, map[string]any{
				"user_id": u.UserID, "name": gStr(u.Name), "avatar_url": gStr(u.AvatarURL), "seen_at": gTime(&u.SeenAt),
			})
		}
		out["x_users"] = users
	}
	return out
}

func canon(t testing.TB, v any) string {
	t.Helper()
	s, err := pyjson.Canonical(v)
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	return s
}

// CheckGolden compares a Go collector with a golden file written by
// tools/dump_golden.py. newCollector builds the collector with the given
// fake transport (it is only used for kind "fetch" goldens, which serve the
// golden's input file as the body of every GET).
//
// Checked per record: source_key, is_backfill, content_hash, and either the
// canonical JSON of the normalized output or the error (NormalizeError
// message must match exactly; a fatal Python exception must be a fatal Go
// error, i.e. not a *collector.NormalizeError, or a Validate() failure).
func CheckGolden(t *testing.T, goldenRel string, newCollector func(*FakeTransport) collector.Collector) {
	t.Helper()
	raw := ReadFile(t, goldenRel)
	gv, err := pyjson.Decode(raw)
	if err != nil {
		t.Fatalf("%s: %v", goldenRel, err)
	}
	g := gv.(*pyjson.Object)
	input := g.Get("input").(string)
	var recs []model.RawRecord
	var c collector.Collector
	switch g.Get("kind") {
	case "fetch":
		c = newCollector(Serve(ReadFile(t, input)))
		res, err := c.Fetch(context.Background(), model.CollectorState{Source: c.Name()})
		if err != nil {
			t.Fatalf("fetch %s: %v", input, err)
		}
		if got, want := canon(t, res.Cursor), canon(t, g.Get("cursor")); got != want {
			t.Errorf("%s cursor:\n got  %s\n want %s", input, got, want)
		}
		recs = res.Records
	case "records":
		c = newCollector(Serve(nil))
		items, err := pyjson.Decode(ReadFile(t, input))
		if err != nil {
			t.Fatal(err)
		}
		for _, it := range items.([]any) {
			o := it.(*pyjson.Object)
			bf, _ := o.Get("is_backfill").(bool)
			recs = append(recs, model.RawRecord{Source: c.Name(), SourceKey: o.Get("source_key").(string),
				Payload: o.Get("payload"), IsBackfill: bf})
		}
	default:
		t.Fatalf("%s: unknown kind %v", goldenRel, g.Get("kind"))
	}
	want := g.Get("records").([]any)
	if len(recs) != len(want) {
		t.Fatalf("%s: %d records, golden has %d", input, len(recs), len(want))
	}
	for i, rec := range recs {
		w := want[i].(*pyjson.Object)
		name := filepath.Base(input) + "#" + rec.SourceKey
		if rec.SourceKey != w.Get("source_key") || rec.IsBackfill != w.Get("is_backfill") {
			t.Errorf("%s: key/backfill = %q/%v, golden %v/%v", name, rec.SourceKey, rec.IsBackfill,
				w.Get("source_key"), w.Get("is_backfill"))
		}
		h, err := rec.ContentHash()
		if err != nil || h != w.Get("content_hash") {
			t.Errorf("%s: content_hash %s (%v), golden %v", name, h, err, w.Get("content_hash"))
		}
		norm, nerr := c.Normalize(rec)
		if nerr == nil {
			nerr = norm.Validate()
		}
		if ge, ok := w.Lookup("error"); ok {
			e := ge.(*pyjson.Object)
			var ne *collector.NormalizeError
			isNE := errors.As(nerr, &ne)
			switch {
			case nerr == nil:
				t.Errorf("%s: Go normalized OK, Python raised %v: %v", name, e.Get("type"), e.Get("message"))
			case e.Get("fatal") == true && isNE:
				t.Errorf("%s: Go NormalizeError %q, Python fatal %v", name, nerr, e.Get("type"))
			case e.Get("fatal") == false && !isNE:
				t.Errorf("%s: Go fatal error %v, Python NormalizeError", name, nerr)
			case e.Get("fatal") == false && ne.Msg != e.Get("message"):
				t.Errorf("%s: NormalizeError message\n got  %q\n want %q", name, ne.Msg, e.Get("message"))
			}
			continue
		}
		if nerr != nil {
			t.Errorf("%s: Go error %v, Python normalized OK", name, nerr)
			continue
		}
		if got, wantS := canon(t, NormalizedValue(norm)), canon(t, w.Get("normalized")); got != wantS {
			t.Errorf("%s: normalized differs\n got  %s\n want %s", name, got, wantS)
		}
	}
}
