package webui_test

import (
	"bytes"
	"io"
	"log/slog"
	"sort"
	"strings"
	"testing"

	"nday.land/nday/internal/admin"
	"nday.land/nday/internal/auth"
	"nday.land/nday/internal/corrections"
	"nday.land/nday/internal/discuss"
	"nday.land/nday/internal/posts"
	"nday.land/nday/internal/web"
	"nday.land/nday/internal/webui"
	"nday.land/nday/internal/webui/i18n"
)

// TestRoutesReservedAsHandles builds the server the way `nday serve` does
// with every optional part on (sign-in, discussions, corrections, posts,
// the back office, the catalog preview, two-host mode), then checks that
// the first path segment of every registered pattern is reserved as a
// handle. Handles live at the root (/<name>), so a free segment would let
// someone register a name that shadows, or is shadowed by, a real page.
func TestRoutesReservedAsHandles(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	acfg := &auth.Config{PublicOrigin: "https://www.nday.land", Secrets: [][]byte{bytes.Repeat([]byte{7}, 32)},
		Providers: map[string]auth.ProviderCredentials{auth.GitHub: {ClientID: "c", ClientSecret: "s"}},
		Passkeys:  true, RPID: "nday.land", Origins: []string{"https://www.nday.land"}}
	asvc, err := auth.New(acfg, auth.Options{Store: &auth.Store{}, Logger: log})
	if err != nil {
		t.Fatal(err)
	}
	ds, err := discuss.New(discuss.Options{Store: &discuss.Store{}, Auth: asvc, Logger: log})
	if err != nil {
		t.Fatal(err)
	}
	corr, err := corrections.New(corrections.Options{Store: &corrections.Store{}, Auth: asvc, Logger: log})
	if err != nil {
		t.Fatal(err)
	}
	none := auth.SingleConn(nil) // nothing is queried while routes are registered
	adm, err := admin.New(admin.Options{Auth: asvc, AuthDB: none, ReadDB: none, Discussions: true, Logger: log})
	if err != nil {
		t.Fatal(err)
	}
	srv := web.New(web.Config{Logger: log, PublicURL: "https://www.nday.land", APIURL: "https://api.nday.land"})
	asvc.Register(srv)
	posts.New(posts.Options{Auth: asvc, Logger: log}).Register(srv)
	corr.Register(srv)
	ds.Register(srv)
	adm.Register(srv)
	if _, err := webui.New(srv, webui.Options{I18nDebug: true, Accounts: webui.AccountsOf(asvc),
		Discussions: webui.DiscussionsOf(ds), Admin: adm}); err != nil {
		t.Fatal(err)
	}

	segs := map[string][]string{}
	for _, p := range srv.Patterns() {
		path := p
		if i := strings.IndexByte(path, ' '); i >= 0 {
			path = strings.TrimSpace(path[i+1:])
		}
		seg, _, _ := strings.Cut(strings.TrimPrefix(path, "/"), "/")
		if seg == "" || strings.HasPrefix(seg, "{") {
			continue // the root and catch-alls
		}
		segs[seg] = append(segs[seg], p)
	}
	// every locale prefix, also those switched off today for an incomplete
	// catalog (they are mounted as soon as the catalog is fixed)
	set, err := i18n.Default()
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range set.All {
		if l.Prefix != "" {
			segs[l.Prefix] = append(segs[l.Prefix], "locale "+l.Tag)
		}
	}
	for _, must := range []string{"api", "auth", "account", "admin", "static", "hot", "vuln", "v1", "ja"} {
		if segs[must] == nil {
			t.Errorf("no pattern under /%s: the route list is incomplete", must)
		}
	}
	names := make([]string, 0, len(segs))
	for s := range segs {
		names = append(names, s)
	}
	sort.Strings(names)
	for _, s := range names {
		if !auth.IsReserved(strings.ToLower(s)) {
			t.Errorf("top-level segment %q (%s) is not reserved: add it to auth.ReservedNames", s, strings.Join(segs[s], ", "))
		}
	}
	t.Logf("checked %d top-level segments: %s", len(names), strings.Join(names, " "))
}
