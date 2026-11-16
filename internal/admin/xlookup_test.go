package admin_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"nday.land/nday/internal/xconfig"
	"nday.land/nday/internal/xlookup"
	"nday.land/nday/internal/xlookup/xfake"
)

// lookupToken is the token of the fake X API; no response, log line, error
// string or audit row may ever contain it.
const lookupToken = "XLOOKUP-SECRET-7c6b5a49"

// lookupFake serves the fake X user lookup over HTTP (httptest) and returns
// it with a client of the given token (timeout short for the slow handle).
func lookupFake(t *testing.T, tok string) (*xfake.Server, *xlookup.Client) {
	t.Helper()
	f := xfake.New(lookupToken)
	f.Add("2244994945", "XDevelopers")
	f.Add("783214", "X")
	f.Add("1001", "Alice_Sec")
	f.Suspended["gone_bad"] = true
	f.RateLimited["too_fast"] = true
	f.Slow["sloth"] = true
	ts := httptest.NewServer(f)
	t.Cleanup(ts.Close)
	c, err := xlookup.New(xlookup.Options{Token: tok, BaseURL: ts.URL, Timeout: 300 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	return f, c
}

type addAnswer struct {
	UserID   string `json:"user_id"`
	Handle   string `json:"handle"`
	Result   string `json:"result"`
	Previous string `json:"previous_handle"`
	LookedUp bool   `json:"looked_up"`
}

// TestXAddByHandle: the handle alone binds the id X returns (canonical
// spelling), every lookup failure has its own code, an id already listed is
// 409 (same handle) or gets the new handle (renamed), invalid input is
// refused before any request, and the token never shows.
func TestXAddByHandle(t *testing.T) {
	f, lk := lookupFake(t, lookupToken)
	h := newHarness(t, hopt{xlookup: lk})
	adm := h.user("kim", "admin")
	ctx := context.Background()
	if err := xconfig.InsertAccount(ctx, h.db.Conn, "783214", "old_x", "kept note"); err != nil {
		t.Fatal(err)
	}
	var all strings.Builder
	post := func(body string) (*http.Response, []byte) {
		resp, b := adm.post("/api/admin/x/accounts", body)
		all.Write(b)
		return resp, b
	}
	cases := []struct {
		name, body string
		status     int
		code       string
		want       addAnswer
		requests   int // requests the fake saw for this case
	}{
		{"found, canonical case", `{"handle":"xdevelopers","note":"devs"}`, 200, "", addAnswer{"2244994945", "XDevelopers", "added", "", true}, 1},
		{"same id, same handle", `{"handle":"@XDEVELOPERS","note":""}`, 409, "exists", addAnswer{}, 1},
		{"renamed", `{"handle":"x","note":""}`, 200, "", addAnswer{"783214", "X", "renamed", "old_x", true}, 1},
		{"not found", `{"handle":"nobody_here","note":""}`, 422, "x_not_found", addAnswer{}, 1},
		{"suspended", `{"handle":"gone_bad","note":""}`, 422, "x_unavailable", addAnswer{}, 1},
		{"429", `{"handle":"too_fast","note":""}`, 503, "x_rate_limited", addAnswer{}, 1},
		{"timeout", `{"handle":"sloth","note":""}`, 502, "x_upstream", addAnswer{}, 1},
		{"explicit id: no lookup", `{"user_id":"42","handle":"manual","note":""}`, 200, "", addAnswer{"42", "manual", "added", "", false}, 0},
		{"hostile: space", `{"handle":"a b","note":""}`, 400, "bad_handle", addAnswer{}, 0},
		{"hostile: markup", `{"handle":"<script>","note":""}`, 400, "bad_handle", addAnswer{}, 0},
		{"hostile: query", `{"handle":"abc&usernames=x","note":""}`, 400, "bad_handle", addAnswer{}, 0},
		{"hostile: comma list", `{"handle":"abc,def","note":""}`, 400, "bad_handle", addAnswer{}, 0},
		{"hostile: path", `{"handle":"../2/tweets","note":""}`, 400, "bad_handle", addAnswer{}, 0},
		{"too long", `{"handle":"abcdefghijklmnop","note":""}`, 400, "bad_handle", addAnswer{}, 0},
		{"empty", `{"handle":"","note":""}`, 400, "bad_handle", addAnswer{}, 0},
		{"bad note", `{"handle":"X","note":"two\nlines"}`, 400, "bad_note", addAnswer{}, 0},
		{"bad id", `{"user_id":"01","handle":"X","note":""}`, 400, "bad_user_id", addAnswer{}, 0},
		{"token-looking field ignored", `{"handle":"X","note":"","token":"` + lookupToken + `x"}`, 400, "bad_request", addAnswer{}, 0},
	}
	for _, tc := range cases {
		before := f.Requests()
		resp, body := post(tc.body)
		check(t, tc.name, tc.status, tc.code)(resp, body)
		if n := f.Requests() - before; n != tc.requests {
			t.Errorf("%s: the fake saw %d requests, want %d", tc.name, n, tc.requests)
		}
		if tc.status == 200 {
			var got addAnswer
			_ = json.Unmarshal(body, &got)
			if got != tc.want {
				t.Errorf("%s: %+v, want %+v", tc.name, got, tc.want)
			}
		}
	}
	// one row per id; the renamed id kept its note and state
	get := func(id string) xconfig.Account { a, _ := xconfig.GetAccount(ctx, h.db.Conn, id); return a }
	if a := get("2244994945"); a.Handle != "XDevelopers" || a.Note != "devs" || !a.Enabled {
		t.Errorf("added: %+v", a)
	}
	if a := get("783214"); a.Handle != "X" || a.Note != "kept note" {
		t.Errorf("renamed: %+v", a)
	}
	if n := h.count(`SELECT count(*) FROM x_accounts`); n != 3 {
		t.Errorf("%d rows", n)
	}
	// the 409 names the listed account
	_, body := post(`{"handle":"XDevelopers","note":""}`)
	if !strings.Contains(string(body), `"user_id":"2244994945"`) {
		t.Errorf("409 body: %s", body)
	}
	// audit rows carry the resolved id and handle
	var audits string
	_ = h.db.Conn.QueryRow(ctx, `SELECT string_agg(action || ' ' || target_id || ' ' || target_label || ' ' || details::text, E'\n' ORDER BY id)
		FROM admin_audit`).Scan(&audits)
	for _, want := range []string{
		`x.account.add 2244994945 @XDevelopers {"note": "devs", "handle": "XDevelopers", "lookup": true, "entered": "xdevelopers", "user_id": "2244994945"}`,
		`x.account.update 783214 @X {"handle": {"to": "X", "from": "old_x"}, "lookup": true, "entered": "x", "user_id": "783214"}`,
		`x.account.add 42 @manual {"note": "", "handle": "manual", "lookup": false, "user_id": "42"}`,
	} {
		if !strings.Contains(audits, want) {
			t.Errorf("audit lacks %s\n%s", want, audits)
		}
	}
	if n := h.count(`SELECT count(*) FROM admin_audit`); n != 3 {
		t.Errorf("audit rows %d, want 3 (refusals write none)", n)
	}
	// the page says lookup is on (and nothing about the token)
	_, page := adm.do("GET", "/admin/x", "")
	all.Write(page)
	if !strings.Contains(string(page), `data-lookup="on"`) || !strings.Contains(string(page), "Lookup is on") {
		t.Error("page does not say lookup is on")
	}
	for _, a := range f.Auths() {
		if a != "Bearer "+lookupToken {
			t.Errorf("Authorization %q", a)
		}
	}
	if strings.Contains(all.String(), lookupToken) || strings.Contains(h.logs.String(), lookupToken) || strings.Contains(audits, lookupToken) {
		t.Error("the token reached a response, the logs or the audit")
	}
}

// TestXAddLookupUnavailable: no token (no request, x_lookup_off, the page
// says so and the explicit id still works) and a refused token (x_auth).
func TestXAddLookupUnavailable(t *testing.T) {
	f, bad := lookupFake(t, "WRONG-"+lookupToken)
	h := newHarness(t, hopt{xlookup: bad})
	adm := h.user("kim", "admin")
	resp, body := adm.post("/api/admin/x/accounts", `{"handle":"X","note":""}`)
	check(t, "refused token", 502, "x_auth")(resp, body)
	if f.Requests() != 1 || strings.Contains(string(body), lookupToken) || strings.Contains(h.logs.String(), lookupToken) {
		t.Errorf("requests %d; body %s", f.Requests(), body)
	}

	h2 := newHarness(t, hopt{}) // no lookup client: like a server without NDAY_X_BEARER_TOKEN
	adm2 := h2.user("kim", "admin")
	check(t, "no token", 503, "x_lookup_off")(adm2.post("/api/admin/x/accounts", `{"handle":"X","note":""}`))
	check(t, "no token, explicit id", 200, "")(adm2.post("/api/admin/x/accounts", `{"user_id":"783214","handle":"X","note":""}`))
	check(t, "no token, import of a handle", 503, "x_lookup_off")(adm2.post("/api/admin/x/import", `{"text":"@X\n","dry_run":true}`))
	check(t, "no token, import with ids", 200, "")(adm2.post("/api/admin/x/import", `{"text":"5 five\n","dry_run":false}`))
	_, page := adm2.do("GET", "/admin/x", "")
	if !strings.Contains(string(page), `data-lookup="off"`) || !strings.Contains(string(page), "Lookup is off") {
		t.Error("page does not say lookup is off")
	}
	_, page = adm2.do("GET", "/zh-hans/admin/x", "")
	if !strings.Contains(string(page), "查询未开启") {
		t.Error("zh-hans page does not say lookup is off")
	}
}

// TestXImportByHandle: handle-only lines are looked up in batches of 100,
// the preview lists the id of each and writes nothing, any unresolved line
// means nothing is written (every failing line listed), and an id found for
// a handle that is also given with its id elsewhere is a duplicate.
func TestXImportByHandle(t *testing.T) {
	f, lk := lookupFake(t, lookupToken)
	h := newHarness(t, hopt{xlookup: lk})
	adm := h.user("kim", "admin")
	mod := h.user("mia", "moderator")
	user := h.user("pat", "user")
	ctx := context.Background()
	imp := func(b *browser, text string, dry bool) (*http.Response, []byte) {
		j, _ := json.Marshal(map[string]any{"text": text, "dry_run": dry})
		return b.post("/api/admin/x/import", string(j))
	}
	type answer struct {
		DryRun                       bool `json:"dry_run"`
		Inserted, Updated, Unchanged int
		Lines                        []struct {
			Line     int    `json:"line"`
			UserID   string `json:"user_id"`
			Handle   string `json:"handle"`
			Result   string `json:"result"`
			LookedUp bool   `json:"looked_up"`
		} `json:"lines"`
		Error struct {
			Code  string `json:"code"`
			Lines []struct {
				Line    int    `json:"line"`
				Message string `json:"message"`
			} `json:"lines"`
		} `json:"error"`
	}
	// role checks are unchanged and no lookup happens for a refused caller
	check(t, "moderator", 403, "forbidden")(imp(mod, "@X\n", true))
	check(t, "user", 404, "not_found")(imp(user, "@X\n", true))
	check(t, "moderator add", 403, "forbidden")(mod.post("/api/admin/x/accounts", `{"handle":"X","note":""}`))
	check(t, "user add", 404, "not_found")(user.post("/api/admin/x/accounts", `{"handle":"X","note":""}`))
	if f.Requests() != 0 {
		t.Fatalf("refused callers caused %d lookups", f.Requests())
	}
	// mixed lines, 150 handles: preview first
	var text strings.Builder
	text.WriteString("@xdevelopers # devs\n1002 bob_sec\nalice_sec\n")
	for i := 0; i < 150; i++ {
		hd := fmt.Sprintf("bulk_%d", i)
		f.Add(fmt.Sprint(9000+i), strings.ToUpper(hd))
		text.WriteString("@" + hd + "\n")
	}
	resp, body := imp(adm, text.String(), true)
	var r answer
	_ = json.Unmarshal(body, &r)
	if resp.StatusCode != 200 || !r.DryRun || r.Inserted != 153 || len(r.Lines) != 153 {
		t.Fatalf("preview: %d %.300s", resp.StatusCode, body)
	}
	if l := r.Lines[0]; l.UserID != "2244994945" || l.Handle != "XDevelopers" || !l.LookedUp {
		t.Errorf("line 1: %+v", l)
	}
	if l := r.Lines[1]; l.UserID != "1002" || l.LookedUp {
		t.Errorf("line 2: %+v", l)
	}
	if l := r.Lines[2]; l.UserID != "1001" || l.Handle != "Alice_Sec" {
		t.Errorf("line 3: %+v", l)
	}
	if n := f.Requests(); n != 2 {
		t.Errorf("152 handles took %d requests, want 2", n)
	}
	for _, q := range f.Queries() {
		if len(strings.Split(q, ",")) > 100 {
			t.Errorf("a request named more than 100 usernames")
		}
	}
	if n := h.count(`SELECT count(*) FROM x_accounts`); n != 0 || h.count(`SELECT count(*) FROM admin_audit`) != 0 {
		t.Fatal("the preview wrote something")
	}
	// one bad line among good ones: nothing written, every failing line listed
	bad := "@xdevelopers\n@nobody_here\n@gone_bad # suspended\n@X\n783214 x_again\n"
	resp, body = imp(adm, bad, false)
	r = answer{}
	_ = json.Unmarshal(body, &r)
	var lines []int
	for _, l := range r.Error.Lines {
		lines = append(lines, l.Line)
	}
	if resp.StatusCode != 400 || r.Error.Code != "bad_import" || fmt.Sprint(lines) != "[2 3 5]" {
		t.Errorf("bad import: %d %s", resp.StatusCode, body)
	}
	if n := h.count(`SELECT count(*) FROM x_accounts`); n != 0 {
		t.Fatal("a refused import wrote something")
	}
	// a parse error: no lookup at all
	before := f.Requests()
	check(t, "unparsable", 400, "bad_import")(imp(adm, "@X\n12345\n", false))
	check(t, "hostile line", 400, "bad_import")(imp(adm, "@abc&usernames=x\n", false))
	if f.Requests() != before {
		t.Error("an unparsable import made a lookup")
	}
	// lookup failures of the whole request
	check(t, "429", 503, "x_rate_limited")(imp(adm, "@X\n@too_fast\n", false))
	// the real import
	resp, body = imp(adm, text.String(), false)
	r = answer{}
	_ = json.Unmarshal(body, &r)
	if resp.StatusCode != 200 || r.Inserted != 153 {
		t.Fatalf("import: %d %.300s", resp.StatusCode, body)
	}
	if a, _ := xconfig.GetAccount(ctx, h.db.Conn, "9007"); a.Handle != "BULK_7" {
		t.Errorf("bulk_7: %+v", a)
	}
	var d string
	_ = h.db.Conn.QueryRow(ctx, `SELECT details::text FROM admin_audit WHERE action = 'x.accounts.import'`).Scan(&d)
	for _, want := range []string{`"inserted": 153`, `"looked_up": 152`, `"inserted 2244994945 @XDevelopers lookup"`, `"inserted 1002 @bob_sec"`, `"changed_omitted": `} {
		if !strings.Contains(d, want) {
			t.Errorf("import audit lacks %s: %s", want, d)
		}
	}
	if strings.Contains(d+string(body)+h.logs.String(), lookupToken) {
		t.Error("token leaked")
	}
}
