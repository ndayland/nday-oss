package admin_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"nday.land/nday/internal/xconfig"
	"nday.land/nday/internal/xlookup/xfake"
)

func setFakeProfile(f *xfake.Server, id, handle, name, desc string) {
	f.Users[strings.ToLower(handle)] = xfake.User{ID: id, Username: handle, Name: name, Description: desc}
}

func profileOfRow(t *testing.T, h *harness, id string) (name, desc *string, looked bool) {
	t.Helper()
	if err := h.db.Conn.QueryRow(context.Background(), `SELECT name, description, profile_at IS NOT NULL FROM x_accounts WHERE user_id = $1`, id).
		Scan(&name, &desc, &looked); err != nil {
		t.Fatal(err)
	}
	return
}

// TestXProfiles: adding by handle stores the name and bio X returned; the
// refresh looks up the accounts never looked up in one request, stores a
// profile only when X answers with the same id, writes one audit row and
// never shows the token; without a token it is refused.
func TestXProfiles(t *testing.T) {
	f, lk := lookupFake(t, lookupToken)
	setFakeProfile(f, "2244994945", "XDevelopers", "Developers", `<b>bio</b> & "more"`)
	setFakeProfile(f, "1001", "Alice_Sec", "Alice", "")
	setFakeProfile(f, "5555", "taken_now", "Someone else", "not ours")
	h := newHarness(t, hopt{xlookup: lk})
	adm := h.user("kim", "admin")
	ctx := context.Background()

	resp, b := adm.post("/api/admin/x/accounts", `{"handle":"xdevelopers"}`)
	if resp.StatusCode != 200 {
		t.Fatalf("add: %d %s", resp.StatusCode, b)
	}
	if n, d, ok := profileOfRow(t, h, "2244994945"); !ok || n == nil || *n != "Developers" || d == nil || *d != `<b>bio</b> & "more"` {
		t.Errorf("added profile: %v %v %v", n, d, ok)
	}
	// listed without a lookup: by id, and an id whose handle now belongs to another id
	for _, a := range [][2]string{{"1001", "alice_sec"}, {"4444", "taken_now"}, {"783214", "nobody_here"}} {
		if err := xconfig.InsertAccount(ctx, h.db.Conn, a[0], a[1], ""); err != nil {
			t.Fatal(err)
		}
	}
	before := f.Requests()
	resp, b = adm.post("/api/admin/x/accounts/profiles", "")
	if resp.StatusCode != 200 {
		t.Fatalf("refresh: %d %s", resp.StatusCode, b)
	}
	if strings.Contains(string(b), lookupToken) || strings.Contains(h.logs.String(), lookupToken) {
		t.Error("the token shows")
	}
	if n := f.Requests() - before; n != 1 {
		t.Errorf("%d X API requests, want 1", n)
	}
	var a struct {
		LookedUp int `json:"looked_up"`
		Updated  int `json:"updated"`
		NotFound int `json:"not_found"`
		Missing  int `json:"missing"`
	}
	if err := json.Unmarshal(b, &a); err != nil {
		t.Fatal(err)
	}
	// the three never looked up; the added one was looked up just now (not due)
	if a.LookedUp != 3 || a.Updated != 1 || a.NotFound != 2 || a.Missing != 0 {
		t.Errorf("refresh answer %+v", a)
	}
	if n, _, ok := profileOfRow(t, h, "1001"); !ok || n == nil || *n != "Alice" {
		t.Errorf("1001: %v", n)
	}
	if n, d, ok := profileOfRow(t, h, "4444"); !ok || n != nil || d != nil {
		t.Errorf("4444 got another account's profile: %v %v", n, d)
	}
	if _, _, ok := profileOfRow(t, h, "783214"); !ok {
		t.Error("783214 not marked looked up")
	}
	if n := h.count(`SELECT count(*) FROM admin_audit WHERE action = 'x.account.profiles' AND target_id = 'profiles'`); n != 1 {
		t.Errorf("%d audit rows", n)
	}
	// the page shows them as text only
	_, page := adm.do("GET", "/admin/x", "")
	if strings.Contains(string(page), "<b>bio</b>") || !strings.Contains(string(page), "&lt;b&gt;bio&lt;/b&gt;") {
		t.Error("bio not escaped on the page")
	}
	if strings.Contains(string(page), lookupToken) {
		t.Error("the token shows on the page")
	}

	// no token: refused, nothing written
	h2 := newHarness(t, hopt{})
	adm2 := h2.user("kim", "admin")
	check(t, "no lookup", 503, "x_lookup_off")(adm2.post("/api/admin/x/accounts/profiles", ""))
	check(t, "moderator", 403, "forbidden")(h2.user("lee", "moderator").post("/api/admin/x/accounts/profiles", ""))
	check(t, "body", 400, "bad_request")(adm2.post("/api/admin/x/accounts/profiles", `{"all":true}`))
}

// TestXImportStoresProfile: a handle-only import line stores the profile
// of the id it was looked up as.
func TestXImportStoresProfile(t *testing.T) {
	f, lk := lookupFake(t, lookupToken)
	setFakeProfile(f, "1001", "Alice_Sec", "Alice", "Researcher")
	h := newHarness(t, hopt{xlookup: lk})
	adm := h.user("kim", "admin")
	resp, b := adm.post("/api/admin/x/import", `{"text":"@alice_sec\n","dry_run":false}`)
	if resp.StatusCode != 200 {
		t.Fatalf("import: %d %s", resp.StatusCode, b)
	}
	if n, d, ok := profileOfRow(t, h, "1001"); !ok || n == nil || *n != "Alice" || d == nil || *d != "Researcher" {
		t.Errorf("imported profile: %v %v %v", n, d, ok)
	}
}

type profilesAnswer struct {
	LookedUp int `json:"looked_up"`
	Updated  int `json:"updated"`
	NotFound int `json:"not_found"`
	Failed   int `json:"failed"`
	Missing  int `json:"missing"`
}

func refreshProfiles(t *testing.T, b *browser) profilesAnswer {
	t.Helper()
	resp, body := b.post("/api/admin/x/accounts/profiles", "")
	if resp.StatusCode != 200 {
		t.Fatalf("refresh: %d %s", resp.StatusCode, body)
	}
	var a profilesAnswer
	if err := json.Unmarshal(body, &a); err != nil {
		t.Fatal(err)
	}
	return a
}

// TestXProfilesCooldown: a refresh right after another makes no X request
// and writes nothing; an account looked up more than a day ago is due again.
func TestXProfilesCooldown(t *testing.T) {
	f, lk := lookupFake(t, lookupToken)
	setFakeProfile(f, "1001", "Alice_Sec", "Alice", "first")
	h := newHarness(t, hopt{xlookup: lk})
	adm := h.user("kim", "admin")
	if err := xconfig.InsertAccount(context.Background(), h.db.Conn, "1001", "alice_sec", ""); err != nil {
		t.Fatal(err)
	}
	if a := refreshProfiles(t, adm); a.LookedUp != 1 || a.Updated != 1 {
		t.Fatalf("first refresh %+v", a)
	}
	reqs, audits := f.Requests(), h.count(`SELECT count(*) FROM admin_audit WHERE action = 'x.account.profiles'`)
	if a := refreshProfiles(t, adm); a != (profilesAnswer{}) {
		t.Errorf("second refresh %+v, want zeros", a)
	}
	if n := f.Requests() - reqs; n != 0 {
		t.Errorf("second refresh made %d X requests", n)
	}
	if n := h.count(`SELECT count(*) FROM admin_audit WHERE action = 'x.account.profiles'`); n != audits {
		t.Error("a refresh without a lookup wrote an audit row")
	}
	h.sql(`UPDATE x_accounts SET profile_at = now() - interval '25 hours' WHERE user_id = '1001'`)
	setFakeProfile(f, "1001", "Alice_Sec", "Alice", "second")
	if a := refreshProfiles(t, adm); a.LookedUp != 1 || a.Updated != 1 || f.Requests()-reqs != 1 {
		t.Errorf("stale account: %+v, %d requests", a, f.Requests()-reqs)
	}
	if _, d, _ := profileOfRow(t, h, "1001"); d == nil || *d != "second" {
		t.Errorf("bio %v", d)
	}
}

// TestXProfilesHostile: NUL, other control characters and bidi controls
// in a name or bio are dropped before storing (line breaks become spaces),
// the rest is shown escaped; one account whose profile cannot be stored
// does not keep the others from theirs.
func TestXProfilesHostile(t *testing.T) {
	f, lk := lookupFake(t, lookupToken)
	setFakeProfile(f, "1001", "Alice_Sec", "Al\x00ice‮<i>", "line1\nline2\x07\x7f⁦x⁩ <script>&")
	setFakeProfile(f, "4444", "Bob_Sec", "Bob", "blocked")
	setFakeProfile(f, "5555", "Cat_Sec", "Cat", "fine")
	h := newHarness(t, hopt{xlookup: lk})
	adm := h.user("kim", "admin")
	ctx := context.Background()
	for _, a := range [][2]string{{"1001", "alice_sec"}, {"4444", "bob_sec"}, {"5555", "cat_sec"}} {
		if err := xconfig.InsertAccount(ctx, h.db.Conn, a[0], a[1], ""); err != nil {
			t.Fatal(err)
		}
	}
	// storing 4444's profile fails (not its "looked up" mark)
	h.sql(`CREATE FUNCTION test_profile_fail() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.user_id = '4444' AND NEW.name IS NOT NULL THEN RAISE EXCEPTION 'test failure'; END IF; RETURN NEW; END $$`)
	h.sql(`CREATE TRIGGER test_profile_fail BEFORE UPDATE ON x_accounts FOR EACH ROW EXECUTE FUNCTION test_profile_fail()`)
	a := refreshProfiles(t, adm)
	if a.LookedUp != 3 || a.Updated != 2 || a.Failed != 1 || a.Missing != 0 {
		t.Errorf("answer %+v", a)
	}
	n, d, _ := profileOfRow(t, h, "1001")
	if n == nil || *n != "Alice<i>" || d == nil || *d != "line1 line2x <script>&" {
		t.Errorf("stored %q %q", deref(n), deref(d))
	}
	if n, _, ok := profileOfRow(t, h, "5555"); n == nil || *n != "Cat" || !ok {
		t.Error("the account after the failing one was not stored")
	}
	if _, _, ok := profileOfRow(t, h, "4444"); !ok {
		t.Error("the failing account is not marked looked up")
	}
	if strings.Contains(h.logs.String(), "blocked") {
		t.Error("the profile text was logged")
	}
	_, page := adm.do("GET", "/admin/x", "")
	if strings.Contains(string(page), "<script>&") || !strings.Contains(string(page), "&lt;script&gt;&amp;") {
		t.Error("bio not escaped on the page")
	}
}

func deref(p *string) string {
	if p == nil {
		return "<nil>"
	}
	return *p
}
