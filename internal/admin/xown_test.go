package admin_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"nday.land/nday/internal/xconfig"
)

// TestXOwnAccountRefused: the site's own X account (@ndayland) cannot get
// onto the allowlist by any admin route: 422 own_account, nothing written,
// no audit row, and an add by its handle makes no X request.
func TestXOwnAccountRefused(t *testing.T) {
	f, lk := lookupFake(t, lookupToken)
	h := newHarness(t, hopt{xlookup: lk})
	h.xCandFixture()
	adm := h.user("kim", "admin")
	ctx := context.Background()
	audits := func() int { return h.count(`SELECT count(*) FROM admin_audit`) }
	rows := func() int { return h.count(`SELECT count(*) FROM x_accounts`) }
	baseRows := rows() // 1001 alice from the fixture

	// add by id and handle
	check(t, "add by id", 422, "own_account")(adm.post("/api/admin/x/accounts", `{"user_id":"5555","handle":"ndayland","note":""}`))
	check(t, "add by id, other case", 422, "own_account")(adm.post("/api/admin/x/accounts", `{"user_id":"5555","handle":"@NDAYLAND","note":""}`))
	before := f.Requests()
	check(t, "add by handle", 422, "own_account")(adm.post("/api/admin/x/accounts", `{"handle":"NdayLand","note":""}`))
	if n := f.Requests() - before; n != 0 {
		t.Errorf("an add of the own handle made %d X requests", n)
	}
	// update of a listed account to the own handle
	check(t, "update", 422, "own_account")(adm.post("/api/admin/x/accounts/1001/update", `{"handle":"ndayland","note":""}`))

	// candidate add (a candidate row inserted behind the collector's checks)
	h.sql(`INSERT INTO x_account_candidate (user_id, handle, first_seen_at, last_seen_at) VALUES ('6001', 'NdayLand', '2026-11-01', '2026-11-10')`)
	h.sql(`INSERT INTO x_account_candidate_ref (user_id, post_id, referrer_id, kind, posted_at) VALUES ('6001', '11', '1001', 'mentioned', '2026-11-10')`)
	check(t, "candidate add", 422, "own_account")(adm.post("/api/admin/x/candidates/6001/add", ""))
	// ... and it is not on the page nor counted
	_, page := adm.do("GET", "/admin/x", "")
	if strings.Contains(string(page), `data-cand="6001"`) {
		t.Error("the own account is listed as a candidate")
	}
	if n, _ := xconfig.CountCandidates(ctx, h.db.Conn, ""); n != 4 { // the fixture's 3001 3002 3003 3005
		t.Errorf("open candidates: %d, want 4", n)
	}

	// a row inserted behind the checks cannot be enabled
	h.sql(`INSERT INTO x_accounts (user_id, handle, enabled) VALUES ('5555', 'NdayLand', false)`)
	baseRows++
	check(t, "enable", 422, "own_account")(adm.post("/api/admin/x/accounts/5555/enable", ""))

	// import: a line error like any invalid line, nothing applied
	for _, text := range []string{"1002 NdayLand\n", "@ndayland\n", "bob_x 1\n9 ok_user\n7 @NDAYLAND  # me\n"} {
		j, _ := json.Marshal(map[string]any{"text": text, "dry_run": false})
		resp, body := adm.post("/api/admin/x/import", string(j))
		check(t, "import "+text, 400, "bad_import")(resp, body)
		if !strings.Contains(string(body), "own X account") {
			t.Errorf("import %q: %s", text, body)
		}
	}
	if rows() != baseRows || audits() != 0 {
		t.Errorf("a refused request wrote something: %d rows (was %d), %d audit rows", rows(), baseRows, audits())
	}

	// a harmless handle that merely contains the own one still works
	check(t, "similar handle", 200, "")(adm.post("/api/admin/x/accounts", `{"user_id":"42","handle":"ndayland2","note":""}`))
}
