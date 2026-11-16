package auth_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"nday.land/nday/internal/auth"
	"nday.land/nday/internal/testutil"
)

func TestShortSubject(t *testing.T) {
	for in, want := range map[string]string{"": "…", "ab": "…", "abc": "a…c", "12345678": "1…8",
		"123456789": "1234…89", "000123456789012345678": "0001…78", "ädöüßéêè9": "ädöü…è9"} {
		if got := auth.ShortSubject(in); got != want {
			t.Errorf("ShortSubject(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestStaffReads: the read-only listings of the admin pages.
func TestStaffReads(t *testing.T) {
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	st := &auth.Store{DB: auth.SingleConn(d.Conn)}
	base := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	mk := func(i int, handle, name string) string {
		var id string
		if err := d.Conn.QueryRow(ctx, `INSERT INTO users (display_name, created_at, last_seen_at) VALUES (nullif($1, ''), $2, $2) RETURNING id::text`,
			name, base.Add(time.Duration(i)*time.Hour)).Scan(&id); err != nil {
			t.Fatal(err)
		}
		if handle != "" {
			key, err := auth.CanonicalHandle(handle)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := st.SetHandle(ctx, id, handle, key, 0); err != nil {
				t.Fatal(err)
			}
		}
		return id
	}
	ada := mk(1, "Ada", "Ada Lovelace")
	mk(2, "adam_s", "")
	bob := mk(3, "bob", "100% _real_ Bob")
	mk(4, "", "Carol")
	names := func(rows []auth.UserRow) string {
		var s []string
		for _, r := range rows {
			if r.Handle != nil {
				s = append(s, *r.Handle)
			} else {
				s = append(s, "-")
			}
		}
		return strings.Join(s, ",")
	}
	for q, want := range map[string]string{"": "-,bob,adam_s,Ada", "ad": "adam_s,Ada", "ADA": "adam_s,Ada", "lovelace": "Ada",
		ada: "Ada", strings.ToUpper(bob): "bob", "%": "bob", "_": "bob", "_real_": "bob", "zzz": "", "d_s": ""} {
		rows, next, err := st.SearchUsers(ctx, q, nil, 10)
		if err != nil {
			t.Fatal(err)
		}
		if got := names(rows); got != want || next != nil {
			t.Errorf("SearchUsers(%q) = %q (next %v), want %q", q, got, next, want)
		}
	}
	// paging, newest first
	p1, next, _ := st.SearchUsers(ctx, "", nil, 3)
	p2, end, _ := st.SearchUsers(ctx, "", next, 3)
	if names(p1) != "-,bob,adam_s" || next == nil || names(p2) != "Ada" || end != nil {
		t.Errorf("paging: %s / %s", names(p1), names(p2))
	}
	// summary: shortened subjects, counts of passkeys and live sessions
	for _, q := range []string{`INSERT INTO identities (provider, subject, user_id, handle) VALUES ('github', '1234567890', $1, 'ada-gh')`,
		`INSERT INTO passkeys (user_id, credential_id, public_key, algorithm, backup_eligible, backed_up, name) VALUES ($1, '\x01', '\x02', -7, false, false, 'k')`,
		`INSERT INTO sessions (token_hash, user_id, created_at, last_seen_at, expires_at) VALUES
		  (sha256('a'), $1, now(), now(), now() + interval '1 day'),
		  (sha256('b'), $1, now() - interval '30 days', now() - interval '20 days', now() + interval '1 day'),
		  (sha256('c'), $1, now() - interval '2 days', now() - interval '1 day', now() - interval '1 s')`} {
		if _, err := d.Conn.Exec(ctx, q, ada); err != nil {
			t.Fatal(err)
		}
	}
	sum, err := st.Summary(ctx, ada, 14*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(sum.Identities) != 1 || sum.Identities[0].SubjectShort != "1234…90" || *sum.Identities[0].Handle != "ada-gh" ||
		sum.Passkeys != 1 || sum.ActiveSessions != 1 {
		t.Errorf("summary: %+v %+v", sum, sum.Identities)
	}
}
