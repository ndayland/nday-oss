package xlookup_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"nday.land/nday/internal/xlookup"
	"nday.land/nday/internal/xlookup/xfake"
)

// TestProfileFields: the lookup asks for the description (user.fields) and
// returns the display name and the description X sent, as is.
func TestProfileFields(t *testing.T) {
	const token = "PROFILE-TOKEN-1"
	f := xfake.New(token)
	f.Users["alice_sec"] = xfake.User{ID: "1001", Username: "Alice_Sec", Name: "Alice <b>", Description: "bio & \"more\""}
	c, err := xlookup.New(xlookup.Options{Token: token, Transport: f.Transport()})
	if err != nil {
		t.Fatal(err)
	}
	r, err := c.LookupOne(context.Background(), "alice_sec")
	if err != nil {
		t.Fatal(err)
	}
	if r.Outcome != xlookup.Found || r.ID != "1001" || r.Name != "Alice <b>" || r.Description != "bio & \"more\"" {
		t.Errorf("result %+v", r)
	}
}

// TestProfilesByID: one request to /2/users with the ids and the profile
// fields; users X does not return (suspended, unknown) are listed as
// missing; ids are checked before anything is sent; 429 is ErrRateLimited.
func TestProfilesByID(t *testing.T) {
	const token = "PROFILE-TOKEN-2"
	f := xfake.New(token)
	f.Users["alice"] = xfake.User{ID: "1001", Username: "Alice", Name: "Alice A", ProfileImageURL: "https://pbs.twimg.com/profile_images/1/a.jpg"}
	f.Users["gone"] = xfake.User{ID: "1002", Username: "gone"}
	f.Suspended["gone"] = true
	f.Users["slowpoke"] = xfake.User{ID: "1004", Username: "slowpoke"}
	f.RateLimited["slowpoke"] = true
	c, err := xlookup.New(xlookup.Options{Token: token, Transport: f.Transport()})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	got, missing, err := c.ProfilesByID(ctx, []string{"1001", "1002", "1003"})
	if err != nil || len(got) != 1 || got["1001"] != (xlookup.Profile{ID: "1001", Handle: "Alice", Name: "Alice A",
		ProfileImageURL: "https://pbs.twimg.com/profile_images/1/a.jpg"}) || strings.Join(missing, ",") != "1002,1003" {
		t.Fatalf("%+v %v %v", got, missing, err)
	}
	if q := f.Queries(); len(q) != 1 || q[0] != "1001,1002,1003" {
		t.Errorf("queries %v", q)
	}
	for _, ids := range [][]string{{"1001", "01"}, {"1001", "1&x=1"}, {}, make([]string, 101)} {
		if _, _, err := c.ProfilesByID(ctx, ids); err == nil {
			t.Errorf("%v accepted", ids)
		}
	}
	if f.Requests() != 1 {
		t.Errorf("invalid ids reached X: %d requests", f.Requests())
	}
	if _, _, err := c.ProfilesByID(ctx, []string{"1004"}); !errors.Is(err, xlookup.ErrRateLimited) {
		t.Errorf("429: %v", err)
	}
	none, _ := xlookup.New(xlookup.Options{Transport: f.Transport()})
	if _, _, err := none.ProfilesByID(ctx, []string{"1001"}); !errors.Is(err, xlookup.ErrNotConfigured) {
		t.Errorf("no token: %v", err)
	}
}
