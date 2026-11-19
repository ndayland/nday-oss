package xlookup_test

import (
	"context"
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
