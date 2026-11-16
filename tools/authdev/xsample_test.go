package main

import (
	"context"
	"io"
	"log/slog"
	"slices"
	"testing"

	"nday.land/nday/internal/testutil"
	"nday.land/nday/internal/xconfig"
)

// TestXSampleCandidates: -x-sample lists the sample candidates (one
// without a handle, one dismissed) and a re-run keeps what an admin did.
func TestXSampleCandidates(t *testing.T) {
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ids := func(status string) []string {
		t.Helper()
		cs, err := xconfig.ListCandidates(ctx, d.Conn, status, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, c := range cs {
			h := "-"
			if c.Handle != nil {
				h = *c.Handle
			}
			out = append(out, c.UserID+" "+h)
		}
		return out
	}
	if err := xSample(ctx, d.URL, log); err != nil {
		t.Fatal(err)
	}
	if got, want := ids("pending"), []string{"4001 ivan_re", "4002 judy_bugs", "4003 -"}; !slices.Equal(got, want) {
		t.Errorf("pending %v, want %v", got, want)
	}
	if got := ids("dismissed"); !slices.Equal(got, []string{"4004 mallory_x"}) {
		t.Errorf("dismissed %v", got)
	}
	if _, err := xconfig.DismissCandidate(ctx, d.Conn, "4002"); err != nil {
		t.Fatal(err)
	}
	if err := xSample(ctx, d.URL, log); err != nil {
		t.Fatal(err)
	}
	if got := ids("pending"); !slices.Equal(got, []string{"4001 ivan_re", "4003 -"}) {
		t.Errorf("after a re-run: %v", got)
	}
}
