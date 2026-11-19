package ghrepo_test

import (
	"testing"

	"nday.land/nday/internal/ghrepo"
)

// TestParseReviewSort: only the six orders are read; anything else is the
// default order, which has no parameter.
func TestParseReviewSort(t *testing.T) {
	for in, want := range map[string]ghrepo.ReviewSort{
		"stars": {By: "stars"}, "-stars": {By: "stars", Desc: true}, "flags": {By: "flags"}, "-flags": {By: "flags", Desc: true},
		"found": {By: "found"}, "-found": {By: "found", Desc: true},
		"": {}, "-": {}, "--stars": {}, "Stars": {}, " stars": {}, "stars,flags": {}, "id": {}, "-id": {}, "r.id": {},
	} {
		got := ghrepo.ParseReviewSort(in)
		if got != want {
			t.Errorf("%q: %+v, want %+v", in, got, want)
		}
		if s := got.String(); (want == ghrepo.ReviewSort{}) && s != "" || (want != ghrepo.ReviewSort{}) && s != in {
			t.Errorf("%q: String %q", in, s)
		}
	}
}
