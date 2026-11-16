package cli

import (
	"testing"
	"time"

	"nday.land/nday/internal/webpages"
)

// The page steps after `nday collect xposts` are bounded more tightly than
// the manual `nday pages-fetch` (whose default is webpages.DefaultLimit).
func TestPostRunPagesBounds(t *testing.T) {
	if postRunPagesTimeout != 2*time.Minute || postRunPagesLimit != 25 || postRunPagesLimit >= webpages.DefaultLimit {
		t.Errorf("bounds %v %d", postRunPagesTimeout, postRunPagesLimit)
	}
}
