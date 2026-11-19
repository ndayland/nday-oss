package cli

import (
	"testing"

	"nday.land/nday/internal/ghrepo"
)

// The GitHub steps after `nday collect xposts` have their own deadline and
// the same small cap as the page steps.
func TestPostRunGitHubBounds(t *testing.T) {
	if postRunGitHubTimeout != postRunPagesTimeout || postRunGitHubLimit != postRunPagesLimit ||
		postRunGitHubLimit >= ghrepo.DefaultLimit || postRunGitHubRefresh > postRunGitHubLimit {
		t.Errorf("bounds %v %d %d", postRunGitHubTimeout, postRunGitHubLimit, postRunGitHubRefresh)
	}
}
