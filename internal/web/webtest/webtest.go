// Package webtest has test helpers for servers built on internal/web.
package webtest

import (
	"net/http"

	"nday.land/nday/internal/web"
)

// TestAPIToken is the only API token BearerAuth accepts.
const TestAPIToken = "nday_test-token-for-package-tests"

// BearerAuth is a web.APIAuth for tests of packages that run the server
// without internal/auth: it accepts exactly
// "Authorization: Bearer <TestAPIToken>" (in every mode) and answers
// 401 token_required otherwise. The real authenticator (auth.Service) has
// its own tests (internal/auth/apitoken_test.go).
type BearerAuth struct{}

// AuthenticateData implements web.APIAuth.
func (BearerAuth) AuthenticateData(w http.ResponseWriter, r *http.Request, _ web.AuthMode) (http.ResponseWriter, *http.Request, bool) {
	if r.Header.Get("Authorization") == "Bearer "+TestAPIToken {
		return w, r, true
	}
	web.WriteUnauthorized(w, "token_required", web.MsgTokenRequired)
	return nil, nil, false
}
