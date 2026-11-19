package ghrepo

import (
	"context"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5"
)

// Test hooks for the external DB tests (package ghrepo_test, which may
// import internal/testutil without an import cycle).

// TestServer is the TLS fake of api.github.com (client_test.go).
type TestServer = apiServer

// NewTestServer starts a fake api.github.com.
func NewTestServer(t *testing.T, h http.HandlerFunc) *TestServer { return newAPIServer(t, h) }

// Client returns a Client that reaches the fake.
func (a *apiServer) Client(token string) *Client { return a.client(token) }

// Queue is queue.
var Queue = queue

// SetDecode replaces the response decoder of a pass.
func SetDecode(o *Options, f func([]byte) (*Repo, error)) { o.decode = f }

// StoreSearched is storeSearched.
var StoreSearched = storeSearched

// SetSearchDecode replaces the search page decoder of a Discover run.
func SetSearchDecode(o *DiscoverOptions, f func([]byte) (*SearchPage, error)) { o.decode = f }

// StoreLockID is storeLockID.
const StoreLockID = storeLockID

// HoldName is holdName in a transaction of its own.
func HoldName(ctx context.Context, db DB, id int64) error {
	return pgx.BeginFunc(ctx, db, func(tx pgx.Tx) error { return holdName(ctx, tx, id) })
}
