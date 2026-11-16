// Package auth is nday's identity layer: sign-in with Google, Apple
// (OpenID Connect), GitHub and X (OAuth 2.0), account linking, sessions,
// and the account endpoints. The design, threat model and owner's setup
// guide are in docs/auth.md.
//
// Routes (registered by Service.Register; all responses Cache-Control:
// no-store; nothing else on the site reads the session cookie):
//
//	GET  /auth/{provider}/start?return=/path[&ticket=T]   (GET only; HEAD is 405)
//	GET  /auth/{provider}/callback        -> 303 to return path + ?auth=ok|linked|denied|conflict|error|
//	                                         signed_in_as_other|reauth_required|suspended
//	GET  /api/me
//	POST /auth/{provider}/ticket          {"intent":"link"|"switch"|"reauth"} -> single-use start URL
//	                                      (only a reauth ticket, or a passkey sign-in, refreshes the
//	                                      session of a signed-in browser)
//	POST /auth/signout | /auth/signout-all | /auth/{provider}/unlink
//	POST /account/delete | /account/locale | /account/handle | /account/accept-terms
//
// # For future features
//
// Users are referenced by UserID (users.id, a random UUID). A table that
// stores something a user authored references the user as
//
//	author_id uuid REFERENCES users (id) ON DELETE SET NULL
//
// so that deleting an account anonymises the content instead of deleting
// it (only users, identities, sessions use ON DELETE CASCADE).
//
// Handlers get the user through the middlewares of *Service (nil-safe):
//
//	svc.Load(h)                 CurrentUser(r) may be nil
//	svc.RequireUser(h)          401 when signed out; non-GET also needs same-origin + X-CSRF-Token
//	svc.RequireActive(h)        RequireUser + 403 for suspended users (use for every write)
//	svc.RequireRole("moderator")(h)
//
// Whenever the request carries a session cookie their FINAL response is
// no-store (+ Vary: Cookie, no ETag/Last-Modified), whatever the wrapped
// handler sets. Still never wrap public, cacheable pages; let those learn
// the sign-in state from GET /api/me in the browser.
//
// Only the configured public host is served (other Host: 421 wrong_host).
package auth
