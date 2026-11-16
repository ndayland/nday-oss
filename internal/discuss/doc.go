// Package discuss is nday's per-vulnerability discussion backend: one
// comment stream per vulnerability (replies one level deep), a small
// Markdown subset (package md), post-moderation (reports, moderators hiding
// comments, suspension) and rate limits. The contract for the pages and
// scripts is docs/discuss.md.
//
// Routes (site host only, registered by Service.Register; every response is
// Cache-Control: no-store with Vary: Cookie; JSON errors as in internal/web):
//
//	GET  /api/discuss/{cve}                       stream + per-caller fields
//	POST /api/discuss/{cve}                       {"body","parent_id"?,"lang"}
//	POST /api/discuss/comment/{id}/edit           {"body"}           author
//	POST /api/discuss/comment/{id}/delete                            author (also while suspended)
//	POST /api/discuss/comment/{id}/report         {"reason","note"?} anyone active but the author
//	POST /api/discuss/comment/{id}/hide|unhide    {"reason"} / -     moderator, admin
//	GET  /api/mod/reports?state=open|resolved                        moderator, admin
//	POST /api/mod/reports/{id}/resolve            {"resolution"}     moderator, admin
//	GET  /api/mod/recent                                             moderator, admin
//	GET  /api/mod/comment/{id}/revisions                             moderator, admin
//
// Sessions, same-origin + CSRF, suspension and roles come from
// internal/auth's middlewares (Load, RequireUser, RequireActive,
// RequireRole); the feature exists only when accounts are enabled.
//
// For the page renderer: Service.Stream (public data only, independent of
// the request) and Service.Version (cache key).
package discuss
