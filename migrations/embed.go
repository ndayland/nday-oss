// Package migrations embeds the SQL migrations (the single source of truth,
// shared with the Python implementation) into the Go binary.
package migrations

import "embed"

// FS holds every NNNN_description.sql file of this directory.
//
//go:embed *.sql
var FS embed.FS
