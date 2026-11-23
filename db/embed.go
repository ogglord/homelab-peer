// Package db holds the hub's SQL: the schema the store applies and the
// queries sqlc generates internal/store from.
package db

import _ "embed"

// Schema is the whole schema of a fresh database.
//
//go:embed schema.sql
var Schema string
