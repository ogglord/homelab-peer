// Package store is the hub's SQLite database: the sqlc queries generated
// from db/queries, the schema in db/schema.sql, transactions and the
// retention prune.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite" // registers the pure-Go "sqlite" driver

	"github.com/ogglord/homelab-peer/db"
)

// schemaVersion is PRAGMA user_version of a database this binary created.
// A database at another version is refused: there is no migration yet.
const schemaVersion = 1

// Retention: terminal requests and their messages, and standalone status,
// go after 90 days; message outcomes (the idempotency window) after 7.
const (
	MessageRetention = 90 * 24 * time.Hour
	OutcomeRetention = 7 * 24 * time.Hour
)

// Store is the hub's database. It is safe for concurrent use.
type Store struct {
	db *sql.DB
	q  *Queries
}

// Open opens the database at path, creating it with the schema when it is
// new.
func Open(ctx context.Context, path string) (*Store, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	qv := url.Values{}
	qv.Add("_pragma", "journal_mode(WAL)")
	qv.Add("_pragma", "busy_timeout(5000)")
	qv.Add("_pragma", "synchronous(NORMAL)")
	qv.Add("_pragma", "foreign_keys(ON)")
	qv.Set("_txlock", "immediate")
	u := url.URL{Scheme: "file", Path: abs, RawQuery: qv.Encode()}
	sdb, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	if err := initSchema(ctx, sdb); err != nil {
		sdb.Close()
		return nil, fmt.Errorf("store: open %s: %w", abs, err)
	}
	return &Store{db: sdb, q: New(sdb)}, nil
}

func initSchema(ctx context.Context, sdb *sql.DB) error {
	tx, err := sdb.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var v int
	if err := tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&v); err != nil {
		return err
	}
	switch v {
	case schemaVersion:
		return nil
	case 0:
	default:
		return fmt.Errorf("schema version %d, this binary knows %d", v, schemaVersion)
	}
	if _, err := tx.ExecContext(ctx, db.Schema); err != nil {
		return fmt.Errorf("schema: %w", err)
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", schemaVersion)); err != nil {
		return err
	}
	return tx.Commit()
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// Queries returns the generated queries bound to the pool (autocommit).
func (s *Store) Queries() *Queries { return s.q }

// Tx runs fn in a write transaction (BEGIN IMMEDIATE), committing if fn
// returns nil and rolling back otherwise.
func (s *Store) Tx(ctx context.Context, fn func(*Queries) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(s.q.WithTx(tx)); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// Meta returns the meta value for key; ok is false if unset.
func (s *Store) Meta(ctx context.Context, key string) (string, bool, error) {
	v, err := s.q.GetMeta(ctx, key)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return v, true, nil
}

// SetMeta upserts a meta value.
func (s *Store) SetMeta(ctx context.Context, key, value string) error {
	return s.q.SetMeta(ctx, SetMetaParams{Key: key, Value: value})
}

// PruneStats reports rows removed by Prune.
type PruneStats struct {
	Requests, Messages, Outcomes int64
}

// Prune deletes what is past retention at now: terminal requests no
// remaining request names as parent (repeated until none goes, leaf first,
// since parent_id restricts), then messages that belong to no remaining
// request, then outcomes. The hub's expiry sweep runs before it, so a due
// request ends with its result message before the prune looks at it.
func (s *Store) Prune(ctx context.Context, now time.Time) (PruneStats, error) {
	cutoff := now.Add(-MessageRetention).UnixMilli()
	var st PruneStats
	err := s.Tx(ctx, func(q *Queries) error {
		st = PruneStats{}
		for {
			n, err := q.PrunePeerRequests(ctx, cutoff)
			if err != nil {
				return err
			}
			if n == 0 {
				break
			}
			st.Requests += n
		}
		var err error
		if st.Messages, err = q.PrunePeerMessages(ctx, cutoff); err != nil {
			return err
		}
		st.Outcomes, err = q.PrunePeerOutcomes(ctx, now.Add(-OutcomeRetention).UnixMilli())
		return err
	})
	return st, err
}
