package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

// A fresh file gets the schema once; opening it again keeps its rows, and a
// database of another schema version is refused.
func TestOpenCreatesSchemaOnce(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p := filepath.Join(t.TempDir(), "peer.db")
	s, err := Open(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetMeta(ctx, "k", "v"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if s, err = Open(ctx, p); err != nil {
		t.Fatal(err)
	}
	if v, ok, err := s.Meta(ctx, "k"); err != nil || !ok || v != "v" {
		t.Fatalf("meta after reopen: %q %v %v", v, ok, err)
	}
	if _, err := s.db.ExecContext(ctx, "PRAGMA user_version = 7"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if _, err := Open(ctx, p); err == nil {
		t.Fatal("a database at schema version 7 was opened")
	}
}

// Prune removes terminal requests (leaf first) and their messages past 90
// days, standalone status past 90 days and outcomes past 7, and keeps the
// rest.
func TestPruneRetention(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(t.TempDir(), "peer.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	old := now.Add(-MessageRetention - time.Hour).UnixMilli()
	recent := now.Add(-time.Hour).UnixMilli()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := s.db.ExecContext(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	req := `INSERT INTO peer_requests (id, sender, target, text, state, expires_at, parent_id, reason, created_at, updated_at)
		VALUES (?, 'a', 'b', 't', ?, ?, ?, ?, ?, ?)`
	exec(req, "parent", "done", nil, nil, nil, old, old)
	exec(req, "child", "failed", nil, "parent", "timeout", old, old)
	exec(req, "fresh", "done", nil, nil, nil, recent, recent)
	exec(req, "open", "waiting", recent, nil, nil, old, old)
	msg := `INSERT INTO peer_messages (id, kind, request_id, sender, target, phase, created_at) VALUES (?, ?, ?, 'a', 'b', ?, ?)`
	exec(msg, "m-parent", "result", "parent", nil, old)
	exec(msg, "m-open", "result", "open", nil, old)
	exec(msg, "m-standalone", "status", nil, "info", old)
	exec(msg, "m-recent", "status", nil, "info", recent)
	out := `INSERT INTO peer_message_outcomes (sender, id, kind, target, outcome, created_at) VALUES ('a', ?, 'status', 'b', 'stored', ?)`
	exec(out, "o-old", now.Add(-OutcomeRetention-time.Hour).UnixMilli())
	exec(out, "o-new", recent)

	st, err := s.Prune(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if st != (PruneStats{Requests: 2, Messages: 2, Outcomes: 1}) {
		t.Fatalf("pruned %+v", st)
	}
	ids := func(q string) []string {
		t.Helper()
		rows, err := s.db.QueryContext(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var id sql.NullString
			if err := rows.Scan(&id); err != nil {
				t.Fatal(err)
			}
			out = append(out, id.String)
		}
		return out
	}
	if got := ids("SELECT id FROM peer_requests ORDER BY id"); len(got) != 2 || got[0] != "fresh" || got[1] != "open" {
		t.Errorf("requests left %v", got)
	}
	if got := ids("SELECT id FROM peer_messages ORDER BY id"); len(got) != 2 || got[0] != "m-open" || got[1] != "m-recent" {
		t.Errorf("messages left %v", got)
	}
	if got := ids("SELECT id FROM peer_message_outcomes"); len(got) != 1 || got[0] != "o-new" {
		t.Errorf("outcomes left %v", got)
	}
}
