package peerclient

import (
	"log/slog"
	"testing"
)

// A frame for the run in progress is dropped as a repeat unless it moved
// the request on (the approval of the step that run parked on); a frame for
// a queued request replaces it unless it is older.
func TestPushDedupe(t *testing.T) {
	t.Parallel()
	r := &runner{log: slog.New(slog.DiscardHandler), wake: make(chan struct{}, 1)}
	r.current = RequestFrame{ID: "a", State: "delivered", Attempt: 0}

	r.push(RequestFrame{ID: "a", State: "waiting", Attempt: 0})
	r.push(RequestFrame{ID: "a", State: "delivered", Attempt: 0})
	if len(r.queue) != 0 {
		t.Fatalf("repeat of the current frame queued: %+v", r.queue)
	}
	approved := RequestFrame{ID: "a", State: StateApproved, Attempt: 1, ApprovalCycles: 1}
	r.push(approved)
	r.push(RequestFrame{ID: "a", State: "delivered", Attempt: 0}) // a late repeat of the run's own frame
	if len(r.queue) != 1 || r.queue[0].Attempt != 1 || r.queue[0].State != StateApproved {
		t.Fatalf("queue %+v, want only the approval", r.queue)
	}
	r.push(approved)
	if len(r.queue) != 1 {
		t.Fatalf("approval queued twice: %+v", r.queue)
	}
}
