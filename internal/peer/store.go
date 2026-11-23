package peer

import (
	"context"
	"time"
)

// Store is the hub's persistence.
type Store interface {
	// Hello replaces host's instance when startedAt is at or after the
	// stored start; false means a newer instance holds the host.
	Hello(ctx context.Context, host, instance string, startedAt, now time.Time) (bool, error)
	Host(ctx context.Context, name string) (Host, bool, error)
	Hosts(ctx context.Context) ([]Host, error)
	// Ack advances host's acknowledged sequence (never backwards) and marks
	// its messages up to seq delivered.
	Ack(ctx context.Context, host string, seq int64) error

	// AcceptStatus stores m and a 'stored' outcome in one transaction and
	// returns its sequence. When sender plus id already has an outcome it
	// writes nothing and returns that outcome instead.
	AcceptStatus(ctx context.Context, m Message) (seq int64, prev *Outcome, err error)
	Message(ctx context.Context, sender, id string) (Message, bool, error)
	// Replay is target's status and results after the cursor, in sequence
	// order, in one read statement.
	Replay(ctx context.Context, target string, after int64, limit int) ([]Message, error)
	Inbox(ctx context.Context, target string, limit int) ([]Message, error)
	MarkRead(ctx context.Context, seq int64) error

	RecentMessages(ctx context.Context, limit int) ([]Message, error)
	RecentOutcomes(ctx context.Context, limit int) ([]Outcome, error)

	// CreateRequest stores r (waiting) and a 'stored' outcome for its
	// sender and id in one transaction. When sender plus id already has an
	// outcome it writes nothing and returns it as prev; when the id already
	// names a request (any sender) it returns that as existing.
	CreateRequest(ctx context.Context, r Request) (prev *Outcome, existing *Request, err error)
	Request(ctx context.Context, id string) (Request, bool, error)
	RequestByToken(ctx context.Context, tokenHash string) (Request, bool, error)
	// PushableRequests is target's waiting and approved requests, oldest first.
	PushableRequests(ctx context.Context, target string) ([]Request, error)
	MarkDelivered(ctx context.Context, id string, attempt int64, now time.Time) (bool, error)
	// Requeue returns delivered requests pushed at or before deliveredBefore
	// to the queue, for target ("" for every host), and returns their hosts.
	Requeue(ctx context.Context, target string, deliveredBefore, now time.Time) ([]string, error)
	// ClaimRequest is the claim compare-and-set. Errors: ErrUnknownRequest,
	// ErrNotPermitted (another host's request), ErrHelloRequired,
	// ErrSuperseded (not the host's current instance), ErrBusy (the host
	// has a running request; the host's delivered requests are requeued in
	// the same transaction), ErrNotClaimable.
	ClaimRequest(ctx context.Context, c ClaimSpec) (Request, error)
	// ParkRequest is the park compare-and-set, recording the run's cost and
	// time. A park of a request already parked by the same attempt,
	// instance and token (the listener's report after the hook's park)
	// records only the cost and time and reports true. Errors:
	// ErrUnknownRequest, ErrNotPermitted, ErrNotRunning, ErrSuperseded,
	// ErrRunToken.
	ParkRequest(ctx context.Context, p ParkSpec) (Request, bool, error)
	// PostResult finishes a running request from its run's result,
	// recording the run's cost and time; a request that is not running is
	// discarded (true) and nothing is recorded. Errors: ErrUnknownRequest,
	// ErrNotPermitted, ErrSuperseded (running under another attempt or
	// instance).
	PostResult(ctx context.Context, r ResultSpec) (Request, *Message, bool, error)
	// FinishRequest is the terminal compare-and-set plus its result message
	// in one transaction; false when the guard did not hold.
	FinishRequest(ctx context.Context, f FinishSpec) (bool, Request, *Message, error)
	RunningRequests(ctx context.Context, target string) ([]Request, error)
	// DueRequests is every non-terminal request whose expiry is at or
	// before now.
	DueRequests(ctx context.Context, now time.Time) ([]Request, error)
	// RunningHosts is every host with a running request.
	RunningHosts(ctx context.Context) ([]string, error)
	RecentRequests(ctx context.Context, limit int) ([]Request, error)
	RequestsInState(ctx context.Context, state RequestState, limit int) ([]Request, error)

	// DecideRequest applies a decision in one transaction: approve is the
	// parked -> approved compare-and-set on the round and fingerprint (a
	// limit park's allowance raised in the same statement), deny finishes
	// the request as denied and returns its result message. A refusal is a
	// DecisionRefused and changes nothing.
	DecideRequest(ctx context.Context, d DecideSpec) (Request, *Message, error)
	// UnnotifiedParked is every parked request whose current round's prompt
	// was not delivered.
	UnnotifiedParked(ctx context.Context) ([]Request, error)
	// MarkNotified records the delivery of a parked request's prompt for
	// round; false when it moved on or was already recorded.
	MarkNotified(ctx context.Context, id string, round int64, promptID string, now time.Time) (bool, error)

	// Approver is the enrolled approver phone; false when none is.
	Approver(ctx context.Context) (Approver, bool, error)
	// SetApprover stores a, replacing any earlier approver (nil removes
	// it), and in the same transaction moves every parked request to a new
	// round, not prompted yet: the old round's prompt was signed for by the
	// old phone. It returns those requests as they were, for withdrawing
	// their prompts.
	SetApprover(ctx context.Context, a *Approver, now time.Time) ([]Request, error)
}
