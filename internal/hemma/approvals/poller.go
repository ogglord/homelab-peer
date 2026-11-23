// Package approvals connects the peer hub's approval rounds to Hemma: the
// Prompter sends a prompt for every park, and the Poller long-polls the
// phones' signed decisions, verifies each against the enrolled key and
// applies it through the peer service, then reports the outcome.
package approvals

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/ogglord/homelab-peer/internal/hemma"
	"github.com/ogglord/homelab-peer/internal/peer"
)

// Store meta keys.
const (
	// MetaCursor is the last decisions cursor processed.
	MetaCursor = "hemma_decision_cursor"
	// metaApplied lists the latest applied (request, round, fingerprint)
	// keys, so a replayed decision reports applied again instead of the
	// refusal ApplyDecision gives a request that already left parked.
	metaApplied = "hemma_applied_decisions"
)

const (
	// DefaultWait is how long the hub holds a decisions poll (its cap).
	DefaultWait = 25 * time.Second
	minBackoff  = time.Second
	maxBackoff  = time.Minute
	// keepApplied bounds metaApplied; a replay older than this many
	// approvals is refused (409 once the hub reported it applied).
	keepApplied = 256
)

// Refusal notes the phone shows.
const (
	noteNoApprover   = "no phone is enrolled on the homelab"
	noteNotEnrolled  = "signed by a phone that is not enrolled"
	noteBadSignature = "the signature does not verify"
	noteBadDecision  = "unknown decision"
)

// Hub is the peer service: the enrolled phone and the decision it applies.
type Hub interface {
	Approvers
	ApplyDecision(ctx context.Context, d peer.Decision) (peer.Request, error)
}

// Meta is the runtime store's meta table.
type Meta interface {
	Meta(ctx context.Context, key string) (string, bool, error)
	SetMeta(ctx context.Context, key, value string) error
}

// Poller fetches and applies decisions.
type Poller struct {
	Client *hemma.Client
	Hub    Hub
	Meta   Meta
	// Wait is how long each poll lets the hub hold; DefaultWait in Run
	// when zero.
	Wait time.Duration
	Log  *slog.Logger
}

// Run polls until ctx ends, backing off (1 s doubling to 1 min) while
// polls fail.
func (p *Poller) Run(ctx context.Context) {
	if p.Wait == 0 {
		p.Wait = DefaultWait
	}
	var backoff time.Duration
	for ctx.Err() == nil {
		err := p.poll(ctx)
		if err == nil {
			backoff = 0
			continue
		}
		if ctx.Err() != nil {
			return
		}
		backoff = nextBackoff(backoff)
		p.log().Warn("hemma: decisions poll failed", "error", err, "retry_in", backoff)
		select {
		case <-ctx.Done():
		case <-time.After(backoff):
		}
	}
}

func nextBackoff(d time.Duration) time.Duration {
	if d == 0 {
		return minBackoff
	}
	return min(2*d, maxBackoff)
}

// poll fetches the decisions after the stored cursor, handles each, and
// stores the new cursor only once all of them were handled: a failure
// leaves the cursor, and the hub hands the batch out again.
func (p *Poller) poll(ctx context.Context) error {
	after, err := p.cursor(ctx)
	if err != nil {
		return err
	}
	batch, err := p.Client.Decisions(ctx, after, p.Wait)
	if err != nil {
		return err
	}
	for _, d := range batch.Decisions {
		if err := p.handle(ctx, d); err != nil {
			return err
		}
	}
	if batch.Cursor == after {
		return nil
	}
	return p.Meta.SetMeta(ctx, MetaCursor, strconv.FormatInt(batch.Cursor, 10))
}

func (p *Poller) cursor(ctx context.Context) (int64, error) {
	v, ok, err := p.Meta.Meta(ctx, MetaCursor)
	if err != nil || !ok {
		return 0, err
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 0 {
		p.log().Warn("hemma: stored decisions cursor is not a number; starting over", "value", v)
		return 0, nil
	}
	return n, nil
}

// handle verifies, applies and reports one decision. An error (the store,
// or a state report that may succeed later) leaves it to be handled again.
func (p *Poller) handle(ctx context.Context, d hemma.Decision) error {
	state, note, err := p.decide(ctx, d)
	if err != nil {
		return err
	}
	if state == hemma.StateRefused {
		p.log().Info("hemma: decision refused", "request_id", d.Request, "round", d.Round, "approval_id", d.ID, "note", note)
	}
	err = p.Client.PostState(ctx, d.ID, state, note)
	var se *hemma.StatusError
	if errors.As(err, &se) && se.Status >= 400 && se.Status < 500 && se.Status != http.StatusTooManyRequests {
		// The hub will not take this report, now or later (409 already
		// counts as reported).
		p.log().Warn("hemma: approval state not taken", "approval_id", d.ID, "state", state, "error", err)
		return nil
	}
	return err
}

// decide returns the state to report for d, applying it when it is the
// enrolled phone's valid decision on a round not applied before.
func (p *Poller) decide(ctx context.Context, d hemma.Decision) (state, note string, err error) {
	a, ok, err := p.Hub.Approver(ctx)
	switch {
	case err != nil:
		return "", "", err
	case !ok:
		return hemma.StateRefused, noteNoApprover, nil
	case d.KeyID != a.KeyID:
		return hemma.StateRefused, noteNotEnrolled, nil
	case d.Decision != hemma.DecisionApprove && d.Decision != hemma.DecisionDeny:
		return hemma.StateRefused, noteBadDecision, nil
	}
	if hemma.Verify(a.PublicKey, hemma.SignedText(d.Request, d.Round, d.Fingerprint, d.Decision, d.ExpiresAt), d.Signature) != nil {
		return hemma.StateRefused, noteBadSignature, nil
	}
	key := appliedKey{d.Request, d.Round, d.Fingerprint}
	applied, err := p.applied(ctx)
	if err != nil {
		return "", "", err
	}
	for _, k := range applied {
		if k == key {
			return hemma.StateApplied, "", nil // a replay: applied before
		}
	}
	_, err = p.Hub.ApplyDecision(ctx, peer.Decision{
		RequestID: d.Request, Round: d.Round, Fingerprint: d.Fingerprint,
		Approve: d.Decision == hemma.DecisionApprove, ExpiresAt: time.Unix(d.ExpiresAt, 0),
	})
	var refused peer.DecisionRefused
	if errors.As(err, &refused) {
		return hemma.StateRefused, string(refused), nil
	}
	if err != nil {
		return "", "", err
	}
	applied = append(applied, key)
	if len(applied) > keepApplied {
		applied = applied[len(applied)-keepApplied:]
	}
	if err := p.setApplied(ctx, applied); err != nil {
		p.log().Warn("hemma: recording the applied decision failed", "request_id", d.Request, "error", err)
	}
	return hemma.StateApplied, "", nil
}

// appliedKey identifies one approval round: decisions are idempotent on it.
type appliedKey struct {
	Request     string `json:"request"`
	Round       int64  `json:"round"`
	Fingerprint string `json:"fingerprint"`
}

func (p *Poller) applied(ctx context.Context) ([]appliedKey, error) {
	v, ok, err := p.Meta.Meta(ctx, metaApplied)
	if err != nil || !ok {
		return nil, err
	}
	var keys []appliedKey
	if err := json.Unmarshal([]byte(v), &keys); err != nil {
		p.log().Warn("hemma: applied decisions record is unreadable; starting over", "error", err)
		return nil, nil
	}
	return keys, nil
}

func (p *Poller) setApplied(ctx context.Context, keys []appliedKey) error {
	b, err := json.Marshal(keys)
	if err != nil {
		return err
	}
	return p.Meta.SetMeta(ctx, metaApplied, string(b))
}

func (p *Poller) log() *slog.Logger {
	if p.Log == nil {
		return slog.Default()
	}
	return p.Log
}
