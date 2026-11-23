package peer

// Approval rounds. A park starts a round: the request is parked with a kind
// (step or limit) and a fingerprint, and the
// Prompter delivers the approval prompt to the operator. The operator's
// decision is signed by the enrolled approver phone; whoever verifies that
// signature calls ApplyDecision, which applies it only to the round and
// fingerprint it names, while the request is still parked there. Rounds are
// unbounded.
//
// What a prompt carries is up to the Prompter; the hub hands it the request
// row.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// ParkKind is what a park waits for.
type ParkKind string

const (
	ParkStep  ParkKind = "step"  // a blocked tool call
	ParkLimit ParkKind = "limit" // the run's cost or time allowance ran out
)

// Allowance: a request starts with these (the column defaults), and each
// approved limit park adds them again.
const (
	AllowanceUSD     = 10.0
	AllowanceSeconds = 7200
	// maxParkReason bounds a park's reason, in runes.
	maxParkReason = 300
)

// limitFingerprint is the fingerprint of a limit park at round.
func limitFingerprint(round int64) string { return sha256Hex("limit:" + strconv.FormatInt(round, 10)) }

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// Prompter delivers approval prompts. The hub calls it outside any
// transaction; a nil Prompter (the default) delivers nothing and parked
// requests wait on the dashboard.
type Prompter interface {
	// SendPrompt delivers the prompt for parked request r's current round
	// (r.ApprovalCycles, r.Fingerprint) and returns the prompt's id. An error
	// leaves the round unprompted; the sweep calls it again every SweepEvery.
	// Delivery must be idempotent per request, round and fingerprint.
	SendPrompt(ctx context.Context, r Request) (promptID string, err error)
	// Withdraw reports that parked request r left parked without a decision
	// (it expired). r is the row as it was parked, with its PromptID.
	Withdraw(ctx context.Context, r Request)
}

// SetPrompter makes parks send approval prompts.
func (s *Service) SetPrompter(p Prompter) { s.prompter = p }

// Decision is a verified operator decision on one approval round.
type Decision struct {
	RequestID   string
	Round       int64
	Fingerprint string
	Approve     bool
	// ExpiresAt is the decision's signed expiry; at or after it the
	// decision is refused.
	ExpiresAt time.Time
}

// DecisionRefused is ApplyDecision's refusal: nothing changed. Its value is
// a fixed note for the approval's state report.
type DecisionRefused string

const (
	RefusedUnknown   DecisionRefused = "unknown request"
	RefusedNotParked DecisionRefused = "the request is not waiting for a decision"
	RefusedStale     DecisionRefused = "the request is no longer at this round and fingerprint"
	RefusedExpired   DecisionRefused = "the decision or the park has expired"
)

func (r DecisionRefused) Error() string { return "peer: decision refused: " + string(r) }

// DecideSpec is a decision compare-and-set.
type DecideSpec struct {
	Decision
	Now time.Time
	// ApprovedExpiresAt is an approved request's expiry.
	ApprovedExpiresAt time.Time
}

// ApplyDecision applies a decision whose signature the caller has verified
// against the enrolled approver key. It holds only while the request is
// parked at d.Round with d.Fingerprint, before the decision's and the park's
// expiry; otherwise it returns a DecisionRefused and changes nothing.
//
// Approve moves parked to approved: a step park's step hash is the one call
// the next run may make, and a limit park raises the allowance by
// AllowanceUSD and AllowanceSeconds. Deny finishes
// the request as denied with its result message.
func (s *Service) ApplyDecision(ctx context.Context, d Decision) (Request, error) {
	if d.RequestID == "" || len(d.RequestID) > maxID {
		return Request{}, RefusedUnknown
	}
	var r Request
	err := s.publishing(func() (*Message, error) {
		now := s.now()
		if !now.Before(d.ExpiresAt) {
			return nil, RefusedExpired
		}
		var m *Message
		var err error
		r, m, err = s.st.DecideRequest(ctx, DecideSpec{Decision: d, Now: now, ApprovedExpiresAt: now.Add(QueueTTL)})
		return m, err
	})
	if err != nil {
		return Request{}, err
	}
	s.log.Info("peer request decided", "request_id", r.ID, "approve", d.Approve, "round", d.Round, "kind", r.ParkKind)
	s.changed(r.ID)
	if r.State == ReqApproved {
		s.pushQueued(ctx, r.Target)
	}
	return r, nil
}

// prompt sends parked request r's prompt and records its delivery.
func (s *Service) prompt(ctx context.Context, r Request) {
	if s.prompter == nil || r.State != ReqParked {
		return
	}
	id, err := s.prompter.SendPrompt(ctx, r)
	if err != nil {
		s.log.Warn("peer approval prompt not delivered; the sweep retries", "request_id", r.ID, "round", r.ApprovalCycles, "error", err)
		return
	}
	if _, err := s.st.MarkNotified(ctx, r.ID, r.ApprovalCycles, id, s.now()); err != nil {
		s.log.Warn("peer approval prompt: recording the delivery failed", "request_id", r.ID, "error", err)
	}
}

// withdraw reports that r, parked, expired without a decision.
func (s *Service) withdraw(ctx context.Context, r Request) {
	if s.prompter != nil {
		s.prompter.Withdraw(ctx, r)
	}
}

// SweepApprovals sends the prompt again for every parked request whose
// current round was never delivered (the process ended between the park
// and its prompt, or delivery failed). It runs every SweepEvery.
func (s *Service) SweepApprovals(ctx context.Context, _ time.Time) error {
	if s.prompter == nil {
		return nil
	}
	parked, err := s.st.UnnotifiedParked(ctx)
	if err != nil {
		return err
	}
	for _, r := range parked {
		s.prompt(ctx, r)
	}
	return nil
}

// bounded flattens s to one line and cuts it to max runes.
func bounded(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	return string([]rune(s)[:max-1]) + "…"
}
