package peer

// A request is one row in peer_requests; the row is authoritative and the
// result message is a notification derived from it.
//
// Transition table. Every transition is one SQL compare-and-set naming its
// from-states (db/queries/peer.sql); "attempt, instance" means the run's
// attempt and listener instance must still match. FinishPeerRequest, called
// only from dbStore's finishTx, is the only writer of a terminal state, and
// it writes the result message in the same transaction.
//
//	from                         to         writer                 guard / statement
//	(new)                        waiting    Send kind request      InsertPeerRequest
//	waiting, approved            delivered  stream push            MarkPeerRequestDelivered (attempt)
//	delivered                    waiting*   hello, busy claim,     RequeuePeerRequests
//	                                        run end, claim timeout
//	waiting, delivered, approved running    Claim                  ClaimPeerRequest (attempt; no other
//	                                                               running request on the host)
//	running                      parked     Park                   ParkPeerRequest (attempt, instance,
//	                                                               token)
//	running                      done       PostResult             finishTx (attempt, instance)
//	running                      failed     PostResult             finishTx (attempt, instance)
//	running                      failed     hello lease            finishTx (attempt, instance, claim
//	                                                               before receipt - LeaseGrace)
//	running                      failed     silent host (ticker)   finishTx (attempt, instance)
//	running                      failed     sweep (timeout)        finishTx (attempt, instance, due)
//	parked                       approved   approve decision       ApprovePeerRequest (round, fingerprint)
//	parked                       denied     deny decision          finishTx, same tx as the round check
//	waiting, delivered, parked,  expired    sweep                  finishTx (due)
//	approved
//
// * back to approved when the request is an approved re-run (it has had a
// round). Decisions are in approval.go (ApplyDecision).
//
// Expiry is rewritten by the transitions that enter a state: 24 h from
// entering waiting, parked or approved; delivered and the requeue keep it, so
// waiting and delivered share one window; running expires after the
// request's remaining time allowance plus RunGrace. The sweep runs every
// minute and before every prune.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math"
	"slices"
	"time"
	"unicode/utf8"
)

// RequestState is where a request is in its lifecycle.
type RequestState string

const (
	ReqWaiting   RequestState = "waiting"
	ReqDelivered RequestState = "delivered"
	ReqRunning   RequestState = "running"
	ReqParked    RequestState = "parked"
	ReqApproved  RequestState = "approved"
	ReqDone      RequestState = "done"
	ReqFailed    RequestState = "failed"
	ReqDenied    RequestState = "denied"
	ReqExpired   RequestState = "expired"
)

// Terminal reports whether s is a final state.
func (s RequestState) Terminal() bool {
	switch s {
	case ReqDone, ReqFailed, ReqDenied, ReqExpired:
		return true
	}
	return false
}

func (s RequestState) claimable() bool {
	return s == ReqWaiting || s == ReqDelivered || s == ReqApproved
}

// FailReason says why a request failed.
type FailReason string

const (
	// Set by the hub.
	FailListenerLost FailReason = "listener_lost"
	FailTimeout      FailReason = "timeout"
	// Posted by a listener (FailTimeout too).
	FailRunFailed      FailReason = "run_failed"
	FailNoOutput       FailReason = "no_output"
	FailInvalidOutput  FailReason = "invalid_output"
	FailGateUnverified FailReason = "gate_unverified"
)

func listenerReason(r FailReason) bool {
	switch r {
	case FailRunFailed, FailNoOutput, FailInvalidOutput, FailGateUnverified, FailTimeout:
		return true
	}
	return false
}

// Lifecycle constants.
const (
	// QueueTTL: a waiting, delivered, parked or approved request expires
	// this long after entering that state.
	QueueTTL = 24 * time.Hour
	// RunGrace: a running request is failed with timeout this long after
	// its remaining time allowance ran out.
	RunGrace = 5 * time.Minute
	// LeaseGrace: a hello fails a running request it does not report only
	// when the claim is older than the hello's receipt minus this.
	LeaseGrace = 15 * time.Second
	// ListenerLostAfter: a host's running requests fail when no listener of
	// that host has been connected for this long.
	ListenerLostAfter = 10 * time.Minute
	// ClaimTimeout: a delivered request nobody claimed goes back to the queue.
	ClaimTimeout = 5 * time.Minute
	// MaxWait bounds a wait.
	MaxWait = 60 * time.Second
	// SweepEvery is the service's background sweep interval.
	SweepEvery = time.Minute
)

const (
	maxText    = 16384
	maxSummary = 4096
	maxStep    = 8192
	maxTool    = 128
	maxRuns    = 64
	maxToken   = 128
)

// StepTextHash is a step park's hash: lowercase hex SHA-256 of the exact
// step text the hub stores and the operator approves. The run's hook
// computes the same over the call it is about to make.
func StepTextHash(step string) string {
	sum := sha256.Sum256([]byte(step))
	return hex.EncodeToString(sum[:])
}

// Request-scoped domain errors.
var (
	ErrUnknownRequest = errors.New("peer: no such request")
	ErrBusy           = errors.New("peer: the host already has a running request")
	ErrNotClaimable   = errors.New("peer: request is not claimable at this attempt")
	ErrNotRunning     = errors.New("peer: request is not running")
	ErrRunToken       = errors.New("peer: run token is not valid for this request")
	ErrChildRequest   = errors.New("peer: a request sent by a run may not send requests")
	ErrSelfRequest    = errors.New("peer: a run may not send a request to its own host")
)

// Request is one peer request row. Zero times and empty strings mean none.
type Request struct {
	ID             string
	Sender         string
	Target         string
	Text           string
	State          RequestState
	Attempt        int64
	Instance       string
	TokenHash      string
	DeliveredAt    time.Time
	ClaimedAt      time.Time
	ExpiresAt      time.Time
	ApprovalCycles int64
	Tool           string
	Step           string
	StepHash       string
	ParentID       string
	NotifiedAt     time.Time // when the current round's prompt was delivered
	PromptID       string    // the current round's prompt id; "" until then
	Reason         FailReason
	Summary        string
	CreatedAt      time.Time
	UpdatedAt      time.Time
	// The current or last park: its kind, the fingerprint a decision must
	// name, and the run's reason.
	ParkKind    ParkKind
	Fingerprint string
	ParkReason  string
	// Limits: what the runs spent and used, against the allowance.
	SpentUSD         float64
	UsedSeconds      int64
	AllowanceUSD     float64
	AllowanceSeconds int64
}

// RemainingUSD is the cost allowance left, at least 0.
func (r Request) RemainingUSD() float64 { return max(r.AllowanceUSD-r.SpentUSD, 0) }

// RemainingSeconds is the run-time allowance left, at least 0.
func (r Request) RemainingSeconds() int64 { return max(r.AllowanceSeconds-r.UsedSeconds, 0) }

// ClaimSpec is a claim compare-and-set. The run expires Grace after the
// request's remaining time allowance, counted from Now.
type ClaimSpec struct {
	ID, Host, Instance string
	Attempt            int64
	TokenHash          string
	Now                time.Time
	Grace              time.Duration
}

// ParkSpec is a park compare-and-set. A step park's fingerprint is its step
// hash; a limit park's is derived from the round the park starts.
type ParkSpec struct {
	ID, Host, Instance   string
	Attempt              int64
	TokenHash            string
	Kind                 ParkKind
	Tool, Step, StepHash string
	Reason               string
	SpentUSD             float64
	UsedSeconds          int64
	Now, ExpiresAt       time.Time
}

// ResultSpec is a listener's result for its run.
type ResultSpec struct {
	ID, Host, Instance string
	Attempt            int64
	State              RequestState // done or failed
	Reason             FailReason
	Summary            string
	SpentUSD           float64
	UsedSeconds        int64
	Now                time.Time
}

// FinishSpec is a terminal transition. From and every set guard must hold.
type FinishSpec struct {
	ID            string
	From          []RequestState
	Attempt       *int64
	Instance      *string
	DueBy         *time.Time // expires_at <= DueBy
	ClaimedBefore *time.Time // claimed_at < ClaimedBefore
	To            RequestState
	Reason        FailReason
	Summary       string
	Now           time.Time
}

func runFinish(r Request, to RequestState, reason FailReason, now time.Time) FinishSpec {
	return FinishSpec{
		ID: r.ID, From: []RequestState{ReqRunning}, Attempt: &r.Attempt, Instance: &r.Instance,
		To: to, Reason: reason, Now: now,
	}
}

// resultMessageID is the id of a request's result message (sender is the
// request's target). Derived, so the finish is idempotent and a sender's own
// ids, which are not hex digests behind this prefix, cannot collide with it.
func resultMessageID(requestID string) string {
	sum := sha256.Sum256([]byte(requestID))
	return "result-" + hex.EncodeToString(sum[:16])
}

// resultBody is the result message text: the outcome on the first line
// ("done", "failed: <reason>", "expired"), then the summary if any.
func resultBody(r Request) string {
	b := string(r.State)
	if r.Reason != "" {
		b += ": " + string(r.Reason)
	}
	if r.Summary != "" {
		b += "\n" + r.Summary
	}
	return b
}

func newRunToken() (token, hash string) {
	token = randomToken()
	return token, hashToken(token)
}

// randomToken is 32 random bytes, base64url without padding.
func randomToken() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand does not fail on Linux
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// ── creation ────────────────────────────────────────────────────────────

// sendRequest stores a request. parent is the request whose run sent it
// (Send checked the run may), "" for one sent outside a run.
func (s *Service) sendRequest(ctx context.Context, c Caller, in Send, parent string) (SendResult, error) {
	switch {
	case in.Text == "" || utf8.RuneCountInString(in.Text) > maxText:
		return SendResult{}, invalid("text must be 1 to 16384 characters")
	case in.Phase != "" || in.Body != "" || in.RequestID != "":
		return SendResult{}, invalid("phase, body and request_id are not allowed on a request")
	}
	now := s.now()
	r := Request{
		ID: in.ID, Sender: c.Host, Target: in.Target, Text: in.Text, State: ReqWaiting,
		ParentID: parent, ExpiresAt: now.Add(QueueTTL), CreatedAt: now, UpdatedAt: now,
	}
	prev, existing, err := s.st.CreateRequest(ctx, r)
	if err != nil {
		return SendResult{}, err
	}
	switch {
	case prev != nil:
		if prev.Kind != KindRequest || prev.Target != in.Target {
			return SendResult{}, ErrConflict
		}
		return replay(*prev), nil
	case existing != nil:
		// The id is taken by another sender, or the outcome was pruned.
		if existing.Sender != c.Host || existing.Target != in.Target || existing.ParentID != parent {
			return SendResult{}, ErrConflict
		}
		return SendResult{ID: in.ID, Kind: KindRequest, State: OutcomeStored, Replayed: true}, nil
	}
	if s.broker.gateUnverified(r.Target) {
		s.failGateUnverified(ctx, r.ID)
	} else {
		s.broker.publishRequest(r)
	}
	return SendResult{ID: in.ID, Kind: KindRequest, State: OutcomeStored}, nil
}

// runRequestParent checks that run r may send a request to target and
// returns the new request's parent: only a run of a request no run sent,
// and never to the run's own host.
func runRequestParent(r Request, target string) (string, error) {
	switch {
	case r.ParentID != "":
		return "", ErrChildRequest
	case target == r.Target:
		return "", ErrSelfRequest
	}
	return r.ID, nil
}

// runOf resolves a run token presented by c: its request must target c's
// host and be running or parked (a run may report after its park).
func (s *Service) runOf(ctx context.Context, c Caller, token string) (Request, error) {
	if len(token) > maxToken {
		return Request{}, ErrRunToken
	}
	r, ok, err := s.st.RequestByToken(ctx, hashToken(token))
	if err != nil {
		return Request{}, err
	}
	if !ok || r.Target != c.Host || (r.State != ReqRunning && r.State != ReqParked) {
		return Request{}, ErrRunToken
	}
	return r, nil
}

// ── listener operations ─────────────────────────────────────────────────

func validRunRef(id, instance string, attempt int64, minAttempt int64) error {
	switch {
	case id == "" || len(id) > maxID:
		return invalid("request_id must be 1 to 64 characters")
	case instance == "" || len(instance) > maxInstance:
		return invalid("instance must be 1 to 128 characters")
	case attempt < minAttempt:
		return invalid("attempt is out of range")
	}
	return nil
}

// Claim starts a run of request id for c's listener instance at the pushed
// attempt and returns the run's token; the hub keeps only its hash.
func (s *Service) Claim(ctx context.Context, c Caller, id string, attempt int64, instance string) (Request, string, error) {
	if err := validRunRef(id, instance, attempt, 0); err != nil {
		return Request{}, "", err
	}
	token, hash := newRunToken()
	r, err := s.st.ClaimRequest(ctx, ClaimSpec{
		ID: id, Host: c.Host, Instance: instance, Attempt: attempt, TokenHash: hash,
		Now: s.now(), Grace: RunGrace,
	})
	if err != nil {
		return Request{}, "", err
	}
	s.changed(r.ID)
	return r, token, nil
}

// ParkIn is a park call from a run's hooks or its listener.
type ParkIn struct {
	ID, Instance, Token  string
	Attempt              int64
	Kind                 ParkKind // "" means step
	Tool, Step, StepHash string
	Reason               string
	SpentUSD             float64
	UsedSeconds          int64
}

// validUsage checks a run's reported cost and time.
func validUsage(spent float64, used int64) error {
	if spent < 0 || math.IsNaN(spent) || math.IsInf(spent, 0) || used < 0 {
		return invalid("spent_usd and used_seconds must not be negative")
	}
	return nil
}

// Park parks c's running request at a new round, then sends the round's
// approval prompt. A step park records the blocked call; a limit park
// records that the run reached its allowance and carries no call.
func (s *Service) Park(ctx context.Context, c Caller, in ParkIn) (Request, error) {
	if err := validRunRef(in.ID, in.Instance, in.Attempt, 1); err != nil {
		return Request{}, err
	}
	if in.Kind == "" {
		in.Kind = ParkStep
	}
	switch {
	case in.Token == "" || len(in.Token) > maxToken:
		return Request{}, invalid("run_token must be 1 to 128 characters")
	case in.Kind != ParkStep && in.Kind != ParkLimit:
		return Request{}, invalid("kind must be step or limit")
	case in.Kind == ParkStep && (in.Tool == "" || len(in.Tool) > maxTool):
		return Request{}, invalid("tool must be 1 to 128 characters")
	case in.Kind == ParkStep && in.Step == "":
		return Request{}, invalid("a step park needs its step")
	case in.Kind == ParkLimit && (in.Tool != "" || in.Step != "" || in.StepHash != ""):
		return Request{}, invalid("a limit park carries no tool, step or step_hash")
	case utf8.RuneCountInString(in.Step) > maxStep:
		return Request{}, invalid("step must be at most 8192 characters")
	case utf8.RuneCountInString(in.Reason) > maxParkReason:
		return Request{}, invalid("reason must be at most 300 characters")
	}
	if err := validUsage(in.SpentUSD, in.UsedSeconds); err != nil {
		return Request{}, err
	}
	var r Request
	var usageOnly bool
	err := s.publishing(func() (*Message, error) {
		now := s.now()
		// An approval names the step text the operator sees: the hub hashes
		// the text it stores and ignores the run's step_hash.
		step, stepHash := in.Step, ""
		if in.Kind == ParkStep {
			stepHash = StepTextHash(step)
		}
		var err error
		r, usageOnly, err = s.st.ParkRequest(ctx, ParkSpec{
			ID: in.ID, Host: c.Host, Instance: in.Instance, Attempt: in.Attempt, TokenHash: hashToken(in.Token),
			Kind: in.Kind, Tool: in.Tool, Step: step, StepHash: stepHash,
			Reason:   bounded(in.Reason, maxParkReason),
			SpentUSD: in.SpentUSD, UsedSeconds: in.UsedSeconds,
			Now: now, ExpiresAt: now.Add(QueueTTL),
		})
		return nil, err
	})
	if err != nil {
		return Request{}, err
	}
	if usageOnly { // already parked and prompted: only the usage changed
		s.changed(r.ID)
		return r, nil
	}
	s.leftRunning(ctx, r)
	s.prompt(ctx, r)
	return r, nil
}

// ResultIn is a listener's derived outcome for its run.
type ResultIn struct {
	ID, Instance string
	Attempt      int64
	State        RequestState // done or failed
	Reason       FailReason
	Summary      string
	SpentUSD     float64
	UsedSeconds  int64
}

// PostResult finishes c's running request. A result for a request that is no
// longer running is discarded (true) and the current row returned.
func (s *Service) PostResult(ctx context.Context, c Caller, in ResultIn) (Request, bool, error) {
	if !c.May(KindResult) {
		return Request{}, false, ErrNotPermitted
	}
	if err := validRunRef(in.ID, in.Instance, in.Attempt, 1); err != nil {
		return Request{}, false, err
	}
	switch {
	case in.State != ReqDone && in.State != ReqFailed:
		return Request{}, false, invalid("outcome must be done or failed")
	case in.State == ReqDone && in.Reason != "":
		return Request{}, false, invalid("a done outcome has no reason")
	case in.State == ReqFailed && !listenerReason(in.Reason):
		return Request{}, false, invalid("a failed outcome needs a reason: run_failed, no_output, invalid_output, timeout or gate_unverified")
	case utf8.RuneCountInString(in.Summary) > maxSummary:
		return Request{}, false, invalid("summary must be at most 4096 characters")
	}
	if err := validUsage(in.SpentUSD, in.UsedSeconds); err != nil {
		return Request{}, false, err
	}
	var r Request
	var discarded bool
	err := s.publishing(func() (*Message, error) {
		now := s.now()
		var m *Message
		var err error
		r, m, discarded, err = s.st.PostResult(ctx, ResultSpec{
			ID: in.ID, Host: c.Host, Instance: in.Instance, Attempt: in.Attempt, State: in.State, Reason: in.Reason,
			Summary:  in.Summary,
			SpentUSD: in.SpentUSD, UsedSeconds: in.UsedSeconds, Now: now,
		})
		return m, err
	})
	if err != nil {
		return Request{}, false, err
	}
	if !discarded {
		s.leftRunning(ctx, r)
	}
	return r, discarded, nil
}

// ── reading ─────────────────────────────────────────────────────────────

// Wait returns request id once it is terminal or after wait (at most
// MaxWait), whichever comes first. Only its sender or target may read it.
func (s *Service) Wait(ctx context.Context, c Caller, id string, wait time.Duration) (Request, error) {
	wait = min(max(wait, 0), MaxWait)
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for {
		r, err := s.readRequest(ctx, c, id)
		if err != nil || r.State.Terminal() || wait == 0 {
			return r, err
		}
		ch := s.watch(id)
		// Re-read after watching, so a change in between is not missed.
		if r, err = s.readRequest(ctx, c, id); err != nil || r.State.Terminal() {
			return r, err
		}
		select {
		case <-ch:
		case <-timer.C:
			return s.readRequest(ctx, c, id)
		case <-ctx.Done():
			return Request{}, ctx.Err()
		}
	}
}

func (s *Service) readRequest(ctx context.Context, c Caller, id string) (Request, error) {
	r, ok, err := s.st.Request(ctx, id)
	switch {
	case err != nil:
		return Request{}, err
	case !ok:
		return Request{}, ErrUnknownRequest
	case r.Sender != c.Host && r.Target != c.Host:
		return Request{}, ErrNotPermitted
	}
	return r, nil
}

// Requests lists recent requests, newest first (operator view); with state,
// only the requests in that state.
func (s *Service) Requests(ctx context.Context, state RequestState, limit int) ([]Request, error) {
	if state != "" {
		return s.st.RequestsInState(ctx, state, clampLimit(limit))
	}
	return s.st.RecentRequests(ctx, clampLimit(limit))
}

// ── transition plumbing ─────────────────────────────────────────────────

// publishing runs fn under pubMu and publishes the message it returns, if
// any, before releasing it, so the live channel sees messages in sequence
// order.
func (s *Service) publishing(fn func() (*Message, error)) error {
	s.pubMu.Lock()
	defer s.pubMu.Unlock()
	m, err := fn()
	if err == nil && m != nil {
		s.broker.publish(*m)
	}
	return err
}

// finish runs a terminal transition, publishes its result message in
// sequence order, and runs the after-effects. It reports whether it won.
func (s *Service) finish(ctx context.Context, spec FinishSpec) (bool, error) {
	var ok bool
	var r Request
	err := s.publishing(func() (*Message, error) {
		var m *Message
		var err error
		ok, r, m, err = s.st.FinishRequest(ctx, spec)
		return m, err
	})
	if err != nil || !ok {
		return false, err
	}
	if slices.Contains(spec.From, ReqRunning) {
		s.leftRunning(ctx, r)
	} else {
		s.changed(r.ID)
	}
	return true, nil
}

// leftRunning is the after-effect of a run ending (parked or terminal):
// waiters wake and the host's queue is pushed.
func (s *Service) leftRunning(ctx context.Context, r Request) {
	s.changed(r.ID)
	s.pushQueued(ctx, r.Target)
}

// pushQueued returns host's delivered requests to the queue and pushes every
// queued one again, in arrival order. While host's listener reports its gate
// unverified, the waiting ones fail with gate_unverified instead: it would
// never claim them.
func (s *Service) pushQueued(ctx context.Context, host string) {
	now := s.now()
	if _, err := s.st.Requeue(ctx, host, now, now); err != nil {
		s.log.Warn("peer requeue failed", "host", host, "error", err)
		return
	}
	gate := s.broker.gateUnverified(host)
	if !gate && !s.broker.connected(host) {
		return
	}
	reqs, err := s.st.PushableRequests(ctx, host)
	if err != nil {
		s.log.Warn("peer push of queued requests failed", "host", host, "error", err)
		return
	}
	for _, r := range reqs {
		if gate && r.State == ReqWaiting {
			s.failGateUnverified(ctx, r.ID)
			continue
		}
		s.broker.publishRequest(r)
	}
}

// failGateUnverified fails a waiting or delivered request whose target's
// listener reports its gate unverified.
func (s *Service) failGateUnverified(ctx context.Context, id string) {
	won, err := s.finish(ctx, FinishSpec{
		ID: id, From: []RequestState{ReqWaiting, ReqDelivered}, To: ReqFailed, Reason: FailGateUnverified, Now: s.now(),
	})
	switch {
	case err != nil:
		s.log.Warn("peer request: failing for an unverified gate failed", "request_id", id, "error", err)
	case won:
		s.log.Info("peer request failed: the target's gate is unverified", "request_id", id)
	}
}

// markDelivered is the stream's after-push transition.
func (s *Service) markDelivered(ctx context.Context, r Request) {
	if _, err := s.st.MarkDelivered(ctx, r.ID, r.Attempt, s.now()); err != nil && ctx.Err() == nil {
		s.log.Warn("peer mark delivered failed", "request_id", r.ID, "error", err)
	}
}

// watch returns a channel closed at the next transition of request id.
func (s *Service) watch(id string) <-chan struct{} {
	s.waitMu.Lock()
	defer s.waitMu.Unlock()
	ch, ok := s.waiters[id]
	if !ok {
		ch = make(chan struct{})
		s.waiters[id] = ch
	}
	return ch
}

func (s *Service) changed(id string) {
	s.waitMu.Lock()
	defer s.waitMu.Unlock()
	if ch, ok := s.waiters[id]; ok {
		close(ch)
		delete(s.waiters, id)
	}
}
