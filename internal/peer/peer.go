// Package peer is the agent peer messaging hub: hosts send requests and
// status messages to each other through it, over its own tailnet node.
//
// Agent operations (hello, stream, send, ack, inbox, read, claim, park,
// result, wait, list) are served on the tailnet listener, where the caller
// is identified from the connection (Identity) and authorised by its peer
// capability; every request-scoped one is bound to the caller's host
// (http.go). The approver phone enrols on a separate listener behind
// Caddy (enrol.go); minting the enrolment code and revoking the phone are
// done by root inside the stack through the hub binary. Decisions arrive
// signed by the enrolled approver and are applied through ApplyDecision
// (approval.go).
//
// A status is stored and pushed to its target's listener. A request is
// stored, pushed, claimed by the target's listener for one run at a time,
// and ends in one terminal outcome (request.go has the transition table,
// lease.go the listener leases and the expiry sweep).
package peer

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"
	"unicode/utf8"
)

// Kind is a message kind.
type Kind string

const (
	KindRequest Kind = "request"
	KindResult  Kind = "result"
	KindStatus  Kind = "status"
)

// validKind reports whether k is a kind a capability may grant. "secret" is
// no kind any more: secret handover was removed.
func validKind(k Kind) bool { return k == KindRequest || k == KindResult || k == KindStatus }

// Phase is where a status says its work is.
type Phase string

func (p Phase) valid() bool {
	switch p {
	case "info", "started", "progress", "blocked", "done", "failed":
		return true
	}
	return false
}

// OutcomeState is what happened to an accepted message id.
type OutcomeState string

// OutcomeStored is the one outcome of an accepted request or status.
const OutcomeStored OutcomeState = "stored"

// Field limits, matching the CHECK constraints of the peer tables.
const (
	maxID       = 64
	maxHost     = 64
	maxInstance = 128
	maxBody     = 16384
)

// Domain errors; http.go maps them to problems with fixed details.
var (
	ErrUnknownCaller  = errors.New("peer: caller identity could not be established")
	ErrNoCapability   = errors.New("peer: caller has no peer capability")
	ErrNotPermitted   = errors.New("peer: not permitted for this caller")
	ErrSenderMismatch = errors.New("peer: sender does not match the caller's host")
	ErrConflict       = errors.New("peer: message id reused with a different kind, target or request")
	ErrSuperseded     = errors.New("peer: superseded by a newer listener instance")
	ErrHelloRequired  = errors.New("peer: no hello from this host since the hub started")
	ErrNotFound       = errors.New("peer: no such message")
	errFellBehind     = errors.New("peer: stream fell behind; reconnect")
)

// invalidError is a malformed message. msg is always a fixed string written
// in this package, never request input, so it is safe as a problem detail.
type invalidError struct{ msg string }

func (e invalidError) Error() string { return "peer: invalid message: " + e.msg }

func invalid(msg string) error { return invalidError{msg} }

// Message is a stored status or result.
type Message struct {
	Seq       int64
	ID        string
	Kind      Kind
	Sender    string
	Target    string
	Phase     Phase  // status only
	Body      string // empty means none
	RequestID string // empty means none
	CreatedAt time.Time
	Delivered bool
	Read      bool
}

// Outcome is the recorded result of a message id (sender plus id).
type Outcome struct {
	Sender    string
	ID        string
	Kind      Kind
	Target    string
	RequestID string
	State     OutcomeState
	CreatedAt time.Time
}

// Host is a peer host's listener record.
type Host struct {
	Name              string
	Instance          string
	InstanceStartedAt time.Time
	LastSeenAt        time.Time
	AckedSeq          int64
	GateUnverified    bool   // the current instance's hello said so (in memory)
	Version           string // the current instance's build commit (in memory)
}

// Send is one message as a caller sends it. Sender is the body-supplied
// sender, checked against the caller's host and otherwise ignored.
type Send struct {
	ID        string
	Kind      Kind
	Sender    string
	Target    string
	Phase     Phase
	Body      string
	RequestID string
	Text      string // request only
	// Legacy is set when the body carried a field of the removed secret
	// handover (name, value, secret_names): the send is refused.
	Legacy bool
	// RunToken is the X-Peer-Run-Token of a message sent from a run.
	RunToken string
}

// SendResult is a message's outcome. Seq is set for a stored status.
type SendResult struct {
	ID       string
	Kind     Kind
	State    OutcomeState
	Seq      int64
	Replayed bool
}

// HubState is the tailnet node's state.
type HubState string

const (
	StateDisabled     HubState = "disabled"
	StateStarting     HubState = "starting"
	StateRunning      HubState = "running"
	StateUnauthorized HubState = "unauthorized"
	StateError        HubState = "error"
)

// HubStatus is the operator view of the hub.
type HubStatus struct {
	State  HubState
	Detail string
	Node   string
	IPs    []string
	Hosts  []Host
}

// Config is the hub's behaviour.
type Config struct {
	// Hostname is the hub's tailnet node name (display only).
	Hostname string
	// Heartbeat is the stream's comment interval; zero means 20 s.
	Heartbeat time.Duration
	// EnrolURL is the approver enrolment endpoint the phone posts to (the
	// enrolment link carries it), e.g. https://peer.example.com/api/peer/approvers.
	EnrolURL string
	// OnEnrolled, when set, runs after an approver phone enrolled.
	OnEnrolled func(name string)
	// Version is the hub's build commit; listeners report theirs.
	Version string
}

// Service is the hub.
type Service struct {
	cfg    Config
	st     Store
	log    *slog.Logger
	now    func() time.Time
	broker *broker

	// pubMu holds a status insert and its publish together, so the live
	// channel sees messages in sequence order (the stream drops anything at
	// or below the last sequence it emitted).
	pubMu sync.Mutex
	// prompter delivers approval prompts (nil: nothing is sent).
	prompter Prompter
	// enrol holds the one current approver enrolment code (approver.go).
	enrol enrolCode
	// waiters wake Wait calls at a request's next transition.
	waitMu  sync.Mutex
	waiters map[string]chan struct{}
	// started is when this service was built: the baseline for a host no
	// listener has contacted since.
	started time.Time

	stateMu sync.Mutex
	state   nodeState

	// afterSubscribe runs between the live subscription and the replay read
	// (tests only).
	afterSubscribe func()
}

// New returns the hub. log may be nil.
func New(cfg Config, st Store, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default().With("component", "peer")
	}
	if cfg.Heartbeat <= 0 {
		cfg.Heartbeat = 20 * time.Second
	}
	s := &Service{
		cfg: cfg, st: st, log: log, now: time.Now,
		state:   nodeState{State: StateStarting},
		waiters: map[string]chan struct{}{},
	}
	s.broker = newBroker(func() time.Time { return s.now() })
	s.started = s.now()
	return s
}

// SetState records the tailnet node's state for the operator view.
func (s *Service) SetState(state HubState, detail string, ips []string) {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	s.state = nodeState{State: state, Detail: detail, IPs: append([]string(nil), ips...)}
}

// nodeState is the part of HubStatus that SetState records.
type nodeState struct {
	State  HubState
	Detail string
	IPs    []string
}

// Status is the operator view: node state and every known host.
func (s *Service) Status(ctx context.Context) (HubStatus, error) {
	hosts, err := s.st.Hosts(ctx)
	if err != nil {
		return HubStatus{}, err
	}
	for i := range hosts {
		hosts[i].GateUnverified, hosts[i].Version = s.broker.hostInfo(hosts[i].Name)
	}
	s.stateMu.Lock()
	ns := s.state
	s.stateMu.Unlock()
	st := HubStatus{State: ns.State, Detail: ns.Detail, Node: s.cfg.Hostname, IPs: ns.IPs, Hosts: hosts}
	if st.IPs == nil {
		st.IPs = []string{}
	}
	return st, nil
}

// Messages lists recent status and result messages, newest first.
func (s *Service) Messages(ctx context.Context, limit int) ([]Message, error) {
	return s.st.RecentMessages(ctx, clampLimit(limit))
}

// Outcomes lists recent outcomes, newest first.
func (s *Service) Outcomes(ctx context.Context, limit int) ([]Outcome, error) {
	return s.st.RecentOutcomes(ctx, clampLimit(limit))
}

func clampLimit(n int) int {
	switch {
	case n <= 0:
		return 50
	case n > 500:
		return 500
	}
	return n
}

// Ack records that c's listener has every message up to seq. instance must
// be the host's current instance.
func (s *Service) Ack(ctx context.Context, c Caller, instance string, seq int64) error {
	if seq < 0 {
		return invalid("seq must not be negative")
	}
	h, ok, err := s.st.Host(ctx, c.Host)
	if err != nil {
		return err
	}
	if !ok {
		return ErrHelloRequired
	}
	if h.Instance != instance {
		return ErrSuperseded
	}
	return s.st.Ack(ctx, c.Host, seq)
}

// Inbox is the unread status and results addressed to c's host.
func (s *Service) Inbox(ctx context.Context, c Caller) ([]Message, error) {
	return s.st.Inbox(ctx, c.Host, 500)
}

// Read returns one message by sender and id, if c's host is its sender or
// target, and marks it read when c's host is its target.
func (s *Service) Read(ctx context.Context, c Caller, sender, id string) (Message, error) {
	m, ok, err := s.st.Message(ctx, sender, id)
	if err != nil {
		return Message{}, err
	}
	if !ok {
		return Message{}, ErrNotFound
	}
	if m.Sender != c.Host && m.Target != c.Host {
		return Message{}, ErrNotPermitted
	}
	if m.Target == c.Host && !m.Read {
		if err := s.st.MarkRead(ctx, m.Seq); err != nil {
			return Message{}, err
		}
		m.Read = true
	}
	return m, nil
}

// Send accepts one message from c. The sender is always c's host; a body
// sender that differs is refused.
func (s *Service) Send(ctx context.Context, c Caller, in Send) (SendResult, error) {
	if in.Legacy || in.Kind == "secret" {
		return SendResult{}, invalid("secret handover was removed: name, value and secret_names are not accepted")
	}
	if in.Sender != "" && in.Sender != c.Host {
		return SendResult{}, ErrSenderMismatch
	}
	if !c.May(in.Kind) {
		return SendResult{}, ErrNotPermitted
	}
	if err := validateCommon(in); err != nil {
		return SendResult{}, err
	}
	if in.Kind != KindRequest && in.Text != "" {
		return SendResult{}, invalid("text is only allowed on a request")
	}
	parent := ""
	if in.RunToken != "" {
		r, err := s.runOf(ctx, c, in.RunToken)
		if err != nil {
			return SendResult{}, err
		}
		switch {
		case in.Kind == KindRequest:
			// R13, R14: a request sent from a run is its child.
			if parent, err = runRequestParent(r, in.Target); err != nil {
				return SendResult{}, err
			}
		case in.RequestID == "":
			in.RequestID = r.ID
		case in.RequestID != r.ID:
			return SendResult{}, ErrRunToken
		}
	}
	switch in.Kind {
	case KindRequest:
		return s.sendRequest(ctx, c, in, parent)
	case KindStatus:
		return s.sendStatus(ctx, c, in)
	}
	return SendResult{}, invalid("kind must be request or status")
}

func validateCommon(in Send) error {
	switch {
	case in.ID == "" || len(in.ID) > maxID:
		return invalid("id must be 1 to 64 characters")
	case in.Target == "" || len(in.Target) > maxHost:
		return invalid("target must be 1 to 64 characters")
	case len(in.RequestID) > maxID:
		return invalid("request_id must be at most 64 characters")
	}
	return nil
}

func (s *Service) sendStatus(ctx context.Context, c Caller, in Send) (SendResult, error) {
	switch {
	case !in.Phase.valid():
		return SendResult{}, invalid("phase must be one of info, started, progress, blocked, done, failed")
	case utf8.RuneCountInString(in.Body) > maxBody:
		return SendResult{}, invalid("body must be at most 16384 characters")
	}
	m := Message{
		ID: in.ID, Kind: KindStatus, Sender: c.Host, Target: in.Target, Phase: in.Phase,
		RequestID: in.RequestID, CreatedAt: s.now(),
	}
	s.pubMu.Lock()
	m.Body = in.Body
	seq, prev, err := s.st.AcceptStatus(ctx, m)
	if err == nil && prev == nil {
		m.Seq = seq
		s.broker.publish(m)
	}
	s.pubMu.Unlock()
	if err != nil {
		return SendResult{}, err
	}
	if prev != nil {
		if prev.Kind != KindStatus || prev.Target != m.Target || prev.RequestID != m.RequestID {
			return SendResult{}, ErrConflict
		}
		res := replay(*prev)
		if stored, ok, err := s.st.Message(ctx, c.Host, in.ID); err == nil && ok {
			res.Seq = stored.Seq
		}
		return res, nil
	}
	return SendResult{ID: m.ID, Kind: KindStatus, State: OutcomeStored, Seq: seq}, nil
}

func replay(o Outcome) SendResult {
	return SendResult{ID: o.ID, Kind: o.Kind, State: o.State, Replayed: true}
}
