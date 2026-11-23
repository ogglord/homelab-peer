package peer

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/ogglord/homelab-peer/internal/store"
)

type dbStore struct{ s *store.Store }

// NewDBStore backs a Store with the hub's SQLite database.
func NewDBStore(s *store.Store) Store { return dbStore{s} }

func (d dbStore) Hello(ctx context.Context, host, instance string, startedAt, now time.Time) (bool, error) {
	n, err := d.s.Queries().PeerHello(ctx, store.PeerHelloParams{
		Name: host, Instance: instance, InstanceStartedAt: startedAt.UnixMilli(), LastSeenAt: now.UnixMilli(),
	})
	return n > 0, err
}

func (d dbStore) Host(ctx context.Context, name string) (Host, bool, error) {
	h, err := d.s.Queries().GetPeerHost(ctx, name)
	if errors.Is(err, sql.ErrNoRows) {
		return Host{}, false, nil
	}
	if err != nil {
		return Host{}, false, err
	}
	return hostFrom(h), true, nil
}

func (d dbStore) Hosts(ctx context.Context) ([]Host, error) {
	rows, err := d.s.Queries().ListPeerHosts(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Host, 0, len(rows))
	for _, h := range rows {
		out = append(out, hostFrom(h))
	}
	return out, nil
}

func (d dbStore) Ack(ctx context.Context, host string, seq int64) error {
	return d.s.Tx(ctx, func(q *store.Queries) error {
		if err := q.AdvancePeerAckedSeq(ctx, store.AdvancePeerAckedSeqParams{Seq: seq, Name: host}); err != nil {
			return err
		}
		return q.MarkPeerMessagesDelivered(ctx, store.MarkPeerMessagesDeliveredParams{Target: host, Seq: seq})
	})
}

func (d dbStore) AcceptStatus(ctx context.Context, m Message) (int64, *Outcome, error) {
	var seq int64
	var prev *Outcome
	err := d.s.Tx(ctx, func(q *store.Queries) error {
		o, err := q.GetPeerMessageOutcome(ctx, store.GetPeerMessageOutcomeParams{Sender: m.Sender, ID: m.ID})
		if err == nil {
			p := outcomeFrom(o)
			prev = &p
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		seq, err = q.InsertPeerMessage(ctx, store.InsertPeerMessageParams{
			ID: m.ID, Kind: string(m.Kind), RequestID: optional(m.RequestID), Sender: m.Sender, Target: m.Target,
			Phase: optional(string(m.Phase)), Body: optional(m.Body), CreatedAt: m.CreatedAt.UnixMilli(),
		})
		if err != nil {
			return err
		}
		return q.InsertPeerMessageOutcome(ctx, store.InsertPeerMessageOutcomeParams{
			Sender: m.Sender, ID: m.ID, Kind: string(m.Kind), Target: m.Target, RequestID: optional(m.RequestID),
			Outcome: string(OutcomeStored), CreatedAt: m.CreatedAt.UnixMilli(),
		})
	})
	return seq, prev, err
}

func (d dbStore) Message(ctx context.Context, sender, id string) (Message, bool, error) {
	m, err := d.s.Queries().GetPeerMessage(ctx, store.GetPeerMessageParams{Sender: sender, ID: id})
	if errors.Is(err, sql.ErrNoRows) {
		return Message{}, false, nil
	}
	if err != nil {
		return Message{}, false, err
	}
	return messageFrom(m), true, nil
}

func (d dbStore) Replay(ctx context.Context, target string, after int64, limit int) ([]Message, error) {
	rows, err := d.s.Queries().ReplayPeerMessages(ctx, store.ReplayPeerMessagesParams{Target: target, After: after, Limit: int64(limit)})
	return messagesFrom(rows), err
}

func (d dbStore) Inbox(ctx context.Context, target string, limit int) ([]Message, error) {
	rows, err := d.s.Queries().ListPeerInbox(ctx, store.ListPeerInboxParams{Target: target, Limit: int64(limit)})
	return messagesFrom(rows), err
}

func (d dbStore) MarkRead(ctx context.Context, seq int64) error {
	return d.s.Queries().MarkPeerMessageRead(ctx, seq)
}

// ── requests ────────────────────────────────────────────────────────────

func (d dbStore) CreateRequest(ctx context.Context, r Request) (*Outcome, *Request, error) {
	var prev *Outcome
	var existing *Request
	err := d.s.Tx(ctx, func(q *store.Queries) error {
		prev, existing = nil, nil
		o, err := q.GetPeerMessageOutcome(ctx, store.GetPeerMessageOutcomeParams{Sender: r.Sender, ID: r.ID})
		if err == nil {
			p := outcomeFrom(o)
			prev = &p
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		row, err := q.GetPeerRequest(ctx, r.ID)
		if err == nil {
			e := requestFrom(row)
			existing = &e
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		now := r.CreatedAt.UnixMilli()
		if err := q.InsertPeerRequest(ctx, store.InsertPeerRequestParams{
			ID: r.ID, Sender: r.Sender, Target: r.Target, Text: r.Text,
			State: string(r.State), ExpiresAt: msp(r.ExpiresAt), ParentID: optional(r.ParentID),
			CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			return err
		}
		return q.InsertPeerMessageOutcome(ctx, store.InsertPeerMessageOutcomeParams{
			Sender: r.Sender, ID: r.ID, Kind: string(KindRequest), Target: r.Target, RequestID: &r.ID,
			Outcome: string(OutcomeStored), CreatedAt: now,
		})
	})
	return prev, existing, err
}

func (d dbStore) Request(ctx context.Context, id string) (Request, bool, error) {
	return getRequest(ctx, d.s.Queries(), id)
}

func getRequest(ctx context.Context, q *store.Queries, id string) (Request, bool, error) {
	row, err := q.GetPeerRequest(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return Request{}, false, nil
	}
	if err != nil {
		return Request{}, false, err
	}
	return requestFrom(row), true, nil
}

func (d dbStore) RequestByToken(ctx context.Context, tokenHash string) (Request, bool, error) {
	row, err := d.s.Queries().GetPeerRequestByToken(ctx, &tokenHash)
	if errors.Is(err, sql.ErrNoRows) {
		return Request{}, false, nil
	}
	if err != nil {
		return Request{}, false, err
	}
	return requestFrom(row), true, nil
}

func (d dbStore) PushableRequests(ctx context.Context, target string) ([]Request, error) {
	rows, err := d.s.Queries().ListPushablePeerRequests(ctx, target)
	return requestsFrom(rows), err
}

func (d dbStore) MarkDelivered(ctx context.Context, id string, attempt int64, now time.Time) (bool, error) {
	n, err := d.s.Queries().MarkPeerRequestDelivered(ctx, store.MarkPeerRequestDeliveredParams{
		Now: msp(now), ID: id, Attempt: attempt,
	})
	return n > 0, err
}

func (d dbStore) Requeue(ctx context.Context, target string, deliveredBefore, now time.Time) ([]string, error) {
	return requeueTx(ctx, d.s.Queries(), target, deliveredBefore, now)
}

func requeueTx(ctx context.Context, q *store.Queries, target string, deliveredBefore, now time.Time) ([]string, error) {
	return q.RequeuePeerRequests(ctx, store.RequeuePeerRequestsParams{
		Now: now.UnixMilli(), DeliveredBefore: msp(deliveredBefore), Target: optional(target),
	})
}

func (d dbStore) ClaimRequest(ctx context.Context, c ClaimSpec) (Request, error) {
	var out Request
	var refused error
	err := d.s.Tx(ctx, func(q *store.Queries) error {
		refused = nil
		r, ok, err := getRequest(ctx, q, c.ID)
		switch {
		case err != nil:
			return err
		case !ok:
			refused = ErrUnknownRequest
			return nil
		case r.Target != c.Host:
			refused = ErrNotPermitted
			return nil
		}
		h, err := q.GetPeerHost(ctx, c.Host)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			refused = ErrHelloRequired
			return nil
		case err != nil:
			return err
		case h.Instance != c.Instance:
			refused = ErrSuperseded
			return nil
		}
		expires := c.Now.Add(time.Duration(r.RemainingSeconds())*time.Second + c.Grace)
		n, err := q.ClaimPeerRequest(ctx, store.ClaimPeerRequestParams{
			Instance: &c.Instance, TokenHash: &c.TokenHash, Now: msp(c.Now), ExpiresAt: msp(expires),
			ID: c.ID, Target: c.Host, Attempt: c.Attempt,
		})
		if err != nil {
			return err
		}
		if n == 1 {
			out, _, err = getRequest(ctx, q, c.ID)
			return err
		}
		if !r.State.claimable() || r.Attempt != c.Attempt {
			refused = ErrNotClaimable
			return nil
		}
		// Claimable but the host has a running request: back to the queue,
		// pushed again when that run ends.
		refused = ErrBusy
		_, err = requeueTx(ctx, q, c.Host, c.Now, c.Now)
		return err
	})
	if err != nil {
		return Request{}, err
	}
	return out, refused
}

func (d dbStore) ParkRequest(ctx context.Context, p ParkSpec) (Request, bool, error) {
	var out Request
	var refused error
	var usageOnly bool
	err := d.s.Tx(ctx, func(q *store.Queries) error {
		refused, usageOnly = nil, false
		r, err := runCheck(ctx, q, p.ID, p.Host, p.Attempt, p.Instance)
		if errors.Is(err, ErrNotRunning) && r.State == ReqParked && r.Attempt == p.Attempt &&
			r.Instance == p.Instance && r.TokenHash == p.TokenHash {
			// The run's hook parked it; this is the listener's report with
			// the run's cost, which the hook could not know.
			if err := q.AddPeerRequestUsage(ctx, store.AddPeerRequestUsageParams{
				SpentUsd: p.SpentUSD, UsedSeconds: p.UsedSeconds, ID: p.ID,
			}); err != nil {
				return err
			}
			usageOnly = true
			out, _, err = getRequest(ctx, q, p.ID)
			return err
		}
		if err != nil {
			refused = err
			if !isDomain(err) {
				return err
			}
			return nil
		}
		if r.TokenHash != p.TokenHash {
			refused = ErrRunToken
			return nil
		}
		params := store.ParkPeerRequestParams{
			ParkKind: optional(string(p.Kind)), ParkReason: optional(p.Reason),
			SpentUsd: p.SpentUSD, UsedSeconds: p.UsedSeconds, ExpiresAt: msp(p.ExpiresAt), Now: p.Now.UnixMilli(),
			ID: p.ID, Attempt: p.Attempt, Instance: &p.Instance, TokenHash: &p.TokenHash,
		}
		if p.Kind == ParkLimit {
			params.Fingerprint = optional(limitFingerprint(r.ApprovalCycles + 1))
		} else {
			params.Tool, params.Step, params.StepHash = &p.Tool, &p.Step, &p.StepHash
			params.Fingerprint = &p.StepHash
		}
		n, err := q.ParkPeerRequest(ctx, params)
		if err != nil {
			return err
		}
		if n != 1 {
			return errors.New("peer: park lost its own transaction")
		}
		out, _, err = getRequest(ctx, q, p.ID)
		return err
	})
	if err != nil {
		return Request{}, false, err
	}
	return out, usageOnly, refused
}

// runCheck reads a request for a run operation by host: it must exist,
// target host, be running, and run at attempt and instance.
func runCheck(ctx context.Context, q *store.Queries, id, host string, attempt int64, instance string) (Request, error) {
	r, ok, err := getRequest(ctx, q, id)
	switch {
	case err != nil:
		return Request{}, err
	case !ok:
		return Request{}, ErrUnknownRequest
	case r.Target != host:
		return Request{}, ErrNotPermitted
	case r.State != ReqRunning:
		return r, ErrNotRunning
	case r.Attempt != attempt || r.Instance != instance:
		return r, ErrSuperseded
	}
	return r, nil
}

func isDomain(err error) bool {
	for _, e := range []error{ErrUnknownRequest, ErrNotPermitted, ErrNotRunning, ErrSuperseded, ErrRunToken} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

func (d dbStore) PostResult(ctx context.Context, rs ResultSpec) (Request, *Message, bool, error) {
	var out Request
	var msg *Message
	var discarded bool
	var refused error
	err := d.s.Tx(ctx, func(q *store.Queries) error {
		refused, msg, discarded = nil, nil, false
		r, err := runCheck(ctx, q, rs.ID, rs.Host, rs.Attempt, rs.Instance)
		switch {
		case errors.Is(err, ErrNotRunning):
			// Terminal, parked or re-queued: the result changes nothing.
			out, discarded = r, true
			return nil
		case err != nil && isDomain(err):
			refused = err
			return nil
		case err != nil:
			return err
		}
		if err := q.AddPeerRequestUsage(ctx, store.AddPeerRequestUsageParams{
			SpentUsd: rs.SpentUSD, UsedSeconds: rs.UsedSeconds, ID: r.ID,
		}); err != nil {
			return err
		}
		spec := runFinish(r, rs.State, rs.Reason, rs.Now)
		spec.Summary = rs.Summary
		ok, fr, m, err := finishTx(ctx, q, spec)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("peer: result finish lost its own transaction")
		}
		out, msg = fr, m
		return nil
	})
	if err != nil {
		return Request{}, nil, false, err
	}
	return out, msg, discarded, refused
}

func (d dbStore) FinishRequest(ctx context.Context, f FinishSpec) (bool, Request, *Message, error) {
	var ok bool
	var out Request
	var msg *Message
	err := d.s.Tx(ctx, func(q *store.Queries) error {
		var err error
		ok, out, msg, err = finishTx(ctx, q, f)
		return err
	})
	if err != nil {
		return false, Request{}, nil, err
	}
	return ok, out, msg, nil
}

// finishTx is the only writer of terminal states: the compare-and-set and,
// when it holds, the request's result message for its sender, in the
// caller's transaction.
func finishTx(ctx context.Context, q *store.Queries, f FinishSpec) (bool, Request, *Message, error) {
	if !f.To.Terminal() {
		return false, Request{}, nil, errors.New("peer: finish to a non-terminal state")
	}
	from := make([]string, len(f.From))
	for i, s := range f.From {
		from[i] = string(s)
	}
	fromJSON, _ := json.Marshal(from)
	n, err := q.FinishPeerRequest(ctx, store.FinishPeerRequestParams{
		ToState: string(f.To), Reason: optional(string(f.Reason)), Summary: optional(f.Summary),
		Now: f.Now.UnixMilli(), ID: f.ID, FromStates: string(fromJSON),
		Attempt: f.Attempt, Instance: f.Instance, DueBy: msp(ptrTime(f.DueBy)), ClaimedBefore: msp(ptrTime(f.ClaimedBefore)),
	})
	if err != nil || n == 0 {
		return false, Request{}, nil, err
	}
	r, _, err := getRequest(ctx, q, f.ID)
	if err != nil {
		return false, Request{}, nil, err
	}
	m := Message{
		ID: resultMessageID(r.ID), Kind: KindResult, RequestID: r.ID, Sender: r.Target, Target: r.Sender,
		Body: resultBody(r), CreatedAt: f.Now,
	}
	if m.Seq, err = q.InsertPeerMessage(ctx, store.InsertPeerMessageParams{
		ID: m.ID, Kind: string(m.Kind), RequestID: &m.RequestID, Sender: m.Sender, Target: m.Target,
		Body: optional(m.Body), CreatedAt: m.CreatedAt.UnixMilli(),
	}); err != nil {
		return false, Request{}, nil, err
	}
	return true, r, &m, nil
}

func (d dbStore) RunningRequests(ctx context.Context, target string) ([]Request, error) {
	rows, err := d.s.Queries().ListPeerRequestsInState(ctx, store.ListPeerRequestsInStateParams{Target: target, State: string(ReqRunning)})
	return requestsFrom(rows), err
}

func (d dbStore) DueRequests(ctx context.Context, now time.Time) ([]Request, error) {
	rows, err := d.s.Queries().ListDuePeerRequests(ctx, msp(now))
	return requestsFrom(rows), err
}

func (d dbStore) RunningHosts(ctx context.Context) ([]string, error) {
	return d.s.Queries().ListPeerHostsRunning(ctx)
}

func (d dbStore) RequestsInState(ctx context.Context, state RequestState, limit int) ([]Request, error) {
	rows, err := d.s.Queries().ListPeerRequestsByState(ctx, store.ListPeerRequestsByStateParams{State: string(state), Limit: int64(limit)})
	return requestsFrom(rows), err
}

// ── approvals ───────────────────────────────────────────────────────────

func (d dbStore) UnnotifiedParked(ctx context.Context) ([]Request, error) {
	rows, err := d.s.Queries().ListUnnotifiedParkedPeerRequests(ctx)
	return requestsFrom(rows), err
}

func (d dbStore) MarkNotified(ctx context.Context, id string, round int64, promptID string, now time.Time) (bool, error) {
	n, err := d.s.Queries().SetPeerRequestNotified(ctx, store.SetPeerRequestNotifiedParams{
		Now: msp(now), PromptID: optional(promptID), ID: id, Round: round,
	})
	return n > 0, err
}

// DecideRequest is a decision's compare-and-set, in one transaction: refuse
// it unless the request is parked at the decision's round and fingerprint
// and its park has not expired, then approve (raising a limit park's
// allowance) or deny it.
func (d dbStore) DecideRequest(ctx context.Context, ds DecideSpec) (Request, *Message, error) {
	var out Request
	var msg *Message
	var refused error
	err := d.s.Tx(ctx, func(q *store.Queries) error {
		out, msg, refused = Request{}, nil, nil
		r, ok, err := getRequest(ctx, q, ds.RequestID)
		switch {
		case err != nil:
			return err
		case !ok:
			refused = RefusedUnknown
			return nil
		case r.State != ReqParked:
			refused = RefusedNotParked
			return nil
		case r.ApprovalCycles != ds.Round || r.Fingerprint == "" || r.Fingerprint != ds.Fingerprint:
			refused = RefusedStale
			return nil
		case !ds.Now.Before(r.ExpiresAt):
			refused = RefusedExpired
			return nil
		}
		if !ds.Approve {
			won, fr, m, err := finishTx(ctx, q, FinishSpec{ID: r.ID, From: []RequestState{ReqParked}, To: ReqDenied, Now: ds.Now})
			if err != nil {
				return err
			}
			if !won {
				return errors.New("peer: deny lost its own transaction")
			}
			out, msg = fr, m
			return nil
		}
		params := store.ApprovePeerRequestParams{
			ExpiresAt: msp(ds.ApprovedExpiresAt), Now: ds.Now.UnixMilli(), ID: r.ID, Round: r.ApprovalCycles,
			Fingerprint: &r.Fingerprint,
		}
		if r.ParkKind == ParkLimit {
			params.AddUsd, params.AddSeconds = AllowanceUSD, AllowanceSeconds
		}
		won, err := q.ApprovePeerRequest(ctx, params)
		if err != nil {
			return err
		}
		if won != 1 {
			return errors.New("peer: approve lost its own transaction")
		}
		out, _, err = getRequest(ctx, q, r.ID)
		return err
	})
	if err != nil {
		return Request{}, nil, err
	}
	return out, msg, refused
}

// metaApprover is the meta key holding the enrolled approver (JSON).
const metaApprover = "peer_approver"

func (d dbStore) Approver(ctx context.Context) (Approver, bool, error) {
	v, ok, err := d.s.Meta(ctx, metaApprover)
	if err != nil || !ok {
		return Approver{}, false, err
	}
	var a Approver
	if err := json.Unmarshal([]byte(v), &a); err != nil {
		return Approver{}, false, err
	}
	return a, true, nil
}

func (d dbStore) SetApprover(ctx context.Context, a *Approver, now time.Time) ([]Request, error) {
	var value string
	if a != nil {
		b, err := json.Marshal(a)
		if err != nil {
			return nil, err
		}
		value = string(b)
	}
	var parked []Request
	err := d.s.Tx(ctx, func(q *store.Queries) error {
		var err error
		if a != nil {
			err = q.SetMeta(ctx, store.SetMetaParams{Key: metaApprover, Value: value})
		} else {
			err = q.DeleteMeta(ctx, metaApprover)
		}
		if err != nil {
			return err
		}
		rows, err := q.ListParkedPeerRequests(ctx)
		if err != nil {
			return err
		}
		parked = requestsFrom(rows)
		for _, r := range parked {
			fp := r.Fingerprint
			if r.ParkKind == ParkLimit { // a limit park's fingerprint names its round
				fp = limitFingerprint(r.ApprovalCycles + 1)
			}
			if _, err := q.ReroundPeerRequest(ctx, store.ReroundPeerRequestParams{
				Fingerprint: optional(fp), Now: now.UnixMilli(), ID: r.ID, Round: r.ApprovalCycles,
			}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return parked, nil
}

func (d dbStore) RecentRequests(ctx context.Context, limit int) ([]Request, error) {
	rows, err := d.s.Queries().ListRecentPeerRequests(ctx, int64(limit))
	return requestsFrom(rows), err
}

func msp(t time.Time) *int64 {
	if t.IsZero() {
		return nil
	}
	ms := t.UnixMilli()
	return &ms
}

func ptrTime(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}

func timeFrom(ms *int64) time.Time {
	if ms == nil {
		return time.Time{}
	}
	return time.UnixMilli(*ms)
}

func requestFrom(r store.PeerRequest) Request {
	return Request{
		ID: r.ID, Sender: r.Sender, Target: r.Target, Text: r.Text,
		State: RequestState(r.State), Attempt: r.Attempt, Instance: deref(r.Instance), TokenHash: deref(r.RunTokenHash),
		DeliveredAt: timeFrom(r.DeliveredAt), ClaimedAt: timeFrom(r.ClaimedAt), ExpiresAt: timeFrom(r.ExpiresAt),
		ApprovalCycles: r.ApprovalCycles, Tool: deref(r.Tool), Step: deref(r.Step), StepHash: deref(r.StepHash),
		ParentID: deref(r.ParentID), NotifiedAt: timeFrom(r.NotifiedAt), PromptID: deref(r.PromptID),
		Reason: FailReason(deref(r.Reason)), Summary: deref(r.Summary),
		CreatedAt: time.UnixMilli(r.CreatedAt), UpdatedAt: time.UnixMilli(r.UpdatedAt),
		ParkKind: ParkKind(deref(r.ParkKind)), Fingerprint: deref(r.Fingerprint), ParkReason: deref(r.ParkReason),
		SpentUSD: r.SpentUsd, UsedSeconds: r.UsedSeconds, AllowanceUSD: r.AllowanceUsd, AllowanceSeconds: r.AllowanceSeconds,
	}
}

func requestsFrom(rows []store.PeerRequest) []Request {
	out := make([]Request, 0, len(rows))
	for _, r := range rows {
		out = append(out, requestFrom(r))
	}
	return out
}

func (d dbStore) RecentMessages(ctx context.Context, limit int) ([]Message, error) {
	rows, err := d.s.Queries().ListRecentPeerMessages(ctx, int64(limit))
	return messagesFrom(rows), err
}

func (d dbStore) RecentOutcomes(ctx context.Context, limit int) ([]Outcome, error) {
	rows, err := d.s.Queries().ListRecentPeerOutcomes(ctx, int64(limit))
	if err != nil {
		return nil, err
	}
	out := make([]Outcome, 0, len(rows))
	for _, o := range rows {
		out = append(out, outcomeFrom(o))
	}
	return out, nil
}

func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func hostFrom(h store.PeerHost) Host {
	return Host{
		Name: h.Name, Instance: h.Instance, InstanceStartedAt: time.UnixMilli(h.InstanceStartedAt),
		LastSeenAt: time.UnixMilli(h.LastSeenAt), AckedSeq: h.AckedSeq,
	}
}

func messageFrom(m store.PeerMessage) Message {
	return Message{
		Seq: m.Seq, ID: m.ID, Kind: Kind(m.Kind), Sender: m.Sender, Target: m.Target, Phase: Phase(deref(m.Phase)),
		Body: deref(m.Body), RequestID: deref(m.RequestID), CreatedAt: time.UnixMilli(m.CreatedAt),
		Delivered: m.Delivered, Read: m.Read,
	}
}

func messagesFrom(rows []store.PeerMessage) []Message {
	out := make([]Message, 0, len(rows))
	for _, m := range rows {
		out = append(out, messageFrom(m))
	}
	return out
}

func outcomeFrom(o store.PeerMessageOutcome) Outcome {
	return Outcome{
		Sender: o.Sender, ID: o.ID, Kind: Kind(o.Kind), Target: o.Target,
		RequestID: deref(o.RequestID), State: OutcomeState(o.Outcome), CreatedAt: time.UnixMilli(o.CreatedAt),
	}
}
