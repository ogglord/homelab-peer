package peer

import "time"

// Wire types of the agent operations. They keep the JSON of the hub's
// earlier home in homelab-daemon field for field, so a deployed `peer`
// binary of any version keeps working: null where that API had null,
// [] where it had a list, and the removed secret handover's members as
// empty lists or nulls.

type helloBody struct {
	Instance       string    `json:"instance"`
	StartedAt      time.Time `json:"started_at"`
	Runs           []string  `json:"runs,omitempty"`
	GateUnverified bool      `json:"gate_unverified,omitempty"`
	Version        string    `json:"version,omitempty"`
}

type identityJSON struct {
	Node    string   `json:"node"`
	Host    string   `json:"host"`
	Kinds   []Kind   `json:"kinds"`
	Secrets []string `json:"secrets"` // always empty
	Cancel  []string `json:"cancel"`
}

type sendBody struct {
	ID        string `json:"id"`
	Kind      Kind   `json:"kind"`
	Sender    string `json:"sender,omitempty"`
	Target    string `json:"target"`
	Phase     Phase  `json:"phase,omitempty"`
	Body      string `json:"body,omitempty"`
	RequestID string `json:"request_id,omitempty"`
	Text      string `json:"text,omitempty"`
	// The removed secret handover: any of them refuses the send.
	Name        string   `json:"name,omitempty"`
	Value       string   `json:"value,omitempty"`
	SecretNames []string `json:"secret_names,omitempty"`
}

type sendResultJSON struct {
	ID       string       `json:"id"`
	Kind     Kind         `json:"kind"`
	Outcome  OutcomeState `json:"outcome"`
	Reason   *string      `json:"reason"` // always null
	Replayed bool         `json:"replayed"`
	Seq      *int64       `json:"seq,omitempty"`
}

type ackBody struct {
	Instance string `json:"instance"`
	Seq      int64  `json:"seq"`
}

type claimBody struct {
	Attempt   int64  `json:"attempt"`
	Instance  string `json:"instance"`
	RequestID string `json:"request_id"`
}

type claimResultJSON struct {
	Request          requestJSON `json:"request"`
	RunToken         string      `json:"run_token"`
	RemainingUSD     float64     `json:"remaining_usd"`
	RemainingSeconds int64       `json:"remaining_seconds"`
}

type parkBody struct {
	Attempt     int64    `json:"attempt"`
	Instance    string   `json:"instance"`
	Kind        ParkKind `json:"kind,omitempty"`
	Reason      string   `json:"reason,omitempty"`
	RequestID   string   `json:"request_id"`
	RunToken    string   `json:"run_token"`
	SpentUSD    float64  `json:"spent_usd,omitempty"`
	Step        string   `json:"step,omitempty"`
	StepHash    string   `json:"step_hash,omitempty"` // ignored: the hub hashes the step it stores
	Tool        string   `json:"tool,omitempty"`
	UsedSeconds int64    `json:"used_seconds,omitempty"`
}

type resultPostBody struct {
	Attempt   int64        `json:"attempt"`
	Instance  string       `json:"instance"`
	Outcome   RequestState `json:"outcome"`
	Reason    FailReason   `json:"reason,omitempty"`
	RequestID string       `json:"request_id"`
	// SecretNames is ignored: older listeners still send the names their
	// run claims it sent.
	SecretNames []string `json:"secret_names,omitempty"`
	SpentUSD    float64  `json:"spent_usd,omitempty"`
	Summary     string   `json:"summary,omitempty"`
	UsedSeconds int64    `json:"used_seconds,omitempty"`
}

type resultAckJSON struct {
	Discarded bool        `json:"discarded"`
	Request   requestJSON `json:"request"`
}

type messageJSON struct {
	Seq       int64     `json:"seq"`
	ID        string    `json:"id"`
	Kind      Kind      `json:"kind"`
	Sender    string    `json:"sender"`
	Target    string    `json:"target"`
	Phase     *Phase    `json:"phase"`
	Body      *string   `json:"body"`
	RequestID *string   `json:"request_id"`
	CreatedAt time.Time `json:"created_at"`
	Delivered bool      `json:"delivered"`
	Read      bool      `json:"read"`
}

type requestJSON struct {
	ID               string       `json:"id"`
	Sender           string       `json:"sender"`
	Target           string       `json:"target"`
	Text             string       `json:"text"`
	SecretNames      []string     `json:"secret_names"` // always empty
	State            RequestState `json:"state"`
	Attempt          int64        `json:"attempt"`
	Instance         *string      `json:"instance"`
	ApprovalCycles   int64        `json:"approval_cycles"`
	Tool             *string      `json:"tool"`
	Step             *string      `json:"step"`
	StepHash         *string      `json:"step_hash"`
	Summary          *string      `json:"summary"`
	ResultSecrets    []string     `json:"result_secrets"` // always empty
	Reason           *FailReason  `json:"reason"`
	CreatedAt        time.Time    `json:"created_at"`
	UpdatedAt        time.Time    `json:"updated_at"`
	DeliveredAt      *time.Time   `json:"delivered_at"`
	ClaimedAt        *time.Time   `json:"claimed_at"`
	ExpiresAt        *time.Time   `json:"expires_at"`
	NotifiedAt       *time.Time   `json:"notified_at"`
	ParentID         *string      `json:"parent_id"`
	ParkKind         *ParkKind    `json:"park_kind"`
	Fingerprint      *string      `json:"fingerprint"`
	ParkReason       *string      `json:"park_reason"`
	PromptID         *string      `json:"prompt_id"`
	SpentUSD         float64      `json:"spent_usd"`
	UsedSeconds      int64        `json:"used_seconds"`
	AllowanceUSD     float64      `json:"allowance_usd"`
	AllowanceSeconds int64        `json:"allowance_seconds"`
}

// requestFrameJSON is a pushed request (SSE event: request).
type requestFrameJSON struct {
	ID             string       `json:"id"`
	Sender         string       `json:"sender"`
	Target         string       `json:"target"`
	Text           string       `json:"text"`
	SecretNames    []string     `json:"secret_names"` // always empty
	State          RequestState `json:"state"`
	Attempt        int64        `json:"attempt"`
	ApprovalCycles int64        `json:"approval_cycles"`
	StepHash       *string      `json:"step_hash"`
	ParentID       *string      `json:"parent_id"`
	CreatedAt      time.Time    `json:"created_at"`
	ExpiresAt      time.Time    `json:"expires_at"`
}

type activityJSON struct {
	Requests []requestJSON `json:"requests"`
	Messages []messageJSON `json:"messages"`
}

// HostJSON is a peer host as the operator sees it.
type HostJSON struct {
	Name              string    `json:"name"`
	Instance          string    `json:"instance"`
	InstanceStartedAt time.Time `json:"instance_started_at"`
	LastSeenAt        time.Time `json:"last_seen_at"`
	AckedSeq          int64     `json:"acked_seq"`
	GateUnverified    bool      `json:"gate_unverified,omitempty"`
	Version           string    `json:"version,omitempty"`
	VersionState      string    `json:"version_state,omitempty"`
}

// HubJSON is the hub's state for the operator (peer-hub status).
type HubJSON struct {
	State   HubState   `json:"state"`
	Detail  string     `json:"detail"`
	Node    string     `json:"node"`
	Version string     `json:"version"`
	IPs     []string   `json:"ips"`
	Hosts   []HostJSON `json:"hosts"`
}

// ApproverJSON is the enrolled phone as the enrolment and admin
// listeners show it.
type ApproverJSON struct {
	KeyID      string    `json:"key_id"`
	Name       string    `json:"name"`
	EnrolledAt time.Time `json:"enrolled_at"`
}

// ApproverStateJSON answers GET /api/peer/approvers: the phone, or null.
type ApproverStateJSON struct {
	Approver *ApproverJSON `json:"approver"`
}

type enrolBody struct {
	Code      string `json:"code"`
	KeyID     string `json:"key_id"`
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
}

// ApproverCodeJSON is a minted enrolment code.
type ApproverCodeJSON struct {
	Code      string    `json:"code"`
	Link      string    `json:"link"`
	ExpiresAt time.Time `json:"expires_at"`
}

func messageOut(m Message) messageJSON {
	out := messageJSON{
		Seq: m.Seq, ID: m.ID, Kind: m.Kind, Sender: m.Sender, Target: m.Target,
		Body: optional(m.Body), RequestID: optional(m.RequestID), CreatedAt: m.CreatedAt,
		Delivered: m.Delivered, Read: m.Read,
	}
	if m.Phase != "" {
		p := m.Phase
		out.Phase = &p
	}
	return out
}

func messagesOut(ms []Message) []messageJSON {
	out := make([]messageJSON, 0, len(ms))
	for _, m := range ms {
		out = append(out, messageOut(m))
	}
	return out
}

func requestOut(r Request) requestJSON {
	out := requestJSON{
		ID: r.ID, Sender: r.Sender, Target: r.Target, Text: r.Text, SecretNames: []string{},
		State: r.State, Attempt: r.Attempt, Instance: optional(r.Instance),
		ApprovalCycles: r.ApprovalCycles, Tool: optional(r.Tool), Step: optional(r.Step), StepHash: optional(r.StepHash),
		Summary: optional(r.Summary), ResultSecrets: []string{}, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
		DeliveredAt: timeOut(r.DeliveredAt), ClaimedAt: timeOut(r.ClaimedAt), ExpiresAt: timeOut(r.ExpiresAt),
		NotifiedAt: timeOut(r.NotifiedAt), ParentID: optional(r.ParentID), Fingerprint: optional(r.Fingerprint),
		ParkReason: optional(r.ParkReason), PromptID: optional(r.PromptID),
		SpentUSD: r.SpentUSD, UsedSeconds: r.UsedSeconds, AllowanceUSD: r.AllowanceUSD, AllowanceSeconds: r.AllowanceSeconds,
	}
	if r.ParkKind != "" {
		k := r.ParkKind
		out.ParkKind = &k
	}
	if r.Reason != "" {
		rr := r.Reason
		out.Reason = &rr
	}
	return out
}

func requestsOut(rs []Request) []requestJSON {
	out := make([]requestJSON, 0, len(rs))
	for _, r := range rs {
		out = append(out, requestOut(r))
	}
	return out
}

func frameOut(r Request) requestFrameJSON {
	return requestFrameJSON{
		ID: r.ID, Sender: r.Sender, Target: r.Target, Text: r.Text, SecretNames: []string{},
		State: r.State, Attempt: r.Attempt, ApprovalCycles: r.ApprovalCycles,
		StepHash: optional(r.StepHash), ParentID: optional(r.ParentID), CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt,
	}
}

func identityOut(c Caller, cancel []string) identityJSON {
	kinds := c.Kinds
	if kinds == nil {
		kinds = []Kind{}
	}
	if cancel == nil {
		cancel = []string{}
	}
	return identityJSON{Node: c.Node, Host: c.Host, Kinds: kinds, Secrets: []string{}, Cancel: cancel}
}

func timeOut(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}
