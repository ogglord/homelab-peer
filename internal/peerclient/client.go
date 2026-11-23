// Package peerclient is the agent side of the peer hub (internal/peer): a
// small HTTP client for the hub's agent operations, an SSE reader and the
// listener loop. It backs cmd/peer, a static binary that runs on every host,
// so it must not import internal/peer, tailscale.com or anything with cgo.
//
// The structs mirror the hub's wire types (internal/peer/wire.go).
package peerclient

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type Hello struct {
	Instance  string    `json:"instance"`
	StartedAt time.Time `json:"started_at"`
	// Runs is the lease report: the request ids this listener still runs,
	// including a claim in flight and a result or park not yet reported.
	Runs []string `json:"runs,omitempty"`
	// GateUnverified says the run gate's canary has not passed on this
	// host, so the listener claims nothing.
	GateUnverified bool `json:"gate_unverified,omitempty"`
	// Version is the peer binary's build commit; the hub shows it per host.
	Version string `json:"version,omitempty"`
}

// Identity is PeerIdentity: the caller as the hub sees it.
type Identity struct {
	Node  string   `json:"node"`
	Host  string   `json:"host"`
	Kinds []string `json:"kinds"`
	// Cancel (hello only) lists the reported runs the hub no longer holds
	// as running for this instance; the listener stops them.
	Cancel []string `json:"cancel"`
}

type Send struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Sender    string `json:"sender,omitempty"`
	Target    string `json:"target"`
	Phase     string `json:"phase,omitempty"`
	Body      string `json:"body,omitempty"`
	Text      string `json:"text,omitempty"` // request only
	RequestID string `json:"request_id,omitempty"`
}

type SendResult struct {
	ID       string  `json:"id"`
	Kind     string  `json:"kind"`
	Outcome  string  `json:"outcome"`
	Reason   *string `json:"reason"`
	Seq      *int64  `json:"seq,omitempty"`
	Replayed bool    `json:"replayed"`
}

// Message kinds a client sends.
const (
	KindRequest = "request"
	KindStatus  = "status"
)

// OutcomeStored is the outcome of an accepted request or status.
const OutcomeStored = "stored"

// Problem codes the client acts on.
const (
	CodeSuperseded      = "superseded"
	CodeNoCapability    = "no_capability"
	CodeBusy            = "busy"
	CodeNotClaimable    = "not_claimable"
	CodeNotRunning      = "not_running"
	CodeRunTokenRequest = "run_token_request"
)

// Accepted reports whether the hub took the message.
func (r SendResult) Accepted() bool { return r.Outcome == OutcomeStored }

type Message struct {
	Seq       int64     `json:"seq"`
	ID        string    `json:"id"`
	Kind      string    `json:"kind"`
	Sender    string    `json:"sender"`
	Target    string    `json:"target"`
	Phase     *string   `json:"phase"`
	Body      *string   `json:"body"`
	RequestID *string   `json:"request_id"`
	CreatedAt time.Time `json:"created_at"`
	Delivered bool      `json:"delivered"`
	Read      bool      `json:"read"`
}

// Phases is the fixed set a status carries (PeerPhase).
var Phases = []string{"info", "started", "progress", "blocked", "done", "failed"}

// Problem is a problem+json answer from the hub.
type Problem struct {
	Status int    `json:"status"`
	Code   string `json:"code"`
	Title  string `json:"title"`
	Detail string `json:"detail"`
}

func (p *Problem) Error() string {
	if p.Detail != "" {
		return fmt.Sprintf("hub answered %d %s: %s", p.Status, p.Code, p.Detail)
	}
	return fmt.Sprintf("hub answered %d %s", p.Status, p.Code)
}

// IsProblem reports whether err is a hub problem with this code.
func IsProblem(err error, code string) bool {
	var p *Problem
	return errors.As(err, &p) && p.Code == code
}

// UnreachableError is a request that never got an HTTP answer from the hub.
type UnreachableError struct {
	Hub string
	Err error
}

func (e *UnreachableError) Error() string { return fmt.Sprintf("hub %s unreachable: %v", e.Hub, e.Err) }
func (e *UnreachableError) Unwrap() error { return e.Err }

// EnvHubURL names the hub origin in the environment: the --hub default, and
// what the launcher hands a run so its peer commands reach the same hub.
const EnvHubURL = "PEER_HUB_URL"

// requestTimeout bounds every request but the stream; a long poll gets its
// wait on top.
const requestTimeout = 30 * time.Second

// MaxWait is the longest single wait the hub serves; longer waits repeat
// it.
const MaxWait = 60 * time.Second

// Client talks to one hub's agent operations.
type Client struct {
	base string // origin, no trailing slash, no /api
	http *http.Client
	// RunToken, when set, goes along with every Send as X-Peer-Run-Token,
	// binding the message to the run's request. The caller fills it in (the
	// peer CLI from PEER_RUN_TOKEN); the client never reads the environment.
	RunToken string
}

// New returns a client for the hub at hubURL, its tailnet origin such as
// http://100.64.0.1:7790 (a trailing /api is accepted; a missing scheme means
// http).
func New(hubURL string) (*Client, error) {
	u := strings.TrimSpace(hubURL)
	if u == "" {
		return nil, errors.New("no hub address: pass --hub or set " + EnvHubURL)
	}
	if !strings.Contains(u, "://") {
		u = "http://" + u
	}
	parsed, err := url.Parse(u)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, fmt.Errorf("hub address %q is not an http URL", hubURL)
	}
	u = strings.TrimSuffix(strings.TrimRight(u, "/"), "/api")
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	return &Client{base: u, http: &http.Client{Transport: &http.Transport{
		DialContext:           dialer.DialContext,
		ResponseHeaderTimeout: requestTimeout + MaxWait,
		MaxIdleConns:          4,
		IdleConnTimeout:       90 * time.Second,
	}}}, nil
}

// Base is the hub origin the client dials.
func (c *Client) Base() string { return c.base }

// HostPort is the hub's host:port, for a plain TCP reach check.
func (c *Client) HostPort() string {
	u, _ := url.Parse(c.base)
	if u.Port() != "" {
		return u.Host
	}
	if u.Scheme == "https" {
		return net.JoinHostPort(u.Hostname(), "443")
	}
	return net.JoinHostPort(u.Hostname(), "80")
}

// Hello registers this listener instance and answers the caller's identity.
func (c *Client) Hello(ctx context.Context, h Hello) (Identity, error) {
	h.StartedAt = h.StartedAt.UTC()
	var id Identity
	return id, c.do(ctx, http.MethodPost, "/peer/hello", h, &id)
}

// Identity answers the caller's identity without registering a listener.
func (c *Client) Identity(ctx context.Context) (Identity, error) {
	var id Identity
	return id, c.do(ctx, http.MethodGet, "/peer/identity", nil, &id)
}

// Send sends one request or status. A decided refusal is a
// SendResult, not an error. With RunToken set the run token goes along as
// X-Peer-Run-Token, which binds the message to the run's
// request; the hub refuses a request sent with one.
func (c *Client) Send(ctx context.Context, s Send) (SendResult, error) {
	var r SendResult
	var hdr http.Header
	if c.RunToken != "" {
		hdr = http.Header{"X-Peer-Run-Token": {c.RunToken}}
	}
	return r, c.doWith(ctx, http.MethodPost, "/peer/send", hdr, 0, s, &r)
}

// SendRequest sends a request for target to run.
func (c *Client) SendRequest(ctx context.Context, id, target, text string) (SendResult, error) {
	return c.Send(ctx, Send{ID: id, Kind: KindRequest, Target: target, Text: text})
}

type Request struct {
	ID             string     `json:"id"`
	Sender         string     `json:"sender"`
	Target         string     `json:"target"`
	Text           string     `json:"text"`
	State          string     `json:"state"`
	Attempt        int64      `json:"attempt"`
	Instance       *string    `json:"instance"`
	ApprovalCycles int64      `json:"approval_cycles"`
	Tool           *string    `json:"tool"`
	Step           *string    `json:"step"`
	StepHash       *string    `json:"step_hash"`
	Reason         *string    `json:"reason"`
	Summary        *string    `json:"summary"`
	ParentID       *string    `json:"parent_id"`
	ParkKind       *string    `json:"park_kind"`
	ParkReason     *string    `json:"park_reason"`
	SpentUSD       float64    `json:"spent_usd"`
	UsedSeconds    int64      `json:"used_seconds"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	DeliveredAt    *time.Time `json:"delivered_at"`
	ClaimedAt      *time.Time `json:"claimed_at"`
	ExpiresAt      *time.Time `json:"expires_at"`
}

// Request states the client acts on (PeerRequestState).
const (
	StateApproved = "approved"
	StateParked   = "parked"
	StateDone     = "done"
	StateFailed   = "failed"
	StateDenied   = "denied"
	StateExpired  = "expired"
)

// Terminal reports whether the request has ended: done, failed, denied or
// expired.
func (r Request) Terminal() bool {
	switch r.State {
	case StateDone, StateFailed, StateDenied, StateExpired:
		return true
	}
	return false
}

// RequestFrame is a pushed request (`event: request`). It
// has no sequence and may arrive more than once; claiming it with its
// Attempt is what starts at most one run.
type RequestFrame struct {
	ID             string    `json:"id"`
	Sender         string    `json:"sender"`
	Target         string    `json:"target"`
	Text           string    `json:"text"`
	State          string    `json:"state"`
	Attempt        int64     `json:"attempt"`
	ApprovalCycles int64     `json:"approval_cycles"`
	StepHash       *string   `json:"step_hash"`
	ParentID       *string   `json:"parent_id"`
	CreatedAt      time.Time `json:"created_at"`
	ExpiresAt      time.Time `json:"expires_at"`
}

type ClaimResult struct {
	Request  Request `json:"request"`
	RunToken string  `json:"run_token"`
	// RemainingUSD and RemainingSeconds are the request's allowance left:
	// the run's budget and deadline.
	RemainingUSD     float64 `json:"remaining_usd"`
	RemainingSeconds int64   `json:"remaining_seconds"`
}

// Claim starts a run of a pushed request at the frame's attempt for this
// listener instance and returns its run token (409 busy, not_claimable or
// superseded when it cannot).
func (c *Client) Claim(ctx context.Context, requestID string, attempt int64, instance string) (ClaimResult, error) {
	var r ClaimResult
	return r, c.do(ctx, http.MethodPost, "/peer/claim", map[string]any{
		"request_id": requestID, "attempt": attempt, "instance": instance,
	}, &r)
}

type ParkPost struct {
	RequestID   string  `json:"request_id"`
	Attempt     int64   `json:"attempt"`
	Instance    string  `json:"instance"`
	RunToken    string  `json:"run_token"`
	Kind        string  `json:"kind,omitempty"` // step (default) or limit
	Tool        string  `json:"tool,omitempty"`
	Step        string  `json:"step,omitempty"`
	StepHash    string  `json:"step_hash,omitempty"` // 64 hex digits; empty for a limit park
	Reason      string  `json:"reason,omitempty"`
	SpentUSD    float64 `json:"spent_usd"`
	UsedSeconds int64   `json:"used_seconds"`
}

// Park records a run's blocked step, or its reaching the allowance, and
// parks its request.
func (c *Client) Park(ctx context.Context, p ParkPost) (Request, error) {
	var r Request
	return r, c.do(ctx, http.MethodPost, "/peer/park", p, &r)
}

type ResultPost struct {
	RequestID   string  `json:"request_id"`
	Attempt     int64   `json:"attempt"`
	Instance    string  `json:"instance"`
	Outcome     string  `json:"outcome"`          // done or failed
	Reason      string  `json:"reason,omitempty"` // failed only
	Summary     string  `json:"summary,omitempty"`
	SpentUSD    float64 `json:"spent_usd"`
	UsedSeconds int64   `json:"used_seconds"`
}

type ResultAck struct {
	Request   Request `json:"request"`
	Discarded bool    `json:"discarded"`
}

// PostResult finishes a running request with the listener's derived outcome.
func (c *Client) PostResult(ctx context.Context, p ResultPost) (ResultAck, error) {
	var r ResultAck
	return r, c.do(ctx, http.MethodPost, "/peer/result", p, &r)
}

// Wait reads a request, waiting up to wait (at most MaxWait) for it to end.
func (c *Client) Wait(ctx context.Context, id string, wait time.Duration) (Request, error) {
	wait = min(max(wait, 0), MaxWait)
	secs := int(wait / time.Second)
	var r Request
	return r, c.doWith(ctx, http.MethodGet, "/peer/requests/"+url.PathEscape(id)+"?wait="+strconv.Itoa(secs), nil, time.Duration(secs)*time.Second, nil, &r)
}

// RunAPI is the hub's run-scoped operations for the run launcher and the
// park hook.
func (c *Client) RunAPI() HubRunAPI { return runAPI{c} }

type runAPI struct{ c *Client }

// Hub field limits (PeerResultPost). A step is never cut: the hub hashes
// the text it receives, and the hook parks no longer step (maxStepRunes).
const maxSummaryRunes = 4096

func (a runAPI) Park(ctx context.Context, r ParkRequest) error {
	_, err := a.c.Park(ctx, ParkPost{
		RequestID: r.RequestID, Attempt: int64(r.Attempt), Instance: r.Instance, RunToken: r.Token, Kind: r.Kind,
		Tool: r.Tool, Step: r.Step, StepHash: strings.TrimPrefix(r.Hash, stepHashPrefix),
		Reason: truncRunes(r.Reason, maxParkReason), SpentUSD: r.SpentUSD, UsedSeconds: r.UsedSeconds,
	})
	return err
}

// PostResult maps a derived outcome onto the hub's result: a failure's
// reason code goes in reason, and its reason text (naming the session) leads
// the summary. Completed actions have no field on the hub and are not sent.
func (a runAPI) PostResult(ctx context.Context, r ResultRequest) error {
	p := ResultPost{
		RequestID: r.RequestID, Attempt: int64(r.Attempt), Instance: r.Instance, Outcome: r.Outcome,
		Summary:  r.Summary,
		SpentUSD: r.SpentUSD, UsedSeconds: r.UsedSeconds,
	}
	switch r.Outcome {
	case RunDone:
	case RunFailed:
		p.Reason = r.Code
		if p.Reason == "" {
			p.Reason = ReasonRunFailed
		}
		if r.Reason != "" {
			p.Summary = strings.TrimSpace(r.Reason + "\n" + r.Summary)
		}
	default:
		return fmt.Errorf("a %s run has no result to post", r.Outcome)
	}
	p.Summary = truncRunes(p.Summary, maxSummaryRunes)
	_, err := a.c.PostResult(ctx, p)
	return err
}

func truncRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n-1]) + "…"
}

// Ack acknowledges every message up to seq for this instance's host.
func (c *Client) Ack(ctx context.Context, instance string, seq int64) error {
	return c.do(ctx, http.MethodPost, "/peer/ack", map[string]any{"seq": seq, "instance": instance}, nil)
}

// Inbox lists the unread messages addressed to the caller's host.
func (c *Client) Inbox(ctx context.Context) ([]Message, error) {
	var ms []Message
	return ms, c.do(ctx, http.MethodGet, "/peer/inbox", nil, &ms)
}

// Activity is the hub's read-only view of recent requests and messages
// across every host. Items are kept raw so the CLI prints them in the API's
// own shapes (PeerRequest, PeerMessage) without dropping fields.
type Activity struct {
	Requests []json.RawMessage `json:"requests"`
	Messages []json.RawMessage `json:"messages"`
}

// List returns recent requests (only those in state, when set) and
// messages, each newest first. limit <= 0 leaves the hub's default.
func (c *Client) List(ctx context.Context, limit int, state string) (Activity, error) {
	q := url.Values{}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	if state != "" {
		q.Set("state", state)
	}
	path := "/peer/list"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	var a Activity
	if err := c.do(ctx, http.MethodGet, path, nil, &a); err != nil {
		return Activity{}, err
	}
	if a.Requests == nil {
		a.Requests = []json.RawMessage{}
	}
	if a.Messages == nil {
		a.Messages = []json.RawMessage{}
	}
	return a, nil
}

// Read returns one message and marks it read when the caller is its target.
func (c *Client) Read(ctx context.Context, sender, id string) (Message, error) {
	var m Message
	return m, c.do(ctx, http.MethodGet, "/peer/messages/"+url.PathEscape(sender)+"/"+url.PathEscape(id), nil, &m)
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	return c.doWith(ctx, method, path, nil, 0, body, out)
}

// doWith is do with extra headers and wait on top of the request timeout.
func (c *Client) doWith(ctx context.Context, method, path string, hdr http.Header, wait time.Duration, body, out any) error {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout+wait)
	defer cancel()
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(raw)
	}
	resp, err := c.send(ctx, method, path, hdr, rd)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return readProblem(resp)
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decoding hub answer to %s %s: %w", method, path, err)
	}
	return nil
}

// send issues one request; a transport failure is an UnreachableError.
func (c *Client) send(ctx context.Context, method, path string, hdr http.Header, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.base+"/api"+path, body)
	if err != nil {
		return nil, err
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json, application/problem+json, text/event-stream")
	resp, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil && errors.Is(err, context.Canceled) {
			return nil, ctx.Err()
		}
		return nil, &UnreachableError{Hub: c.base, Err: err}
	}
	return resp, nil
}

func readProblem(resp *http.Response) error {
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	p := &Problem{}
	if json.Unmarshal(raw, p) != nil || p.Code == "" {
		p = &Problem{Code: "http_" + fmt.Sprint(resp.StatusCode), Title: http.StatusText(resp.StatusCode)}
	}
	if p.Status == 0 {
		p.Status = resp.StatusCode
	}
	return p
}

// NewID returns a random URL-safe message id (22 characters), generated once
// before the first attempt so a retry replays instead of sending twice.
func NewID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b) // never fails (crypto/rand panics instead)
	return base64.RawURLEncoding.EncodeToString(b)
}
