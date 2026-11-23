package peer

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ogglord/homelab-peer/internal/httpx"
)

// Three listeners, three handlers, nothing shared:
//
//   - AgentHandler on the tailnet node: the agent operations under
//     /api/peer, each bound to the caller the connection identifies.
//   - EnrolHandler behind Caddy (peer.<domain>): the phone's enrolment and
//     the approver's state, and a health probe. The operator's page
//     (internal/web) is served on the same listener, behind its sign-in.
//   - AdminHandler on a root-only unix socket inside the stack: mint an
//     enrolment code, revoke the phone, and the hub's state, for the
//     `peer-hub` subcommands.

// apiBase is the prefix every agent and enrolment route is mounted under.
const apiBase = "/api"

// maxAgentBody bounds a request body on the tailnet listener.
const maxAgentBody = 64 << 10

// errNoContent makes a handler answer 204.
var errNoContent = errors.New("no content")

// problem maps domain errors to problems. Every detail is a fixed string,
// never request input.
func problem(err error) error {
	var inv invalidError
	switch {
	case errors.As(err, &inv):
		return httpx.BadRequest("invalid_message", "%s", inv.msg)
	case errors.Is(err, ErrUnknownCaller):
		return httpx.Unauthorized("unknown_caller", "caller identity could not be established")
	case errors.Is(err, ErrNoCapability):
		return httpx.Forbidden("no_capability", "caller has no peer capability")
	case errors.Is(err, ErrNotPermitted):
		return httpx.Forbidden("not_permitted", "not permitted for this caller")
	case errors.Is(err, ErrSenderMismatch):
		return httpx.Forbidden("sender_mismatch", "sender does not match the caller's host")
	case errors.Is(err, ErrConflict):
		return httpx.Conflict("conflict", "message id already used with a different kind, target or request")
	case errors.Is(err, ErrSuperseded):
		return httpx.Conflict("superseded", "a newer listener instance holds this host")
	case errors.Is(err, ErrHelloRequired):
		return httpx.Conflict("hello_required", "say hello before streaming")
	case errors.Is(err, ErrNotFound):
		return httpx.NotFound("unknown_message", "no such message")
	case errors.Is(err, ErrUnknownRequest):
		return httpx.NotFound("unknown_request", "no such request")
	case errors.Is(err, ErrBusy):
		return httpx.Conflict("busy", "the host already has a running request; the request stays queued")
	case errors.Is(err, ErrNotClaimable):
		return httpx.Conflict("not_claimable", "the request is not claimable at this attempt")
	case errors.Is(err, ErrNotRunning):
		return httpx.Conflict("not_running", "the request is not running")
	case errors.Is(err, ErrRunToken):
		return httpx.Forbidden("invalid_run_token", "run token is not valid for this request")
	case errors.Is(err, ErrChildRequest):
		return httpx.Forbidden("child_request", "a request sent by a run may not send requests")
	case errors.Is(err, ErrSelfRequest):
		return httpx.Forbidden("self_request", "a run may not send a request to its own host")
	case errors.Is(err, ErrInvalidCode):
		return httpx.Forbidden("invalid_code", "the enrolment code is wrong, used or expired")
	case errors.Is(err, ErrInvalidKey):
		return httpx.BadRequest("invalid_key", "the public key must be an unpadded base64url P-256 SPKI and key_id its hex SHA-256")
	}
	return err
}

// respond writes out as JSON, or the error as a problem (errNoContent: 204).
func respond(w http.ResponseWriter, r *http.Request, out any, err error) {
	switch {
	case errors.Is(err, errNoContent):
		w.WriteHeader(http.StatusNoContent)
	case err != nil:
		httpx.ResponseError(w, r, problem(err))
	default:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(out)
	}
}

// decode reads a JSON body into v. The problem never quotes the decoder's
// message, which can echo the input.
func decode(r *http.Request, v any) error {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			return &httpx.Problem{Status: http.StatusRequestEntityTooLarge, Code: "request_too_large",
				Title: http.StatusText(http.StatusRequestEntityTooLarge), Detail: "request body is too large"}
		}
		return httpx.BadRequest("bad_request", "request body could not be decoded")
	}
	return nil
}

// queryInt reads an optional integer query parameter (def when absent).
func queryInt(r *http.Request, name string, def int64) (int64, error) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return def, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, httpx.BadRequest("bad_request", "query parameter %s must be an integer", name)
	}
	return n, nil
}

// queryState reads the optional request state filter.
func queryState(r *http.Request) (RequestState, error) {
	st := RequestState(r.URL.Query().Get("state"))
	switch st {
	case "", ReqWaiting, ReqDelivered, ReqRunning, ReqParked, ReqApproved, ReqDone, ReqFailed, ReqDenied, ReqExpired:
		return st, nil
	}
	return "", httpx.BadRequest("invalid_state", "state is not a request state")
}

// ── agent listener ──────────────────────────────────────────────────────

// agentOp is one agent operation: it gets the identified caller.
type agentOp func(r *http.Request, c Caller) (any, error)

// AgentHandler is the tailnet listener's whole handler: identify the caller
// from the connection, then serve the agent operations; anything else is a
// problem+json 404.
func AgentHandler(svc *Service, id Identity, log *slog.Logger) http.Handler {
	ops := map[string]agentOp{
		"POST /peer/hello":                 svc.httpHello,
		"GET /peer/identity":               func(_ *http.Request, c Caller) (any, error) { return identityOut(c, nil), nil },
		"POST /peer/send":                  svc.httpSend,
		"POST /peer/ack":                   svc.httpAck,
		"GET /peer/list":                   svc.httpList,
		"GET /peer/inbox":                  svc.httpInbox,
		"GET /peer/messages/{sender}/{id}": svc.httpRead,
		"POST /peer/claim":                 svc.httpClaim,
		"POST /peer/park":                  svc.httpPark,
		"POST /peer/result":                svc.httpResult,
		"GET /peer/requests/{id}":          svc.httpWait,
	}
	mux := http.NewServeMux()
	for pattern, op := range ops {
		method, path, _ := strings.Cut(pattern, " ")
		mux.HandleFunc(method+" "+apiBase+path, func(w http.ResponseWriter, r *http.Request) {
			c, _ := callerFrom(r.Context())
			out, err := op(r, c)
			respond(w, r, out, err)
		})
	}
	mux.HandleFunc("GET "+apiBase+"/peer/stream", svc.httpStream)
	mux.Handle("/", httpx.NotFoundHandler)
	return httpx.Middleware(log)(identify(id, log, mux))
}

// identify binds the caller to the request from the connection's remote
// address only; forwarded-address headers and body fields play no part.
func identify(id Identity, log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := id.Identify(r.Context(), r.RemoteAddr)
		if err != nil {
			log.Warn("peer caller refused", "remote", r.RemoteAddr, "error", err)
			refused := ErrUnknownCaller
			if errors.Is(err, ErrNoCapability) {
				refused = ErrNoCapability
			}
			httpx.ResponseError(w, r, problem(refused))
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxAgentBody)
		next.ServeHTTP(w, r.WithContext(withCaller(r.Context(), c)))
	})
}

func (s *Service) httpHello(r *http.Request, c Caller) (any, error) {
	var b helloBody
	if err := decode(r, &b); err != nil {
		return nil, err
	}
	res, err := s.Hello(r.Context(), c, HelloIn{
		Instance: b.Instance, StartedAt: b.StartedAt, Runs: b.Runs, GateUnverified: b.GateUnverified, Version: b.Version,
	})
	if err != nil {
		return nil, err
	}
	return identityOut(c, res.Cancel), nil
}

func (s *Service) httpSend(r *http.Request, c Caller) (any, error) {
	var b sendBody
	if err := decode(r, &b); err != nil {
		return nil, err
	}
	res, err := s.Send(r.Context(), c, Send{
		ID: b.ID, Kind: b.Kind, Sender: b.Sender, Target: b.Target, Phase: b.Phase, Body: b.Body,
		RequestID: b.RequestID, Text: b.Text, RunToken: r.Header.Get("X-Peer-Run-Token"),
		Legacy: b.Name != "" || b.Value != "" || len(b.SecretNames) > 0,
	})
	if err != nil {
		return nil, err
	}
	out := sendResultJSON{ID: res.ID, Kind: res.Kind, Outcome: res.State, Replayed: res.Replayed}
	if res.Seq > 0 {
		seq := res.Seq
		out.Seq = &seq
	}
	return out, nil
}

func (s *Service) httpAck(r *http.Request, c Caller) (any, error) {
	var b ackBody
	if err := decode(r, &b); err != nil {
		return nil, err
	}
	if err := s.Ack(r.Context(), c, b.Instance, b.Seq); err != nil {
		return nil, err
	}
	return nil, errNoContent
}

// httpList is the read of recent requests and messages across every host.
// Any identified caller may read it.
func (s *Service) httpList(r *http.Request, _ Caller) (any, error) {
	limit, err := queryInt(r, "limit", 0)
	if err != nil {
		return nil, err
	}
	state, err := queryState(r)
	if err != nil {
		return nil, err
	}
	rs, err := s.Requests(r.Context(), state, int(limit))
	if err != nil {
		return nil, err
	}
	ms, err := s.Messages(r.Context(), int(limit))
	if err != nil {
		return nil, err
	}
	return activityJSON{Requests: requestsOut(rs), Messages: messagesOut(ms)}, nil
}

func (s *Service) httpInbox(r *http.Request, c Caller) (any, error) {
	ms, err := s.Inbox(r.Context(), c)
	if err != nil {
		return nil, err
	}
	return messagesOut(ms), nil
}

func (s *Service) httpRead(r *http.Request, c Caller) (any, error) {
	m, err := s.Read(r.Context(), c, r.PathValue("sender"), r.PathValue("id"))
	if err != nil {
		return nil, err
	}
	return messageOut(m), nil
}

func (s *Service) httpClaim(r *http.Request, c Caller) (any, error) {
	var b claimBody
	if err := decode(r, &b); err != nil {
		return nil, err
	}
	req, token, err := s.Claim(r.Context(), c, b.RequestID, b.Attempt, b.Instance)
	if err != nil {
		return nil, err
	}
	return claimResultJSON{
		Request: requestOut(req), RunToken: token, RemainingUSD: req.RemainingUSD(), RemainingSeconds: req.RemainingSeconds(),
	}, nil
}

func (s *Service) httpPark(r *http.Request, c Caller) (any, error) {
	var b parkBody
	if err := decode(r, &b); err != nil {
		return nil, err
	}
	req, err := s.Park(r.Context(), c, ParkIn{
		ID: b.RequestID, Instance: b.Instance, Token: b.RunToken, Attempt: b.Attempt, Kind: b.Kind,
		Tool: b.Tool, Step: b.Step, StepHash: b.StepHash, Reason: b.Reason,
		SpentUSD: b.SpentUSD, UsedSeconds: b.UsedSeconds,
	})
	if err != nil {
		return nil, err
	}
	return requestOut(req), nil
}

func (s *Service) httpResult(r *http.Request, c Caller) (any, error) {
	var b resultPostBody
	if err := decode(r, &b); err != nil {
		return nil, err
	}
	req, discarded, err := s.PostResult(r.Context(), c, ResultIn{
		ID: b.RequestID, Instance: b.Instance, Attempt: b.Attempt, State: b.Outcome,
		Reason: b.Reason, Summary: b.Summary, SpentUSD: b.SpentUSD, UsedSeconds: b.UsedSeconds,
	})
	if err != nil {
		return nil, err
	}
	return resultAckJSON{Request: requestOut(req), Discarded: discarded}, nil
}

func (s *Service) httpWait(r *http.Request, c Caller) (any, error) {
	wait, err := queryInt(r, "wait", 0)
	if err != nil {
		return nil, err
	}
	req, err := s.Wait(r.Context(), c, r.PathValue("id"), time.Duration(wait)*time.Second)
	if err != nil {
		return nil, err
	}
	return requestOut(req), nil
}

// httpStream pushes the caller's status, results and requests (SSE).
func (s *Service) httpStream(w http.ResponseWriter, r *http.Request) {
	c, _ := callerFrom(r.Context())
	instance := r.URL.Query().Get("instance")
	if instance == "" {
		httpx.ResponseError(w, r, httpx.BadRequest("bad_request", "query parameter instance is required"))
		return
	}
	after, err := queryInt(r, "after", 0)
	if err != nil {
		httpx.ResponseError(w, r, err)
		return
	}
	sub, err := s.Subscribe(r.Context(), c, instance, after)
	if err != nil {
		httpx.ResponseError(w, r, problem(err))
		return
	}
	_ = httpx.Stream{Ctx: r.Context(), Heartbeat: s.Heartbeat(), Run: func(ctx context.Context, emit func(string, any) error) error {
		return sub.Run(ctx,
			func(m Message) error { return emit("message", messageOut(m)) },
			func(rq Request) error { return emit("request", frameOut(rq)) })
	}}.Serve(w)
}

// ── enrolment listener ──────────────────────────────────────────────────

// maxEnrolBody bounds an enrolment body.
const maxEnrolBody = 8 << 10

// EnrolHandler serves the phone's side of approver enrolment behind Caddy:
// GET and POST /api/peer/approvers, and GET /healthz for the stack's health
// probe. Minting a code and revoking are not here (AdminHandler).
func EnrolHandler(svc *Service, log *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+ApproverPath, func(w http.ResponseWriter, r *http.Request) {
		out, err := svc.approverState(r)
		respond(w, r, out, err)
	})
	mux.HandleFunc("POST "+ApproverPath, func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxEnrolBody)
		var b enrolBody
		if err := decode(r, &b); err != nil {
			respond(w, r, nil, err)
			return
		}
		a, err := svc.EnrolApprover(r.Context(), EnrolIn{Code: b.Code, PublicKey: b.PublicKey, KeyID: b.KeyID, Name: b.Name})
		respond(w, r, map[string]string{"key_id": a.KeyID}, err)
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		respond(w, r, map[string]string{"status": "ok"}, nil)
	})
	mux.Handle("/", httpx.NotFoundHandler)
	return httpx.Middleware(log)(mux)
}

func (s *Service) approverState(r *http.Request) (ApproverStateJSON, error) {
	a, ok, err := s.Approver(r.Context())
	if err != nil || !ok {
		return ApproverStateJSON{}, err
	}
	return ApproverStateJSON{Approver: &ApproverJSON{KeyID: a.KeyID, Name: a.Name, EnrolledAt: a.EnrolledAt}}, nil
}

// ── admin socket ────────────────────────────────────────────────────────

// Admin routes (AdminHandler).
const (
	AdminApproverCode = "/approver/code"
	AdminApprover     = "/approver"
	AdminStatus       = "/status"
)

// AdminHandler serves the operator's operations on the hub's unix socket,
// which only root and the hub's own user can open: mint the enrolment
// code, show or revoke the approver, and the hub's state.
func AdminHandler(svc *Service, log *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+AdminApproverCode, func(w http.ResponseWriter, r *http.Request) {
		c := svc.MintApproverCode()
		respond(w, r, ApproverCodeJSON{Code: c.Code, Link: c.Link, ExpiresAt: c.ExpiresAt}, nil)
	})
	mux.HandleFunc("GET "+AdminApprover, func(w http.ResponseWriter, r *http.Request) {
		out, err := svc.approverState(r)
		respond(w, r, out, err)
	})
	mux.HandleFunc("DELETE "+AdminApprover, func(w http.ResponseWriter, r *http.Request) {
		err := svc.RevokeApprover(r.Context())
		if err == nil {
			err = errNoContent
		}
		respond(w, r, nil, err)
	})
	mux.HandleFunc("GET "+AdminStatus, func(w http.ResponseWriter, r *http.Request) {
		out, err := svc.Hub(r.Context())
		respond(w, r, out, err)
	})
	mux.Handle("/", httpx.NotFoundHandler)
	return httpx.Middleware(log)(mux)
}

// Hub is the hub's state with each host's version compared to the hub's,
// for the operator: `peer-hub status` and the page.
func (s *Service) Hub(ctx context.Context) (HubJSON, error) {
	st, err := s.Status(ctx)
	if err != nil {
		return HubJSON{}, err
	}
	hosts := make([]HostJSON, 0, len(st.Hosts))
	for _, x := range st.Hosts {
		hosts = append(hosts, HostJSON{
			Name: x.Name, Instance: x.Instance, InstanceStartedAt: x.InstanceStartedAt,
			LastSeenAt: x.LastSeenAt, AckedSeq: x.AckedSeq, GateUnverified: x.GateUnverified,
			Version: x.Version, VersionState: versionState(x.Version, s.cfg.Version),
		})
	}
	return HubJSON{State: st.State, Detail: st.Detail, Node: st.Node, Version: s.cfg.Version, IPs: st.IPs, Hosts: hosts}, nil
}

// versionState compares a listener's reported build commit with the hub's:
// both are hex revisions, the listener's usually short (and "-dirty" when
// built from a dirty tree). Anything else is unknown.
func versionState(version, hubCommit string) string {
	v := strings.TrimSuffix(version, "-dirty")
	if len(v) < 7 || !isHex(v) || len(hubCommit) < 7 || !isHex(hubCommit) {
		return "unknown"
	}
	n := min(len(v), len(hubCommit))
	if strings.EqualFold(v[:n], hubCommit[:n]) {
		return "current"
	}
	return "behind"
}

func isHex(s string) bool {
	for _, r := range s {
		if !strings.ContainsRune("0123456789abcdefABCDEF", r) {
			return false
		}
	}
	return true
}
