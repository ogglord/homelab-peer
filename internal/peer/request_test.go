package peer

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// clock is a settable hub clock.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

// reqHub is a hub on a fake clock starting at t0.
func reqHub(t *testing.T) (*hub, *clock) {
	t.Helper()
	h := newHub(t)
	clk := &clock{t: t0}
	h.svc.now = clk.now
	h.svc.started = t0
	return h, clk
}

const haInst = "ha-1"

// testStep is the step the tests park on; stepHash is the hub's hash of it.
const testStep = "rm x"

var stepHash = sha(testStep)

// runExpiry is past a fresh claim's run expiry: the whole time allowance
// plus grace.
const runExpiry = AllowanceSeconds*time.Second + RunGrace + time.Minute

// request sends a request from homelab to target and fails the test on error.
func (h *hub) request(t *testing.T, id, target string) {
	t.Helper()
	res, err := h.svc.Send(context.Background(), homelab, Send{ID: id, Kind: KindRequest, Target: target, Text: "list add-ons"})
	if err != nil || res.State != OutcomeStored {
		t.Fatalf("send request %s = %+v, %v", id, res, err)
	}
}

func (h *hub) hello(t *testing.T, c Caller, instance string, runs ...string) HelloResult {
	t.Helper()
	res, err := h.svc.Hello(context.Background(), c, HelloIn{Instance: instance, StartedAt: t0, Runs: runs})
	if err != nil {
		t.Fatalf("hello %s: %v", instance, err)
	}
	return res
}

// claim claims id for haCaller at attempt and returns its token.
func (h *hub) claim(t *testing.T, id string, attempt int64) string {
	t.Helper()
	_, token, err := h.svc.Claim(context.Background(), haCaller, id, attempt, haInst)
	if err != nil {
		t.Fatalf("claim %s: %v", id, err)
	}
	return token
}

func (h *hub) req(t *testing.T, id string) Request {
	t.Helper()
	r, ok, err := h.svc.st.Request(context.Background(), id)
	if err != nil || !ok {
		t.Fatalf("request %s: %v %v", id, ok, err)
	}
	return r
}

// exec runs SQL on the hub's database through its own handle (test setup only).
func (h *hub) exec(t *testing.T, q string, args ...any) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+h.dbPath+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(q, args...); err != nil {
		t.Fatal(err)
	}
}

// results is every result message of request id.
func (h *hub) results(t *testing.T, id string) []Message {
	t.Helper()
	ms, err := h.svc.Messages(context.Background(), 500)
	if err != nil {
		t.Fatal(err)
	}
	var out []Message
	for _, m := range ms {
		if m.Kind == KindResult && m.RequestID == id {
			out = append(out, m)
		}
	}
	return out
}

// The whole loop over HTTP: the request is pushed as a request frame, the
// listener claims it and gets a token, posts the result, and the requester
// is pushed the result message and reads the outcome through wait.
func TestRequestLoopOverHTTP(t *testing.T) {
	t.Parallel()
	h := newHub(t)
	lab, ha := h.as(t, homelab), h.as(t, haCaller)
	if r := ha.hello(haInst, t0); r.status != http.StatusOK {
		t.Fatalf("hello: %d %s", r.status, r.body)
	}
	if r := lab.hello("lab-1", t0); r.status != http.StatusOK {
		t.Fatalf("hello: %d %s", r.status, r.body)
	}
	haStream, _ := ha.stream(haInst, 0)
	labStream, _ := lab.stream("lab-1", 0)

	r := lab.send(map[string]any{"id": "r1", "kind": "request", "target": "homeassistant", "text": "list add-ons"})
	if res := sendResult(t, r); res.Outcome != OutcomeStored || res.Kind != KindRequest {
		t.Fatalf("send request: %+v", res)
	}
	f, _ := haStream.next()
	var frame requestFrameJSON
	if f.event != "request" || json.Unmarshal([]byte(f.data), &frame) != nil || frame.ID != "r1" || frame.Attempt != 0 ||
		frame.State != ReqWaiting || frame.Text != "list add-ons" || frame.SecretNames == nil {
		t.Fatalf("frame %+v / %+v", f, frame)
	}

	cr := ha.do(http.MethodPost, "/api/peer/claim", map[string]any{"request_id": "r1", "attempt": 0, "instance": haInst})
	var claim claimResultJSON
	if cr.status != http.StatusOK || json.Unmarshal(cr.body, &claim) != nil || claim.RunToken == "" ||
		claim.Request.State != ReqRunning || claim.Request.Attempt != 1 {
		t.Fatalf("claim: %d %s", cr.status, cr.body)
	}
	if again := ha.do(http.MethodPost, "/api/peer/claim", map[string]any{"request_id": "r1", "attempt": 0, "instance": haInst}); again.status != http.StatusConflict || again.code() != "not_claimable" {
		t.Fatalf("duplicate claim: %d %s", again.status, again.body)
	}
	if strings.Contains(string(h.dbBytes(t)), claim.RunToken) {
		t.Fatal("the run token is stored")
	}

	// A status from the run, with its token and no request id, is bound.
	st := sendResult(t, ha.send(map[string]any{"id": "s1", "kind": "status", "target": "homelab", "phase": "progress", "body": "working"}, "X-Peer-Run-Token", claim.RunToken))
	if st.Outcome != OutcomeStored {
		t.Fatalf("status: %+v", st)
	}
	if m, _, _ := h.svc.st.Message(context.Background(), "homeassistant", "s1"); m.RequestID != "r1" {
		t.Fatalf("status not bound to the run's request: %+v", m)
	}
	if ids, _ := labStream.messages(1); ids[0] != "s1" {
		t.Fatalf("lab got %v", ids)
	}

	pr := ha.do(http.MethodPost, "/api/peer/result", map[string]any{"request_id": "r1", "attempt": 1, "instance": haInst, "outcome": "done", "summary": "3 add-ons"})
	var ack resultAckJSON
	if pr.status != http.StatusOK || json.Unmarshal(pr.body, &ack) != nil || ack.Discarded || ack.Request.State != ReqDone {
		t.Fatalf("result: %d %s", pr.status, pr.body)
	}
	f, _ = labStream.next()
	var m messageJSON
	if f.event != "message" || json.Unmarshal([]byte(f.data), &m) != nil || m.Kind != "result" || *m.RequestID != "r1" ||
		*m.Body != "done\n3 add-ons" || m.Sender != "homeassistant" {
		t.Fatalf("result frame %+v", f)
	}

	wr := lab.do(http.MethodGet, "/api/peer/requests/r1?wait=5", nil)
	var got requestJSON
	if wr.status != http.StatusOK || json.Unmarshal(wr.body, &got) != nil || got.State != ReqDone ||
		*got.Summary != "3 add-ons" || got.ExpiresAt != nil {
		t.Fatalf("wait: %d %s", wr.status, wr.body)
	}
	if r := h.as(t, statusOnly).do(http.MethodGet, "/api/peer/requests/r1", nil); r.status != http.StatusForbidden {
		t.Fatalf("third host read the request: %d %s", r.status, r.body)
	}
}

// A wait returns as soon as the request ends.
func TestWaitReturnsAtTheTransition(t *testing.T) {
	t.Parallel()
	h, _ := reqHub(t)
	h.hello(t, haCaller, haInst)
	h.request(t, "r1", "homeassistant")
	h.claim(t, "r1", 0)
	done := make(chan Request, 1)
	go func() {
		r, err := h.svc.Wait(context.Background(), homelab, "r1", MaxWait)
		if err != nil {
			t.Error(err)
		}
		done <- r
	}()
	time.Sleep(50 * time.Millisecond)
	if _, _, err := h.svc.PostResult(context.Background(), haCaller, ResultIn{ID: "r1", Instance: haInst, Attempt: 1, State: ReqFailed, Reason: FailNoOutput}); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-done:
		if r.State != ReqFailed || r.Reason != FailNoOutput {
			t.Fatalf("wait = %+v", r)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("wait did not return at the transition")
	}
}

// Only a caller with the request kind may send one; a reused id is a
// replay or a conflict.
func TestRequestCreation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h, _ := reqHub(t)
	ha := caller("homeassistant", allKinds)
	if _, err := h.svc.Send(ctx, haCaller, Send{ID: "r1", Kind: KindRequest, Target: "homelab", Text: "x"}); !errors.Is(err, ErrNotPermitted) {
		t.Fatalf("caller without the request kind: %v", err)
	}
	h.request(t, "r1", "homeassistant")
	again, err := h.svc.Send(ctx, homelab, Send{ID: "r1", Kind: KindRequest, Target: "homeassistant", Text: "list add-ons"})
	if err != nil || !again.Replayed {
		t.Fatalf("retry = %+v, %v", again, err)
	}
	if _, err := h.svc.Send(ctx, homelab, Send{ID: "r1", Kind: KindRequest, Target: "laptop", Text: "x"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("same id, other target: %v", err)
	}
	if _, err := h.svc.Send(ctx, ha, Send{ID: "r1", Kind: KindRequest, Target: "homeassistant", Text: "x"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("another sender reusing a request id: %v", err)
	}
	if r := h.req(t, "r1"); r.State != ReqWaiting || !r.ExpiresAt.Equal(t0.Add(QueueTTL)) {
		t.Fatalf("row %+v", r)
	}
}

// A status-only identity cannot claim, park or post a result for a request
// addressed to homelab, and the row does not change.
func TestOtherHostCannotTouchRequest(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h, _ := reqHub(t)
	h.hello(t, homelab, "lab-1")
	h.request(t, "q", "homelab")
	h.request(t, "r", "homelab")
	_, token, err := h.svc.Claim(ctx, homelab, "r", 0, "lab-1")
	if err != nil {
		t.Fatal(err)
	}
	before := []Request{h.req(t, "q"), h.req(t, "r")}
	laptop := h.as(t, statusOnly)
	for name, r := range map[string]reply{
		"claim":  laptop.do(http.MethodPost, "/api/peer/claim", map[string]any{"request_id": "q", "attempt": 0, "instance": "lap-1"}),
		"park":   laptop.do(http.MethodPost, "/api/peer/park", map[string]any{"request_id": "r", "attempt": 1, "instance": "lab-1", "run_token": token, "tool": "Bash", "step": "rm -rf /", "step_hash": stepHash}),
		"result": laptop.do(http.MethodPost, "/api/peer/result", map[string]any{"request_id": "r", "attempt": 1, "instance": "lab-1", "outcome": "done"}),
	} {
		if r.status != http.StatusForbidden || r.code() != "not_permitted" {
			t.Errorf("%s: %d %s", name, r.status, r.body)
		}
	}
	// Home Assistant may post results, but not for homelab's request.
	if _, _, err := h.svc.PostResult(ctx, haCaller, ResultIn{ID: "r", Instance: "lab-1", Attempt: 1, State: ReqDone}); !errors.Is(err, ErrNotPermitted) {
		t.Errorf("ha result for a homelab request: %v", err)
	}
	after := []Request{h.req(t, "q"), h.req(t, "r")}
	for i := range before {
		if before[i].State != after[i].State || before[i].Attempt != after[i].Attempt || !before[i].UpdatedAt.Equal(after[i].UpdatedAt) {
			t.Errorf("row changed: %+v -> %+v", before[i], after[i])
		}
	}
}

// Two claims of one delivered request (a duplicate frame, or two listener
// instances): exactly one wins and the row records it.
func TestConcurrentClaimsOneWins(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h, _ := reqHub(t)
	h.hello(t, haCaller, haInst)
	h.request(t, "r1", "homeassistant")
	if ok, err := h.svc.st.MarkDelivered(ctx, "r1", 0, t0); err != nil || !ok {
		t.Fatalf("mark delivered: %v %v", ok, err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	var tokens []string
	for range 8 {
		wg.Go(func() {
			if _, tok, err := h.svc.Claim(ctx, haCaller, "r1", 0, haInst); err == nil {
				mu.Lock()
				tokens = append(tokens, tok)
				mu.Unlock()
			} else if !errors.Is(err, ErrNotClaimable) {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	r := h.req(t, "r1")
	if len(tokens) != 1 || r.State != ReqRunning || r.Instance != haInst || r.Attempt != 1 || r.TokenHash != hashToken(tokens[0]) {
		t.Fatalf("tokens %d, row %+v", len(tokens), r)
	}

	// An instance a newer hello replaced cannot claim.
	h.request(t, "r2", "homeassistant")
	if _, err := h.svc.Hello(ctx, haCaller, HelloIn{Instance: "ha-2", StartedAt: t0.Add(time.Second), Runs: []string{"r1"}}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.svc.Claim(ctx, haCaller, "r2", 0, haInst); !errors.Is(err, ErrSuperseded) {
		t.Fatalf("claim by a replaced instance: %v", err)
	}
}

// One run per host: a second request's claim is refused busy and it stays
// queued; once the first run ends it is pushed again and can be claimed.
func TestOneRunPerHost(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h := newHub(t)
	ha := h.as(t, haCaller)
	ha.hello(haInst, t0)
	s, _ := ha.stream(haInst, 0)
	h.request(t, "r1", "homeassistant")
	h.request(t, "r2", "homeassistant")
	for _, want := range []string{"r1", "r2"} {
		if f, _ := s.next(); f.event != "request" || !strings.Contains(f.data, `"id":"`+want+`"`) {
			t.Fatalf("frame %+v, want %s", f, want)
		}
	}
	h.claim(t, "r1", 0)
	if _, _, err := h.svc.Claim(ctx, haCaller, "r2", 0, haInst); !errors.Is(err, ErrBusy) {
		t.Fatalf("second claim: %v, want busy", err)
	}
	// Busy requeues it; a concurrent push may already have marked it
	// delivered again. Either way it is queued, not running.
	if r := h.req(t, "r2"); r.State != ReqWaiting && r.State != ReqDelivered {
		t.Fatalf("second request %s, want waiting or delivered", r.State)
	}
	if _, _, err := h.svc.PostResult(ctx, haCaller, ResultIn{ID: "r1", Instance: haInst, Attempt: 1, State: ReqDone}); err != nil {
		t.Fatal(err)
	}
	// Request frames may repeat (an early live push can duplicate the
	// replay), so skip any leftover r1 frame before r2's re-push.
	for i := 0; ; i++ {
		f, _ := s.next()
		if f.event == "request" && strings.Contains(f.data, `"id":"r2"`) {
			break
		}
		if i == 3 || f.event != "request" || !strings.Contains(f.data, `"id":"r1"`) {
			t.Fatalf("after the run: %+v, want r2 pushed again", f)
		}
	}
	h.claim(t, "r2", 0)
}

// Every hub-initiated terminal transition leaves exactly one result message.
func TestHubTerminalTransitionsWriteOneResult(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h, clk := reqHub(t)
	h.hello(t, haCaller, haInst)
	h.request(t, "expire", "homeassistant")
	h.request(t, "timeout", "homeassistant")
	h.claim(t, "timeout", 0)

	clk.set(t0.Add(runExpiry))
	if n, err := h.svc.Sweep(ctx, clk.now()); err != nil || n != 1 {
		t.Fatalf("sweep: %d %v", n, err)
	}
	clk.set(t0.Add(QueueTTL + time.Minute))
	if n, err := h.svc.Sweep(ctx, clk.now()); err != nil || n != 1 {
		t.Fatalf("sweep: %d %v", n, err)
	}

	h.request(t, "lease", "homeassistant")
	h.claim(t, "lease", 0)
	clk.set(clk.now().Add(LeaseGrace + time.Second))
	if res := h.hello(t, haCaller, haInst); len(res.Lost) != 1 {
		t.Fatalf("hello lost %v", res.Lost)
	}

	h.request(t, "silent", "homeassistant")
	h.claim(t, "silent", 0)
	clk.set(clk.now().Add(ListenerLostAfter + time.Second))
	if n, err := h.svc.loseSilentHosts(ctx, clk.now()); err != nil || n != 1 {
		t.Fatalf("silent host: %d %v", n, err)
	}

	for id, want := range map[string]string{
		"expire": "expired", "timeout": "failed: timeout", "lease": "failed: listener_lost", "silent": "failed: listener_lost",
	} {
		ms := h.results(t, id)
		if len(ms) != 1 || ms[0].Body != want || ms[0].Sender != "homeassistant" || ms[0].Target != "homelab" {
			t.Errorf("%s: result messages %+v, want one %q", id, ms, want)
		}
	}
	// A second sweep finds nothing and writes nothing.
	if n, _ := h.svc.Sweep(ctx, clk.now().Add(48*time.Hour)); n != 0 {
		t.Fatalf("second sweep ended %d", n)
	}
}

// The state change and its result message are one transaction: when the
// message cannot be written, the request does not change.
func TestFinishIsOneTransaction(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h, clk := reqHub(t)
	h.request(t, "r1", "homeassistant")
	// A message already holding the result's id makes its insert fail.
	h.exec(t, `INSERT INTO peer_messages (id, kind, sender, target, phase, created_at) VALUES (?, 'status', 'homeassistant', 'x', 'info', 1)`, resultMessageID("r1"))
	clk.set(t0.Add(QueueTTL + time.Minute))
	if _, err := h.svc.Sweep(ctx, clk.now()); err == nil {
		t.Fatal("sweep succeeded with a failing message insert")
	}
	if r := h.req(t, "r1"); r.State != ReqWaiting {
		t.Fatalf("state %s after a failed finish, want waiting", r.State)
	}
}

// The sweep expires waiting, delivered, approved and parked requests 24 h
// after they entered that state, and leaves younger ones.
func TestSweepExpiresOnlyDueRequests(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h, clk := reqHub(t)
	h.hello(t, haCaller, haInst)
	for _, id := range []string{"waiting", "delivered", "approved", "parked", "young"} {
		h.request(t, id, "homeassistant")
	}
	if _, err := h.svc.st.MarkDelivered(ctx, "delivered", 0, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	h.exec(t, `UPDATE peer_requests SET state = 'approved' WHERE id = 'approved'`)
	token := h.claim(t, "parked", 0)
	if _, err := h.svc.Park(ctx, haCaller, ParkIn{ID: "parked", Instance: haInst, Token: token, Attempt: 1, Tool: "Bash", Step: testStep}); err != nil {
		t.Fatal(err)
	}
	h.exec(t, `UPDATE peer_requests SET expires_at = ? WHERE id = 'young'`, t0.Add(QueueTTL+2*time.Hour).UnixMilli())

	clk.set(t0.Add(QueueTTL + time.Minute))
	n, err := h.svc.Sweep(ctx, clk.now())
	if err != nil || n != 4 {
		t.Fatalf("sweep: %d %v", n, err)
	}
	for _, id := range []string{"waiting", "delivered", "approved", "parked"} {
		if r := h.req(t, id); r.State != ReqExpired {
			t.Errorf("%s: %s, want expired", id, r.State)
		}
	}
	if r := h.req(t, "young"); r.State != ReqWaiting {
		t.Errorf("young: %s, want waiting", r.State)
	}
}

// dueHook runs its after func between the sweep's read and its
// compare-and-sets.
type dueHook struct {
	Store
	after func()
}

func (d dueHook) DueRequests(ctx context.Context, now time.Time) ([]Request, error) {
	rs, err := d.Store.DueRequests(ctx, now)
	d.after()
	return rs, err
}

// A request that re-entered an expirable state with a fresh expiry after the
// sweep read it (an approval of a parked request) is not expired on the
// stale read: the compare-and-set names the due expiry.
func TestSweepDoesNotExpireAMovedRequest(t *testing.T) {
	t.Parallel()
	var h *hub
	clk := &clock{t: t0}
	h = newHubWith(t, func(s Store) Store {
		return dueHook{s, func() {
			h.exec(t, `UPDATE peer_requests SET state = 'approved', expires_at = ? WHERE id = 'r1'`, clk.now().Add(QueueTTL).UnixMilli())
		}}
	})
	h.svc.now, h.svc.started = clk.now, t0
	h.request(t, "r1", "homeassistant")
	h.exec(t, `UPDATE peer_requests SET state = 'parked' WHERE id = 'r1'`)
	clk.set(t0.Add(QueueTTL + time.Minute))
	if n, err := h.svc.Sweep(context.Background(), clk.now()); err != nil || n != 0 {
		t.Fatalf("sweep ended %d (%v)", n, err)
	}
	if r := h.req(t, "r1"); r.State != ReqApproved {
		t.Fatalf("state %s, want approved", r.State)
	}
}

// writer is one party that can move a request.
type writer struct {
	name string
	run  func(ctx context.Context, h *hub, now time.Time, token string) bool
}

var (
	wSweep = writer{"sweep", func(ctx context.Context, h *hub, now time.Time, _ string) bool {
		n, err := h.svc.Sweep(ctx, now)
		return err == nil && n == 1
	}}
	wClaim = writer{"claim", func(ctx context.Context, h *hub, _ time.Time, _ string) bool {
		_, _, err := h.svc.Claim(ctx, haCaller, "r1", 0, haInst)
		return err == nil
	}}
	wHello = writer{"hello", func(ctx context.Context, h *hub, _ time.Time, _ string) bool {
		res, err := h.svc.Hello(ctx, haCaller, HelloIn{Instance: haInst, StartedAt: t0})
		return err == nil && len(res.Lost) == 1
	}}
	wPark = writer{"park", func(ctx context.Context, h *hub, _ time.Time, token string) bool {
		r, err := h.svc.Park(ctx, haCaller, ParkIn{ID: "r1", Instance: haInst, Token: token, Attempt: 1, Tool: "Bash", Step: testStep})
		return err == nil && r.State == ReqParked
	}}
	wResult = writer{"result", func(ctx context.Context, h *hub, _ time.Time, _ string) bool {
		_, discarded, err := h.svc.PostResult(ctx, haCaller, ResultIn{ID: "r1", Instance: haInst, Attempt: 1, State: ReqDone})
		return err == nil && !discarded
	}}
)

// For every pair of writers that can both move a request in a state, in
// both orders and concurrently, exactly one wins, and a result message
// exists exactly when the winner ended the request.
func TestWritersExactlyOneWins(t *testing.T) {
	t.Parallel()
	queued := []writer{wSweep, wClaim}
	running := []writer{wSweep, wHello, wPark, wResult}
	cases := []struct {
		state   RequestState
		writers []writer
	}{
		{ReqWaiting, queued}, {ReqDelivered, queued}, {ReqApproved, queued}, {ReqRunning, running},
	}
	for _, tc := range cases {
		for i, a := range tc.writers {
			for j, b := range tc.writers {
				if i == j {
					continue
				}
				for _, concurrent := range []bool{false, true} {
					name := string(tc.state) + "/" + a.name + "-then-" + b.name
					if concurrent {
						if i > j {
							continue
						}
						name = string(tc.state) + "/" + a.name + "-with-" + b.name
					}
					t.Run(name, func(t *testing.T) { raceWriters(t, tc.state, a, b, concurrent) })
				}
			}
		}
	}
}

func raceWriters(t *testing.T, state RequestState, a, b writer, concurrent bool) {
	ctx := context.Background()
	h, clk := reqHub(t)
	h.hello(t, haCaller, haInst)
	h.request(t, "r1", "homeassistant")
	var token string
	switch state {
	case ReqDelivered:
		if _, err := h.svc.st.MarkDelivered(ctx, "r1", 0, t0); err != nil {
			t.Fatal(err)
		}
	case ReqApproved:
		h.exec(t, `UPDATE peer_requests SET state = 'approved' WHERE id = 'r1'`)
	case ReqRunning:
		token = h.claim(t, "r1", 0)
	}
	// Late enough that every writer is eligible: the expiry is due and the
	// claim is older than the lease grace.
	if state == ReqRunning {
		clk.set(t0.Add(runExpiry))
	} else {
		clk.set(t0.Add(QueueTTL + time.Minute))
	}
	now := clk.now()
	wins := make([]bool, 2)
	if concurrent {
		var wg sync.WaitGroup
		start := make(chan struct{})
		for k, w := range []writer{a, b} {
			wg.Go(func() {
				<-start
				wins[k] = w.run(ctx, h, now, token)
			})
		}
		close(start)
		wg.Wait()
	} else {
		wins[0] = a.run(ctx, h, now, token)
		wins[1] = b.run(ctx, h, now, token)
	}
	if wins[0] == wins[1] {
		t.Fatalf("wins %s=%v %s=%v, want exactly one", a.name, wins[0], b.name, wins[1])
	}
	r := h.req(t, "r1")
	want := 0
	if r.State.Terminal() {
		want = 1
	}
	if ms := h.results(t, "r1"); len(ms) != want {
		t.Fatalf("state %s with %d result messages", r.State, len(ms))
	}
}

// A listener whose approval gate failed its canary claims nothing and says
// so in its hello. While its instance says so, the hub fails the host's
// waiting and delivered requests with gate_unverified (each requester gets
// the result), and every new one; a run in progress is left alone. A later
// hello without the flag ends it.
func TestGateUnverifiedHelloFailsQueuedRequests(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h, _ := reqHub(t)
	h.hello(t, haCaller, haInst)
	h.request(t, "r1", "homeassistant")
	h.request(t, "r2", "homeassistant")
	h.request(t, "r3", "homeassistant")
	if ok, err := h.svc.st.MarkDelivered(ctx, "r2", 0, t0.Add(-time.Second)); err != nil || !ok {
		t.Fatalf("mark r2 delivered: %v %v", ok, err)
	}
	h.claim(t, "r3", 0)
	flagged := func() bool {
		t.Helper()
		st, err := h.svc.Status(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, x := range st.Hosts {
			if x.Name == "homeassistant" {
				return x.GateUnverified
			}
		}
		t.Fatal("homeassistant not in the hub status")
		return false
	}
	failed := func(id string) {
		t.Helper()
		if r := h.req(t, id); r.State != ReqFailed || r.Reason != FailGateUnverified {
			t.Fatalf("%s: %s %s, want failed gate_unverified", id, r.State, r.Reason)
		}
		if ms := h.results(t, id); len(ms) != 1 || ms[0].Target != "homelab" || ms[0].Body != "failed: gate_unverified" {
			t.Fatalf("%s results: %+v", id, ms)
		}
	}

	r := h.as(t, haCaller).do(http.MethodPost, "/api/peer/hello", map[string]any{
		"instance": haInst, "started_at": t0.Format(time.RFC3339Nano), "runs": []string{"r3"}, "gate_unverified": true,
	})
	if r.status != http.StatusOK {
		t.Fatalf("hello: %d %s", r.status, r.body)
	}
	failed("r1")
	failed("r2")
	if r := h.req(t, "r3"); r.State != ReqRunning {
		t.Fatalf("running r3: %s", r.State)
	}
	if !flagged() {
		t.Error("the hub status does not show the unverified gate")
	}
	h.request(t, "r4", "homeassistant")
	failed("r4")

	h.hello(t, haCaller, haInst, "r3")
	h.request(t, "r5", "homeassistant")
	if r := h.req(t, "r5"); r.State != ReqWaiting {
		t.Fatalf("after a hello without the flag: %s", r.State)
	}
	if flagged() {
		t.Error("the flag outlived a hello without it")
	}
}
