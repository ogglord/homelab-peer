package approvals

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ogglord/homelab-peer/internal/hemma"
	"github.com/ogglord/homelab-peer/internal/peer"
	"github.com/ogglord/homelab-peer/internal/store"
)

// phone is a test approver key.
type phone struct {
	key *ecdsa.PrivateKey
	a   peer.Approver
}

func newPhone(t *testing.T, name string) phone {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return phone{k, peer.Approver{KeyID: hemma.KeyID(der), PublicKey: base64.RawURLEncoding.EncodeToString(der), Name: name}}
}

// decide signs a decision the way the phone does.
func (p phone) decide(t *testing.T, seq int64, request string, round int64, fp, decision string, expires int64) hemma.Decision {
	t.Helper()
	sum := sha256.Sum256([]byte(hemma.SignedText(request, round, fp, decision, expires)))
	sig, err := ecdsa.SignASN1(rand.Reader, p.key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return hemma.Decision{Seq: seq, ID: fmt.Sprintf("ap_%d", seq), Request: request, Round: round, Fingerprint: fp,
		Decision: decision, ExpiresAt: expires, KeyID: p.a.KeyID, Signature: base64.RawURLEncoding.EncodeToString(sig)}
}

// fakeHub is the peer service side: the enrolled approver and ApplyDecision.
type fakeHub struct {
	mu       sync.Mutex
	approver *peer.Approver
	applied  []peer.Decision
	refuse   error // ApplyDecision's answer
}

func (h *fakeHub) Approver(context.Context) (peer.Approver, bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.approver == nil {
		return peer.Approver{}, false, nil
	}
	return *h.approver, true, nil
}

func (h *fakeHub) ApplyDecision(_ context.Context, d peer.Decision) (peer.Request, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.refuse != nil {
		return peer.Request{}, h.refuse
	}
	h.applied = append(h.applied, d)
	return peer.Request{ID: d.RequestID}, nil
}

func (h *fakeHub) appliedCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.applied)
}

type stateCall struct{ id, state, note string }

// hemmaHub is a fake Hemma hub: it hands out queued decisions after a
// cursor and records state reports; reported answers 409 for an approval
// reported before, as the hub does.
type hemmaHub struct {
	mu        sync.Mutex
	decisions []hemma.Decision
	afters    []string
	states    []stateCall
	reported  map[string]bool
	prompts   []map[string]any
	status    int // non-zero: every call answers it
}

func newHemmaHub(t *testing.T) (*hemmaHub, *hemma.Client) {
	t.Helper()
	h := &hemmaHub{reported: map[string]bool{}}
	srv := httptest.NewServer(http.HandlerFunc(h.serve))
	t.Cleanup(srv.Close)
	tok := filepath.Join(t.TempDir(), "TOKEN")
	if err := os.WriteFile(tok, []byte("0123456789abcdef0123456789abcdef"), 0o600); err != nil {
		t.Fatal(err)
	}
	return h, &hemma.Client{BaseURL: srv.URL, TokenFile: tok}
}

func (h *hemmaHub) serve(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.status != 0 {
		w.WriteHeader(h.status)
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/homelab/decisions":
		after := r.URL.Query().Get("after")
		h.afters = append(h.afters, after)
		var n int64
		_, _ = fmt.Sscan(after, &n)
		out := hemma.Decisions{Decisions: []hemma.Decision{}, Cursor: n}
		for _, d := range h.decisions {
			if d.Seq > n {
				out.Decisions = append(out.Decisions, d)
				out.Cursor = d.Seq
			}
		}
		_ = json.NewEncoder(w).Encode(out)
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/state"):
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/homelab/approvals/"), "/state")
		var b struct{ State, Note string }
		_ = json.NewDecoder(r.Body).Decode(&b)
		h.states = append(h.states, stateCall{id, b.State, b.Note})
		if h.reported[id] {
			w.WriteHeader(http.StatusConflict)
			_, _ = io.WriteString(w, `{"error":"state cannot change that way"}`)
			return
		}
		h.reported[id] = true
		_, _ = io.WriteString(w, `{}`)
	case r.Method == http.MethodPost && r.URL.Path == "/homelab/approvals":
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		h.prompts = append(h.prompts, b)
		_, _ = io.WriteString(w, `{"id":"ap_new","repeat":false,"sent":1,"failed":0}`)
	default:
		http.NotFound(w, r)
	}
}

func (h *hemmaHub) stateCalls() []stateCall {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]stateCall(nil), h.states...)
}

func openStore(t *testing.T, path string) *store.Store {
	t.Helper()
	s, err := store.Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// logBuffer collects warnings and errors: replays must leave none.
type logBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

type pollerEnv struct {
	hemma  *hemmaHub
	hub    *fakeHub
	phone  phone
	poller *Poller
	meta   *store.Store
	logs   *logBuffer
	dbPath string
}

func newPollerEnv(t *testing.T) *pollerEnv {
	t.Helper()
	hh, client := newHemmaHub(t)
	ph := newPhone(t, "Admin")
	a := ph.a
	fh := &fakeHub{approver: &a}
	dbPath := filepath.Join(t.TempDir(), "homelab.db")
	st := openStore(t, dbPath)
	t.Cleanup(func() { st.Close() })
	logs := &logBuffer{}
	p := &Poller{Client: client, Hub: fh, Meta: st, Wait: 0,
		Log: slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelWarn}))}
	return &pollerEnv{hemma: hh, hub: fh, phone: ph, poller: p, meta: st, logs: logs, dbPath: dbPath}
}

const fp = "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"

var future = time.Now().Add(time.Hour).Unix()

func TestValidDecisionIsAppliedReportedAndCursorStored(t *testing.T) {
	t.Parallel()
	e := newPollerEnv(t)
	e.hemma.decisions = []hemma.Decision{e.phone.decide(t, 3, "req_1", 2, fp, hemma.DecisionApprove, future)}
	if err := e.poller.poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(e.hub.applied) != 1 {
		t.Fatalf("applied = %+v", e.hub.applied)
	}
	want := peer.Decision{RequestID: "req_1", Round: 2, Fingerprint: fp, Approve: true, ExpiresAt: time.Unix(future, 0)}
	if got := e.hub.applied[0]; got.RequestID != want.RequestID || got.Round != want.Round || got.Fingerprint != want.Fingerprint ||
		got.Approve != want.Approve || !got.ExpiresAt.Equal(want.ExpiresAt) {
		t.Fatalf("applied %+v, want %+v", got, want)
	}
	if got := e.hemma.stateCalls(); len(got) != 1 || got[0] != (stateCall{"ap_3", hemma.StateApplied, ""}) {
		t.Fatalf("states = %+v", got)
	}
	if v, ok, _ := e.meta.Meta(context.Background(), MetaCursor); !ok || v != "3" {
		t.Fatalf("cursor = %q (set %v), want 3", v, ok)
	}
}

func TestDenyIsApplied(t *testing.T) {
	t.Parallel()
	e := newPollerEnv(t)
	e.hemma.decisions = []hemma.Decision{e.phone.decide(t, 1, "req_1", 1, fp, hemma.DecisionDeny, future)}
	if err := e.poller.poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(e.hub.applied) != 1 || e.hub.applied[0].Approve {
		t.Fatalf("applied = %+v", e.hub.applied)
	}
}

func TestRefusedDecisions(t *testing.T) {
	t.Parallel()
	other := newPhone(t, "Other")
	cases := map[string]struct {
		decision func(e *pollerEnv) hemma.Decision
		setup    func(e *pollerEnv)
		note     string
	}{
		"bad signature": {
			decision: func(e *pollerEnv) hemma.Decision {
				d := e.phone.decide(t, 1, "req_1", 2, fp, hemma.DecisionApprove, future)
				d.Decision = hemma.DecisionDeny // signed approve, claims deny
				return d
			},
			note: noteBadSignature,
		},
		"signed by another key": {
			decision: func(e *pollerEnv) hemma.Decision {
				d := other.decide(t, 1, "req_1", 2, fp, hemma.DecisionApprove, future)
				d.KeyID = e.phone.a.KeyID // claims the enrolled key's id
				return d
			},
			note: noteBadSignature,
		},
		"wrong key id": {
			decision: func(e *pollerEnv) hemma.Decision {
				return other.decide(t, 1, "req_1", 2, fp, hemma.DecisionApprove, future)
			},
			note: noteNotEnrolled,
		},
		"no phone enrolled": {
			decision: func(e *pollerEnv) hemma.Decision {
				return e.phone.decide(t, 1, "req_1", 2, fp, hemma.DecisionApprove, future)
			},
			setup: func(e *pollerEnv) { e.hub.approver = nil },
			note:  noteNoApprover,
		},
		"stale round": {
			decision: func(e *pollerEnv) hemma.Decision {
				return e.phone.decide(t, 1, "req_1", 2, fp, hemma.DecisionApprove, future)
			},
			setup: func(e *pollerEnv) { e.hub.refuse = peer.RefusedStale },
			note:  string(peer.RefusedStale),
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e := newPollerEnv(t)
			if c.setup != nil {
				c.setup(e)
			}
			e.hemma.decisions = []hemma.Decision{c.decision(e)}
			if err := e.poller.poll(context.Background()); err != nil {
				t.Fatal(err)
			}
			if len(e.hub.applied) != 0 {
				t.Fatalf("applied %+v", e.hub.applied)
			}
			if got := e.hemma.stateCalls(); len(got) != 1 || got[0] != (stateCall{"ap_1", hemma.StateRefused, c.note}) {
				t.Fatalf("states = %+v, want refused %q", got, c.note)
			}
			if v, _, _ := e.meta.Meta(context.Background(), MetaCursor); v != "1" {
				t.Fatalf("cursor = %q, want 1", v)
			}
		})
	}
}

// A replay (the hub hands the same decision out again, as after its own
// restore) neither applies twice nor reports a refusal nor logs a warning.
func TestReplayOfAppliedDecisionIsQuiet(t *testing.T) {
	t.Parallel()
	e := newPollerEnv(t)
	d := e.phone.decide(t, 1, "req_1", 2, fp, hemma.DecisionApprove, future)
	e.hemma.decisions = []hemma.Decision{d}
	if err := e.poller.poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The request has left parked: the real hub would refuse it now.
	e.hub.refuse = peer.RefusedNotParked
	// The hub's data was restored: the stored cursor is past anything it
	// hands out, so it replays from 0.
	if err := e.meta.SetMeta(context.Background(), MetaCursor, "0"); err != nil {
		t.Fatal(err)
	}
	if err := e.poller.poll(context.Background()); err != nil {
		t.Fatalf("replay: %v", err)
	}
	if e.hub.appliedCount() != 1 {
		t.Fatalf("applied %d times", e.hub.appliedCount())
	}
	got := e.hemma.stateCalls()
	if len(got) != 2 || got[1].state != hemma.StateApplied {
		t.Fatalf("states = %+v, want applied reported again (answered 409)", got)
	}
	if l := e.logs.String(); l != "" {
		t.Fatalf("replay logged: %s", l)
	}
}

// Applied but the state report failed: the cursor stays, the next poll gets
// the decision again and reports it applied without applying it twice.
func TestStateReportFailureRetriesWithoutReapplying(t *testing.T) {
	t.Parallel()
	e := newPollerEnv(t)
	e.hemma.decisions = []hemma.Decision{e.phone.decide(t, 1, "req_1", 2, fp, hemma.DecisionApprove, future)}
	failing := &failingState{hemmaHub: e.hemma, failures: 1}
	srv := httptest.NewServer(failing)
	t.Cleanup(srv.Close)
	e.poller.Client.BaseURL = srv.URL
	if err := e.poller.poll(context.Background()); err == nil {
		t.Fatal("a failed state report is not an error")
	}
	if v, ok, _ := e.meta.Meta(context.Background(), MetaCursor); ok && v != "0" {
		t.Fatalf("cursor stored as %q after a failed report", v)
	}
	e.hub.refuse = peer.RefusedNotParked
	if err := e.poller.poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if e.hub.appliedCount() != 1 {
		t.Fatalf("applied %d times", e.hub.appliedCount())
	}
	if got := e.hemma.stateCalls(); len(got) != 1 || got[0].state != hemma.StateApplied {
		t.Fatalf("states = %+v", got)
	}
}

// failingState answers 503 to the first failures state reports.
type failingState struct {
	*hemmaHub
	mu       sync.Mutex
	failures int
}

func (f *failingState) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	fail := strings.HasSuffix(r.URL.Path, "/state") && f.failures > 0
	if fail {
		f.failures--
	}
	f.mu.Unlock()
	if fail {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	f.serve(w, r)
}

func TestCursorSurvivesRestart(t *testing.T) {
	t.Parallel()
	e := newPollerEnv(t)
	e.hemma.decisions = []hemma.Decision{e.phone.decide(t, 41, "req_1", 2, fp, hemma.DecisionApprove, future)}
	if err := e.poller.poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.meta.Close()
	st := openStore(t, e.dbPath)
	t.Cleanup(func() { st.Close() })
	p := &Poller{Client: e.poller.Client, Hub: e.hub, Meta: st, Log: e.poller.Log}
	if err := p.poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.hemma.mu.Lock()
	afters := append([]string(nil), e.hemma.afters...)
	e.hemma.mu.Unlock()
	if len(afters) != 2 || afters[0] != "0" || afters[1] != "41" {
		t.Fatalf("afters = %v, want [0 41]", afters)
	}
	if e.hub.appliedCount() != 1 {
		t.Fatalf("applied %d times", e.hub.appliedCount())
	}
}

func TestStoreFailureKeepsCursor(t *testing.T) {
	t.Parallel()
	e := newPollerEnv(t)
	e.hemma.decisions = []hemma.Decision{e.phone.decide(t, 5, "req_1", 2, fp, hemma.DecisionApprove, future)}
	e.hub.refuse = errors.New("database is locked")
	if err := e.poller.poll(context.Background()); err == nil {
		t.Fatal("no error")
	}
	if _, ok, _ := e.meta.Meta(context.Background(), MetaCursor); ok {
		t.Fatal("cursor stored after a failed apply")
	}
	if len(e.hemma.stateCalls()) != 0 {
		t.Fatal("state reported for a decision that was not processed")
	}
}

func TestRunStopsWithContext(t *testing.T) {
	t.Parallel()
	e := newPollerEnv(t)
	e.hemma.status = http.StatusServiceUnavailable
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.poller.Run(ctx); close(done) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
}

func TestBackoffIsCapped(t *testing.T) {
	t.Parallel()
	var d time.Duration
	for i := 0; i < 20; i++ {
		d = nextBackoff(d)
	}
	if d != maxBackoff {
		t.Fatalf("backoff = %v, want %v", d, maxBackoff)
	}
	if nextBackoff(0) != minBackoff {
		t.Fatalf("first backoff = %v", nextBackoff(0))
	}
}
