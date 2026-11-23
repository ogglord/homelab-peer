package peerclient_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ogglord/homelab-peer/internal/peer"
	"github.com/ogglord/homelab-peer/internal/peerclient"
	"github.com/ogglord/homelab-peer/internal/peerclient/hubtest"
)

// syncBuffer is a log the listener writes while the test reads it.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// runListener is homeassistant's listener with runs on the fake claude,
// against a real hub.
type runListener struct {
	hub    *hubtest.Hub
	ha     *hubtest.Server
	h      *harness
	outbox string
	logs   *syncBuffer
	l      *peerclient.Listener
	done   chan error // Run's return, put back by exited
}

// startRunListener starts it running steps, with a runs directory; set,
// when given, adjusts the run configuration first.
func startRunListener(t *testing.T, set func(*peerclient.Runs), steps ...string) *runListener {
	t.Helper()
	r := newRunListener(t, set, steps...)
	r.start(t)
	return r
}

// newRunListener is startRunListener's listener, not started yet.
func newRunListener(t *testing.T, set func(*peerclient.Runs), steps ...string) *runListener {
	t.Helper()
	r := &runListener{hub: hubtest.New(t), outbox: t.TempDir(), logs: &syncBuffer{}, done: make(chan error, 1)}
	r.ha = r.hub.Serve(haCaller)
	h := newHarness(t, steps...)
	r.h = h
	h.l.Log = nil // the listener's log
	h.l.Env = append(h.l.Env, "FAKE_CLAUDE_CANARY_STEPS=["+strings.Join(canaryPass, ",")+"]")
	ob, err := peerclient.OpenOutbox(r.outbox)
	if err != nil {
		t.Fatal(err)
	}
	runs := &peerclient.Runs{Launcher: *h.l, Outbox: ob, RunsDir: filepath.Join(t.TempDir(), peerclient.RunsDirName)}
	if set != nil {
		set(runs)
	}
	r.l = &peerclient.Listener{
		Client: client(t, r.ha), Instance: peerclient.NewInstance(), StartedAt: time.Now(),
		Deliver: func(peerclient.Message) error { return nil }, Runs: runs,
		Log:        slog.New(slog.NewTextHandler(r.logs, nil)),
		MinBackoff: 10 * time.Millisecond, MaxBackoff: 50 * time.Millisecond,
	}
	return r
}

func (r *runListener) start(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	go func() { r.done <- r.l.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-r.done })
}

// exited reports Run's return if it returns within d, leaving it for the
// cleanup.
func (r *runListener) exited(d time.Duration) (bool, error) {
	select {
	case err := <-r.done:
		r.done <- err
		return true, err
	case <-time.After(d):
		return false, nil
	}
}

func (r *runListener) eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s\nlistener log:\n%s", what, r.logs.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (r *runListener) stored() bool {
	names, _ := filepath.Glob(filepath.Join(r.outbox, "*.json"))
	return len(names) > 0
}

// outage runs request id until it reports while the hub is down, then ages
// its claim past the lease grace and brings the hub back.
func (r *runListener) outage(t *testing.T, id string) {
	t.Helper()
	r.hub.Request(homelabCaller, id, "homeassistant", "list your add-ons")
	r.eventually(t, "the request to run", func() bool { return r.hub.Get(id).State == peer.ReqRunning })
	r.ha.Down()
	r.eventually(t, "the report in the outbox", r.stored)
	r.hub.AgeClaim(id, time.Minute) // well past peer.LeaseGrace
	r.ha.Up()
	r.eventually(t, "the request to move on", func() bool { return r.hub.Get(id).State != peer.ReqRunning })
}

// Covers AE7: a run that ends while the hub is unreachable keeps its
// result in the outbox and is reported as held in hello; on reconnect the
// hub records the result, not listener_lost.
func TestRunResultSurvivesHubOutage(t *testing.T) {
	t.Parallel()
	r := startRunListener(t, nil, `{"sleep":"1s"}`, done)
	r.outage(t, "req-out")
	if got := r.hub.Get("req-out"); got.State != peer.ReqDone || got.Summary != "listed 3 add-ons" {
		t.Fatalf("request %s %s %q", got.State, got.Reason, got.Summary)
	}
	if r.stored() {
		t.Error("the result is still in the outbox")
	}
}

// A run that parks while the hub is unreachable keeps the park in the
// outbox (the hook could not report it either); on reconnect the hub records
// the park, not listener_lost.
func TestRunParkSurvivesHubOutage(t *testing.T) {
	t.Parallel()
	r := startRunListener(t, nil, `{"sleep":"1s"}`, blocked("rm -rf /config/old-backups", "deletes backups"), done)
	r.outage(t, "req-opark")
	got := r.hub.Get("req-opark")
	if got.State != peer.ReqParked || got.Step != `Bash {"command":"rm -rf /config/old-backups"}` || got.ParkReason != "deletes backups" {
		t.Fatalf("request %s %s on %q", got.State, got.Reason, got.Step)
	}
	if r.stored() {
		t.Error("the park is still in the outbox")
	}
}

// An inconclusive canary (here claude's first start
// exits without output) is retried; once it passes, requests run without a
// listener restart, and the hello no longer reports the gate unverified.
func TestRunCanaryRetried(t *testing.T) {
	t.Parallel()
	td, err := filepath.Abs("testdata")
	if err != nil {
		t.Fatal(err)
	}
	flaky := filepath.Join(t.TempDir(), "flaky-claude")
	script := "#!/bin/sh\nif [ ! -e \"$0.failed\" ]; then : > \"$0.failed\"; exit 1; fi\nexec " + filepath.Join(td, "fake-claude") + " \"$@\"\n"
	if err := os.WriteFile(flaky, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	r := startRunListener(t, func(runs *peerclient.Runs) {
		runs.Launcher.Claude = flaky
		runs.CanaryRetry = 20 * time.Millisecond
	}, done)
	r.eventually(t, "the gate to be verified", func() bool { return strings.Contains(r.logs.String(), "gate verified") })
	if !strings.Contains(r.logs.String(), "canary was inconclusive") {
		t.Fatalf("no inconclusive canary logged:\n%s", r.logs.String())
	}
	r.eventually(t, "a hello without gate_unverified", func() bool {
		return !strings.Contains(string(r.ha.LastHello()), "gate_unverified")
	})
	r.hub.Request(homelabCaller, "req-retry", "homeassistant", "list your add-ons")
	r.eventually(t, "the request to finish", func() bool { return r.hub.Get("req-retry").State.Terminal() })
	if got := r.hub.Get("req-retry"); got.State != peer.ReqDone {
		t.Fatalf("request %s %s", got.State, got.Reason)
	}
}

// While the canary cannot prove the gate, hello says so and nothing is
// claimed.
func TestRunHelloReportsGateUnverified(t *testing.T) {
	t.Parallel()
	r := startRunListener(t, func(runs *peerclient.Runs) {
		runs.Launcher.Env = append(runs.Launcher.Env, "FAKE_CLAUDE_NOHOOKS=1")
		runs.CanaryRetry = 20 * time.Millisecond
	}, done)
	r.eventually(t, "a hello with gate_unverified", func() bool {
		return strings.Contains(string(r.ha.LastHello()), `"gate_unverified":true`)
	})
	if n := r.ha.Calls("POST /api/peer/claim"); n != 0 {
		t.Fatalf("%d claims with the gate unverified", n)
	}
}

// failingHub refuses every report with err.
type failingHub struct {
	err error
}

func (h *failingHub) Park(context.Context, peerclient.ParkRequest) error         { return h.err }
func (h *failingHub) PostResult(context.Context, peerclient.ResultRequest) error { return h.err }

// The outbox keeps a report the hub could not take and names its request
// (dashes and all), drops one the hub refused for good, and drops on demand.
func TestOutboxPendingAndDrop(t *testing.T) {
	t.Parallel()
	ob, err := peerclient.OpenOutbox(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	down := &failingHub{err: &peerclient.UnreachableError{Hub: "x", Err: errors.New("connection refused")}}
	gone := &failingHub{err: &peerclient.Problem{Status: 409, Code: peerclient.CodeNotRunning}}

	ref := func(id string) peerclient.RunRef {
		return peerclient.RunRef{RequestID: id, Attempt: 1, Instance: "i", Token: "t"}
	}
	if err := ob.Post(ctx, down, peerclient.ResultRequest{RunRef: ref("req-a-1"), Outcome: peerclient.RunDone}); err == nil {
		t.Fatal("post to an unreachable hub succeeded")
	}
	if err := ob.PostPark(ctx, down, peerclient.ParkRequest{RunRef: ref("req-b"), Tool: "Bash"}); err == nil {
		t.Fatal("park to an unreachable hub succeeded")
	}
	if err := ob.PostPark(ctx, gone, peerclient.ParkRequest{RunRef: ref("req-c"), Tool: "Bash"}); err == nil {
		t.Fatal("refused park succeeded")
	}
	if got := ob.Pending(); !slices.Equal(got, []string{"req-a-1", "req-b"}) {
		t.Fatalf("pending %q", got)
	}
	if left, _ := ob.Flush(ctx, down); left != 2 {
		t.Fatalf("%d left after a failed flush", left)
	}
	ob.Drop([]string{"req-a-1"})
	if got := ob.Pending(); !slices.Equal(got, []string{"req-b"}) {
		t.Fatalf("pending after drop %q", got)
	}
	if left, err := ob.Flush(ctx, &failingHub{}); left != 0 || err != nil || len(ob.Pending()) != 0 {
		t.Fatalf("flush: %d left, %v", left, err)
	}
}

// decide is the operator's verified decision on parked request id's current
// round.
func (r *runListener) decide(t *testing.T, id string, approve bool) {
	t.Helper()
	p := r.hub.Get(id)
	if _, err := r.hub.Service().ApplyDecision(context.Background(), peer.Decision{
		RequestID: id, Round: p.ApprovalCycles, Fingerprint: p.Fingerprint, Approve: approve, ExpiresAt: time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
}

// R9/R10: each request runs in its own worktree of the checkout, kept with
// its changes and its session while it is parked; the approved run resumes
// both, and once the request is done the listener removes the worktree and
// the transcript. Spent and used reach the hub.
func TestRunWorktreeAndSessionLiveUntilTheEnd(t *testing.T) {
	t.Parallel()
	checkout := newCheckout(t)
	var runsDir string
	r := startRunListener(t, func(runs *peerclient.Runs) {
		runs.Checkout, runsDir = checkout, runs.RunsDir
	}, costing(bash("touch made-by-the-first-run"), 0.5), blocked("echo deploy", "deploys"), bash("ls made-by-the-first-run"), done)
	r.hub.Request(homelabCaller, "req-wt", "homeassistant", "deploy")
	r.eventually(t, "the request to park", func() bool { return r.hub.Get("req-wt").State == peer.ReqParked })
	wt := filepath.Join(runsDir, "req-wt")
	transcript := peerclient.TranscriptPath(r.h.config, wt, peerclient.SessionUUID("req-wt"))
	r.eventually(t, "the run to be reported parked", func() bool { return strings.Contains(r.logs.String(), `msg="run parked"`) })
	if _, err := os.Stat(filepath.Join(wt, "made-by-the-first-run")); err != nil {
		t.Fatalf("the worktree did not keep the run's change: %v", err)
	}
	if _, err := os.Stat(transcript); err != nil {
		t.Fatalf("no transcript while parked: %v", err)
	}
	if got := r.hub.Get("req-wt"); got.ParkReason != "deploys" || got.UsedSeconds < 1 {
		t.Fatalf("park reason %q used %d", got.ParkReason, got.UsedSeconds)
	}

	r.decide(t, "req-wt", true)
	r.eventually(t, "the resumed run to finish", func() bool { return r.hub.Get("req-wt").State.Terminal() })
	got := r.hub.Get("req-wt")
	if rec := r.h.seen(t); got.State != peer.ReqDone || !rec.Resume || len(rec.Outputs) != 2 || rec.Outputs[1] != "made-by-the-first-run\n" {
		t.Fatalf("request %s %q, resume outputs %q", got.State, got.Summary, rec.Outputs)
	}
	if got.SpentUSD != 0.5 || got.UsedSeconds < 2 {
		t.Errorf("spent %v used %d", got.SpentUSD, got.UsedSeconds)
	}
	r.eventually(t, "the worktree and transcript to go", func() bool {
		_, werr := os.Stat(wt)
		_, terr := os.Stat(transcript)
		return errors.Is(werr, os.ErrNotExist) && errors.Is(terr, os.ErrNotExist)
	})
	if n := strings.Count(gitT(t, checkout, "worktree", "list", "--porcelain"), "worktree "); n != 1 {
		t.Fatalf("%d worktrees registered after the end", n)
	}
}

// R11/R12: a run's budget is the request's remaining allowance; reaching it
// parks the request with kind limit and no call, the cost reported; the
// approval extends it and the run resumes with the budget prompt.
func TestRunLimitParkAndExtension(t *testing.T) {
	t.Parallel()
	r := startRunListener(t, nil, costing(bash("echo a"), 6), costing(bash("echo b"), 6), done)
	r.hub.Request(homelabCaller, "req-lim", "homeassistant", "big job")
	r.eventually(t, "the request to park", func() bool { return r.hub.Get("req-lim").State == peer.ReqParked })
	got := r.hub.Get("req-lim")
	if got.ParkKind != peer.ParkLimit || got.Tool != "" || got.StepHash != "" || got.SpentUSD != 12 || got.UsedSeconds < 1 {
		t.Fatalf("park %s tool %q spent %v used %d", got.ParkKind, got.Tool, got.SpentUSD, got.UsedSeconds)
	}
	if rec := r.h.seen(t); argAfter(rec.Argv, "--max-budget-usd") != "10" {
		t.Fatalf("--max-budget-usd %q, want the allowance 10", argAfter(rec.Argv, "--max-budget-usd"))
	}
	r.decide(t, "req-lim", true)
	r.eventually(t, "the resumed run to finish", func() bool { return r.hub.Get("req-lim").State.Terminal() })
	rec := r.h.seen(t)
	if got := r.hub.Get("req-lim"); got.State != peer.ReqDone || rec.Prompt != "The operator extended your budget; continue the task." {
		t.Fatalf("request %s, resume prompt %q", got.State, rec.Prompt)
	}
	if argAfter(rec.Argv, "--max-budget-usd") != "8" {
		t.Fatalf("resumed --max-budget-usd %q, want 20 - 12", argAfter(rec.Argv, "--max-budget-usd"))
	}
}

// A request that ended while the listener could not see it (gone from the
// hub, or denied while parked) loses its runs entry and session at the next
// sweep, which runs once the gate is verified; a parked request keeps its.
func TestRunSweepRemovesEndedRequests(t *testing.T) {
	t.Parallel()
	var runsDir, transcript string
	r := startRunListener(t, func(runs *peerclient.Runs) {
		runsDir = runs.RunsDir
		for _, kv := range runs.Launcher.Env {
			if config, ok := strings.CutPrefix(kv, "CLAUDE_CONFIG_DIR="); ok {
				transcript = peerclient.TranscriptPath(config, runs.Launcher.Dir, peerclient.SessionUUID("req-gone"))
			}
		}
		for _, err := range []error{
			os.MkdirAll(filepath.Join(runs.RunsDir, "req-gone"), 0o700),
			os.MkdirAll(filepath.Dir(transcript), 0o700),
			os.WriteFile(transcript, []byte("{}"), 0o600),
		} {
			if err != nil {
				t.Fatal(err)
			}
		}
	}, blocked("echo x", "needs approval"), done)
	r.eventually(t, "the unknown request's entry to go", func() bool {
		_, err := os.Stat(filepath.Join(runsDir, "req-gone"))
		_, terr := os.Stat(transcript)
		return errors.Is(err, os.ErrNotExist) && errors.Is(terr, os.ErrNotExist)
	})
	r.hub.Request(homelabCaller, "req-parked", "homeassistant", "x")
	r.eventually(t, "the run to be reported parked", func() bool { return strings.Contains(r.logs.String(), `msg="run parked"`) })
	if _, err := os.Stat(filepath.Join(runsDir, "req-parked")); err != nil {
		t.Fatalf("a parked request lost its entry: %v", err)
	}
}
