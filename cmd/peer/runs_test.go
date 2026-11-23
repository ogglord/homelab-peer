package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ogglord/homelab-peer/internal/peer"
	"github.com/ogglord/homelab-peer/internal/peerclient/fakeclaude"
	"github.com/ogglord/homelab-peer/internal/peerclient/hubtest"
)

// The run tests drive `peer listen --claude` (this test binary running the
// real CLI, in its own process) against a real in-process hub, with the fake
// claude (internal/peerclient/fakeclaude) as the run. The fake's hook command
// and the `peer` on the run's PATH are the real CLI too, so `peer park`,
// `peer send status` and `peer secret receive` run as a run calls them.
func TestMain(m *testing.M) {
	switch os.Getenv("PEERCLIENT_HELPER") {
	case "fake-claude":
		os.Exit(fakeclaude.Main(os.Args[1:]))
	case "peer":
		os.Exit(run(os.Args, os.Stdin, os.Stdout, os.Stderr))
	}
	// Run inside a real peer run, the test process inherits that run's PEER_*
	// (token, hub, sockets); the CLI under test would send them to the fake
	// hubs. Tests that want them set their own.
	for _, kv := range os.Environ() {
		if k, _, _ := strings.Cut(kv, "="); strings.HasPrefix(k, "PEER_") {
			os.Unsetenv(k)
		}
	}
	os.Exit(m.Run())
}

// syncBuffer is a buffer the listener writes to while the test reads it.
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

func bash(cmd string) string {
	in, _ := json.Marshal(map[string]any{"tool": "Bash", "input": map[string]string{"command": cmd}})
	return string(in)
}

func steps(s ...string) string { return "[" + strings.Join(s, ",") + "]" }

const doneStep = `{"result":{"outcome":"done","summary":"listed 3 add-ons"}}`

// canarySteps passes the canary: the hook denies the touch, the classifier
// blocks the rm.
var canarySteps = steps(bash("{{canary-touch}}"), blocked("{{canary-rm}}", "hard_deny"), `{"result":{"outcome":"done","summary":"denied"}}`)

// blocked is a Bash step auto mode's classifier blocks with reason.
func blocked(cmd, reason string) string {
	in, _ := json.Marshal(map[string]any{"tool": "Bash", "input": map[string]string{"command": cmd}, "classifier": "block", "reason": reason})
	return string(in)
}

// runHost is homeassistant's listener with runs enabled, and homelab, the
// requester, on the same hub.
type runHost struct {
	hub     *hubtest.Hub
	lab, ha *hubtest.Server
	out     *syncBuffer // listener stdout
	logs    *syncBuffer // listener stderr
	record  string      // the fake's record of the last run
}

// startRuns starts the listener with the fake claude running runSteps.
// env adds to (or, with a value, overrides) the fake's environment.
func startRuns(t *testing.T, runSteps string, env ...string) *runHost {
	t.Helper()
	return startRunsWith(t, runSteps, nil, env...)
}

// startRunsWith is startRuns with extra `peer listen` flags.
func startRunsWith(t *testing.T, runSteps string, listenArgs []string, env ...string) *runHost {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	td, err := filepath.Abs("../../internal/peerclient/testdata")
	if err != nil {
		t.Fatal(err)
	}
	h := &runHost{hub: hubtest.New(t), out: &syncBuffer{}, logs: &syncBuffer{}, record: filepath.Join(t.TempDir(), "record.json")}
	h.lab, h.ha = h.hub.Serve(homelabCaller), h.hub.Serve(haCaller)

	// The listener's environment, passed on to its runs; env comes last and
	// wins (exec keeps the last value of a key). Not t.Setenv: the tests run
	// in parallel.
	environ := append(os.Environ(),
		"PEERCLIENT_TEST_BIN="+exe,
		"PATH="+filepath.Join(td, "bin")+":"+os.Getenv("PATH"),
		"PEER_HUB_URL="+h.ha.URL(),
		"FAKE_CLAUDE_RECORD="+h.record,
		"CLAUDE_CONFIG_DIR="+t.TempDir(),
		"FAKE_CLAUDE_STEPS="+runSteps,
		"FAKE_CLAUDE_CANARY_STEPS="+canarySteps,
		"FAKE_CLAUDE_SIGINT_EXITS=1",
		"GORACE=atexit_sleep_ms=0",
	)
	environ = append(environ, env...)

	cmd := exec.Command(exe, "--hub", h.ha.URL(), "listen",
		"--claude", filepath.Join(td, "fake-claude"), "--peer", filepath.Join(td, "bin", "peer"),
		"--run-dir", t.TempDir(), "--state-dir", t.TempDir())
	cmd.Args = append(cmd.Args, listenArgs...)
	cmd.Env = append(environ, "PEERCLIENT_HELPER=peer")
	cmd.Stdout, cmd.Stderr = h.out, h.logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			_ = cmd.Process.Kill()
			t.Error("listener did not stop on SIGTERM")
		}
	})
	return h
}

// eventually polls cond for up to 20 s.
func (h *runHost) eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s\nlistener log:\n%s", what, h.logs.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (h *runHost) state(id string) peer.RequestState { return h.hub.Get(id).State }

func (h *runHost) seen(t *testing.T) fakeclaude.Record {
	t.Helper()
	data, err := os.ReadFile(h.record)
	if err != nil {
		t.Fatal(err)
	}
	var r fakeclaude.Record
	if err := json.Unmarshal(data, &r); err != nil {
		t.Fatal(err)
	}
	return r
}

// sendSecretWhenRunning sends value for request id from homelab once the
// request runs, as `peer send secret` does, and returns its result.
func (h *runHost) sendSecretWhenRunning(t *testing.T, id, value string) <-chan result {
	t.Helper()
	h.eventually(t, "the request to run", func() bool { return h.state(id) == peer.ReqRunning })
	ch := make(chan result, 1)
	go func() {
		ch <- peerCmd(value+"\n", "--json", "--hub", h.lab.URL(), "send", "secret",
			"--target", "homeassistant", "--name", "mqtt/PASSWORD", "--request", id, "--value-stdin")
	}()
	return ch
}

// Covers F1: a request to the listener's host is claimed and run; the run's
// status carries its token and lands bound to the request; the run's done
// is the outcome `send request --wait` and `wait` return.
func TestRunRequestEndsDone(t *testing.T) {
	t.Parallel()
	h := startRuns(t, steps(bash("peer send status --target homelab --phase progress 'half way'"), doneStep))

	r := peerCmd("", "--json", "--hub", h.lab.URL(), "send", "request", "--target", "homeassistant",
		"--id", "req-f1", "--wait", "--timeout", "30s", "list", "your", "add-ons")
	if r.code != 0 {
		t.Fatalf("send request --wait: %+v\nlistener log:\n%s", r, h.logs.String())
	}
	got := r.json(t, r.out)
	req := got["request"].(map[string]any)
	if got["success"] != true || req["state"] != "done" || req["summary"] != "listed 3 add-ons" || req["text"] != "list your add-ons" {
		t.Fatalf("outcome %v", got)
	}

	if w := peerCmd("", "--json", "--hub", h.lab.URL(), "wait", "--timeout", "1s", "req-f1"); w.code != 0 || w.json(t, w.out)["request"].(map[string]any)["state"] != "done" {
		t.Fatalf("wait: %+v", w)
	}

	in := peerCmd("", "--json", "--hub", h.lab.URL(), "inbox")
	var progress map[string]any
	for _, m := range in.json(t, in.out)["messages"].([]any) {
		if m := m.(map[string]any); m["kind"] == "status" {
			progress = m
		}
	}
	if progress == nil || progress["request_id"] != "req-f1" || progress["body"] != "half way" || progress["sender"] != "homeassistant" {
		t.Fatalf("run's status not bound to the request: %v", in.out)
	}
	if rec := h.seen(t); rec.Stdin != "list your add-ons" {
		t.Errorf("prompt %q", rec.Stdin)
	}
}

// Covers AE10 and R8 at integration level: the step auto mode's classifier
// blocks parks the request on the hub through `peer park --denied`, with the
// classifier's reason on one line, although the run then printed done.
func TestRunParksOnTheHub(t *testing.T) {
	t.Parallel()
	h := startRuns(t, steps(
		blocked("echo v > /config/secrets.yaml", "writes the config:\n v into secrets.yaml"),
		doneStep))
	h.hub.Request(homelabCaller, "req-park", "homeassistant", "set the mqtt password")
	h.eventually(t, "the request to park", func() bool { return h.state("req-park") == peer.ReqParked })

	got := h.hub.Get("req-park")
	if want := `Bash {"command":"echo v > /config/secrets.yaml"}`; got.Tool != "Bash" || got.Step != want {
		t.Fatalf("parked on %q %q, want Bash %q", got.Tool, got.Step, want)
	}
	if want := "writes the config: v into secrets.yaml"; got.ParkKind != peer.ParkStep || got.ParkReason != want {
		t.Fatalf("park %s reason %q, want %q", got.ParkKind, got.ParkReason, want)
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(got.StepHash) || got.ApprovalCycles != 1 {
		t.Fatalf("step hash %q, cycles %d", got.StepHash, got.ApprovalCycles)
	}
	if w := peerCmd("", "--hub", h.lab.URL(), "wait", "--timeout", "1s", "req-park"); w.code == 0 || !strings.Contains(w.out, "parked") || !strings.Contains(w.out, "blocked on: Bash") {
		t.Fatalf("wait on a parked request: %+v", w)
	}
	// Parked stays parked: the listener posted no result over it.
	time.Sleep(300 * time.Millisecond)
	if s := h.state("req-park"); s != peer.ReqParked {
		t.Fatalf("state %s after the run ended", s)
	}
}

// R29: two requests for the host run one after the other, in arrival order;
// the listener claims the second only after the first finished, so the hub
// never answers busy.
func TestRunOneAtATime(t *testing.T) {
	t.Parallel()
	h := startRuns(t, steps(`{"sleep":"700ms"}`, doneStep))
	h.hub.Request(homelabCaller, "req-a", "homeassistant", "first")
	h.hub.Request(homelabCaller, "req-b", "homeassistant", "second")
	h.eventually(t, "both requests to finish", func() bool {
		a, b := h.state("req-a"), h.state("req-b")
		if a == peer.ReqRunning && b == peer.ReqRunning {
			t.Fatal("both requests running at once")
		}
		return a.Terminal() && b.Terminal()
	})
	a, b := h.hub.Get("req-a"), h.hub.Get("req-b")
	if a.State != peer.ReqDone || b.State != peer.ReqDone {
		t.Fatalf("states %s %s", a.State, b.State)
	}
	if b.ClaimedAt.Before(a.UpdatedAt) {
		t.Fatalf("second claimed at %s, before the first finished at %s", b.ClaimedAt, a.UpdatedAt)
	}
	if n := h.ha.Calls("POST /api/peer/claim"); n != 2 {
		t.Fatalf("%d claims, want 2 (no busy retries)", n)
	}
}

// KTD11: a run the hub no longer holds (here failed by the timeout sweep)
// is reported on the next hello, comes back in the cancel list and is
// stopped; its late outcome is not posted over the hub's.
func TestRunCancelledByHello(t *testing.T) {
	t.Parallel()
	h := startRuns(t, steps(`{"sleep":"30s"}`, doneStep))
	h.hub.Request(homelabCaller, "req-c", "homeassistant", "take your time")
	h.eventually(t, "the request to run", func() bool { return h.state("req-c") == peer.ReqRunning })
	// The canary wrote the record first; wait for the run's own.
	h.eventually(t, "the run to start", func() bool {
		data, _ := os.ReadFile(h.record)
		return strings.Contains(string(data), `"stdin":"take your time"`)
	})

	if n, err := h.hub.Service().Sweep(context.Background(), time.Now().Add(peer.AllowanceSeconds*time.Second+peer.RunGrace+time.Minute)); err != nil || n != 1 {
		t.Fatalf("sweep: %d %v", n, err)
	}
	h.ha.Down()
	h.ha.Up()
	start := time.Now()
	h.eventually(t, "the run to be cancelled", func() bool { return strings.Contains(h.logs.String(), "run cancelled by the hub") })
	if took := time.Since(start); took > 15*time.Second {
		t.Fatalf("cancel took %s", took)
	}
	if rec := h.seen(t); !slices.Contains(rec.Signals, "interrupt") {
		t.Errorf("the run got no SIGINT: %+v", rec.Signals)
	}
	if got := h.hub.Get("req-c"); got.State != peer.ReqFailed || got.Reason != peer.FailTimeout {
		t.Fatalf("request %s %s", got.State, got.Reason)
	}
}

// A request sent from inside a run carries the run's token from the
// environment; the hub refuses a token that names no run, and the command
// fails. (A valid run may send requests to another host: R13.)
func TestSendRequestFromRunRefused(t *testing.T) {
	lab := hubtest.New(t).Serve(homelabCaller)
	t.Setenv("PEER_RUN_TOKEN", "a-run-token")
	r := peerCmd("", "--json", "--hub", lab.URL(), "send", "request", "--target", "homeassistant", "restart", "everything")
	if r.code == 0 {
		t.Fatalf("exit 0: %+v", r)
	}
	if got := r.json(t, r.stderr); got["status"] != float64(403) || got["code"] != "invalid_run_token" {
		t.Fatalf("problem %v", got)
	}
}

// R26: a canary that cannot prove the gate (a build whose hooks never fire)
// leaves the listener connected but claiming nothing; its hello says the
// gate is unverified, so the hub fails the host's requests with
// gate_unverified instead of leaving them waiting.
func TestRunGateUnverifiedNeverClaims(t *testing.T) {
	t.Parallel()
	h := startRuns(t, steps(doneStep), "FAKE_CLAUDE_NOHOOKS=1")
	h.eventually(t, "the canary verdict", func() bool { return strings.Contains(h.logs.String(), "gate unverified") })
	h.eventually(t, "a hello reporting it", func() bool { return strings.Contains(string(h.ha.LastHello()), `"gate_unverified":true`) })
	h.hub.Request(homelabCaller, "req-g", "homeassistant", "list your add-ons")
	h.eventually(t, "the request to fail", func() bool { return h.state("req-g").Terminal() })
	if got := h.hub.Get("req-g"); got.State != peer.ReqFailed || got.Reason != peer.FailGateUnverified {
		t.Fatalf("request %s %s", got.State, got.Reason)
	}
	if n := h.ha.Calls("POST /api/peer/claim"); n != 0 {
		t.Fatalf("%d claims with the gate unverified", n)
	}
}

// Covers AE5 and F2 end to end through the real listener: the run parks on
// a step, the operator approves while the listener is offline, the request
// waits approved; when the listener is back the re-run makes exactly the
// approved call and ends done.
func TestRunApprovedReRun(t *testing.T) {
	t.Parallel()
	h := startRuns(t, steps(
		bash("peer send status --target homelab --phase progress 'checked the config'"),
		blocked("echo restart-core", "restarts core"),
		doneStep))
	h.hub.Request(homelabCaller, "req-ok", "homeassistant", "restart core")
	h.eventually(t, "the request to park", func() bool { return h.state("req-ok") == peer.ReqParked })
	parked := h.hub.Get("req-ok")
	if parked.Step != `Bash {"command":"echo restart-core"}` {
		t.Fatalf("parked on %q", parked.Step)
	}

	h.ha.Down()
	r, err := h.hub.Service().ApplyDecision(context.Background(), approve(parked))
	if err != nil || r.State != peer.ReqApproved {
		t.Fatalf("approve: %+v %v", r, err)
	}
	time.Sleep(200 * time.Millisecond)
	if s := h.state("req-ok"); s != peer.ReqApproved {
		t.Fatalf("state %s with the listener offline", s)
	}
	h.ha.Up()
	h.eventually(t, "the re-run to finish", func() bool { return h.state("req-ok").Terminal() })

	got := h.hub.Get("req-ok")
	if got.State != peer.ReqDone || got.Attempt != 2 || got.ApprovalCycles != 1 {
		t.Fatalf("request %s attempt %d cycles %d", got.State, got.Attempt, got.ApprovalCycles)
	}
	// The re-run resumed the session at the parked step.
	rec := h.seen(t)
	if !rec.Resume || len(rec.Outputs) != 1 || rec.Outputs[0] != "restart-core\n" || len(rec.Denied) != 0 {
		t.Fatalf("re-run resume %v outputs %q denied %q", rec.Resume, rec.Outputs, rec.Denied)
	}
	if !strings.Contains(rec.Prompt, "The operator approved this exact call") || !strings.Contains(rec.Prompt, `echo restart-core`) {
		t.Errorf("resume prompt %q lacks the approved step", rec.Prompt)
	}
}

// approve is the decision approving parked's current round.
func approve(parked peer.Request) peer.Decision {
	return peer.Decision{
		RequestID: parked.ID, Round: parked.ApprovalCycles, Fingerprint: parked.Fingerprint, Approve: true,
		ExpiresAt: time.Now().Add(time.Minute),
	}
}

// haAllow is the live homeassistant listener's allow list.
var haAllow = []string{"--allow", "Bash(ha addons list:*)", "--allow", "Bash(ha core info:*)"}

// An allowed command whose stderr is merged into a pipe through a read-only
// filter runs without parking: the redirection is harmless and the filter is
// always allowed, even under a host's own allow list.
func TestRunAllowedPipelineEndsDone(t *testing.T) {
	t.Parallel()
	h := startRunsWith(t, steps(bash("ha addons list 2>&1 | head -5"), doneStep), haAllow)
	h.hub.Request(homelabCaller, "req-pipe", "homeassistant", "list your add-ons")
	h.eventually(t, "the request to end or park", func() bool {
		s := h.state("req-pipe")
		return s.Terminal() || s == peer.ReqParked
	})
	got := h.hub.Get("req-pipe")
	if rec := h.seen(t); got.State != peer.ReqDone || got.ApprovalCycles != 0 || len(rec.Denied) != 0 || len(rec.Outputs) != 1 {
		t.Fatalf("request %s cycles %d step %q, denied %q", got.State, got.ApprovalCycles, got.Step, rec.Denied)
	}
}

// The live cycle_cap bug: a compound step with a part outside the allow list
// parks; once approved, the re-run makes that exact call and ends done on
// attempt 2 instead of parking again every cycle.
func TestRunApprovedCompoundStepEndsDone(t *testing.T) {
	t.Parallel()
	const compound = `ha addons list --raw-json 2>/dev/null | head -c 20000 || ha apps list 2>&1 | head -100`
	h := startRunsWith(t, steps(blocked(compound, "lists add-ons"), doneStep), haAllow)
	h.hub.Request(homelabCaller, "req-compound", "homeassistant", "list your add-ons")
	h.eventually(t, "the request to park", func() bool { return h.state("req-compound") == peer.ReqParked })
	parked := h.hub.Get("req-compound")
	if want := "Bash " + string(mustJSON(map[string]string{"command": compound})); parked.Step != want {
		t.Fatalf("parked on %q, want %q", parked.Step, want)
	}
	if r, err := h.hub.Service().ApplyDecision(context.Background(), approve(parked)); err != nil || r.State != peer.ReqApproved {
		t.Fatalf("approve: %+v %v", r, err)
	}
	h.eventually(t, "the re-run to end or park", func() bool {
		s := h.state("req-compound")
		return s.Terminal() || (s == peer.ReqParked && h.hub.Get("req-compound").ApprovalCycles > 1)
	})
	got := h.hub.Get("req-compound")
	if rec := h.seen(t); got.State != peer.ReqDone || got.Attempt != 2 || got.ApprovalCycles != 1 || len(rec.Denied) != 0 || len(rec.Outputs) != 1 {
		t.Fatalf("request %s attempt %d cycles %d, re-run denied %q", got.State, got.Attempt, got.ApprovalCycles, rec.Denied)
	}
}

// The hook reports a park before the run has wound down; an approval in
// that window pushes the request while the listener still handles attempt
// 1. That frame is newer than the run's, so it runs once attempt 1 ends,
// without waiting for a reconnect.
func TestRunApprovedInParkWindow(t *testing.T) {
	t.Parallel()
	// The sleep after the parked step holds attempt 1 open (the fake ignores
	// SIGINT), so the approval lands before the listener is done with it.
	h := startRuns(t, steps(blocked("echo restart-core", "restarts core"), `{"sleep":"2s"}`, doneStep), "FAKE_CLAUDE_SIGINT_EXITS=0")
	h.hub.Request(homelabCaller, "req-win", "homeassistant", "restart core")
	h.eventually(t, "the request to park", func() bool { return h.state("req-win") == peer.ReqParked })
	hellos := h.ha.Hellos()
	parked := h.hub.Get("req-win")
	if _, err := h.hub.Service().ApplyDecision(context.Background(), approve(parked)); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(h.logs.String(), `msg="run parked"`) {
		t.Fatalf("attempt 1 ended before the approval; the window was missed\n%s", h.logs.String())
	}
	h.eventually(t, "the approved re-run to finish", func() bool { return h.state("req-win").Terminal() })
	if got := h.hub.Get("req-win"); got.State != peer.ReqDone || got.Attempt != 2 {
		t.Fatalf("request %s %s attempt %d", got.State, got.Reason, got.Attempt)
	}
	if n := h.ha.Hellos(); n != hellos {
		t.Fatalf("%d hellos during the window, want none (no reconnect)", n-hellos)
	}
}

func mustJSON(v any) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	return bytes.TrimSuffix(b.Bytes(), []byte("\n"))
}
