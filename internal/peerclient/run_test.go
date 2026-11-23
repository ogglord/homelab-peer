package peerclient_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ogglord/homelab-peer/internal/peerclient"
	"github.com/ogglord/homelab-peer/internal/peerclient/fakeclaude"
)

func TestMain(m *testing.M) {
	switch os.Getenv("PEERCLIENT_HELPER") {
	case "fake-claude":
		os.Exit(fakeclaude.Main(os.Args[1:]))
	case "peer":
		os.Exit(fakePeer(os.Args[1:]))
	}
	os.Exit(m.Run())
}

var testRef = peerclient.RunRef{RequestID: "req-1", Attempt: 1, Instance: "listen-x", Token: "tok-secret-run-token"}

type harness struct {
	l      *peerclient.Launcher
	record string
	config string // the runs' Claude config directory
	logs   *bytes.Buffer
}

// newHarness is a launcher on the fake claude running steps.
func newHarness(t *testing.T, steps ...string) *harness {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	td, err := filepath.Abs("testdata")
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{record: filepath.Join(t.TempDir(), "record.json"), config: t.TempDir(), logs: &bytes.Buffer{}}
	h.l = &peerclient.Launcher{
		Claude: filepath.Join(td, "fake-claude"),
		Peer:   filepath.Join(td, "bin", "peer"),
		Dir:    t.TempDir(),
		Rules:  peerclient.DefaultRules(),
		Log:    slog.New(slog.NewTextHandler(h.logs, nil)),
		Env: []string{
			"PEERCLIENT_TEST_BIN=" + exe,
			"PATH=" + filepath.Join(td, "bin") + ":" + os.Getenv("PATH"),
			"CLAUDE_CONFIG_DIR=" + h.config,
			"FAKE_CLAUDE_RECORD=" + h.record,
			"FAKE_CLAUDE_STEPS=[" + strings.Join(steps, ",") + "]",
		},
		Timeout: 20 * time.Second,
	}
	return h
}

// run runs text as a request homelab sent.
func (h *harness) run(t *testing.T, text string) peerclient.Outcome {
	t.Helper()
	return h.runSpec(t, peerclient.RunSpec{Envelope: peerclient.Envelope{Sender: "homelab"}, Text: text})
}

// runSpec runs spec as testRef.
func (h *harness) runSpec(t *testing.T, spec peerclient.RunSpec) peerclient.Outcome {
	t.Helper()
	spec.Ref = testRef
	return h.l.Run(context.Background(), spec)
}

// fromHA runs text as a request Home Assistant sent: every call outside the
// allow list parks.
func (h *harness) fromHA(t *testing.T, text string) peerclient.Outcome {
	t.Helper()
	return h.runSpec(t, peerclient.RunSpec{Envelope: peerclient.Envelope{Sender: peerclient.UntrustedSender}, Text: text})
}

func (h *harness) seen(t *testing.T) fakeRecord {
	t.Helper()
	data, err := os.ReadFile(h.record)
	if err != nil {
		t.Fatal(err)
	}
	var r fakeRecord
	if err := json.Unmarshal(data, &r); err != nil {
		t.Fatal(err)
	}
	return r
}

// transcript is the request's transcript path in the launcher's directory.
func (h *harness) transcript(id string) string {
	return peerclient.TranscriptPath(h.config, h.l.Dir, peerclient.SessionUUID(id))
}

func bash(cmd string) string {
	in, _ := json.Marshal(map[string]any{"tool": "Bash", "input": map[string]string{"command": cmd}})
	return string(in)
}

// blocked is a Bash step auto mode's classifier blocks with reason.
func blocked(cmd, reason string) string {
	in, _ := json.Marshal(map[string]any{"tool": "Bash", "input": map[string]string{"command": cmd}, "classifier": "block", "reason": reason})
	return string(in)
}

// costing is step with a cost.
func costing(step string, usd float64) string {
	var m map[string]any
	_ = json.Unmarshal([]byte(step), &m)
	m["cost"] = usd
	out, _ := json.Marshal(m)
	return string(out)
}

const done = `{"result":{"outcome":"done","summary":"listed 3 add-ons","actions":["read the add-on list"]}}`

// argAfter is the argument after flag in argv.
func argAfter(argv []string, flag string) string {
	if i := slices.Index(argv, flag); i >= 0 && i+1 < len(argv) {
		return argv[i+1]
	}
	return ""
}

// Covers F1: a schema-conforming done is the outcome, with the session's
// cost and the run's time; the request text is the prompt, the run is in
// auto mode in the request's session, both hooks are set, and the token
// reaches the run only through its environment.
func TestRunDone(t *testing.T) {
	t.Parallel()
	h := newHarness(t, costing(bash("echo hi"), 0.25), done)
	o := h.run(t, "list your add-ons")
	if o.State != peerclient.RunDone || o.Summary != "listed 3 add-ons" || o.SessionID == "" {
		t.Fatalf("outcome %+v", o)
	}
	if o.SpentUSD != 0.25 || o.UsedSeconds < 1 {
		t.Errorf("spent %v used %d", o.SpentUSD, o.UsedSeconds)
	}
	if res := o.Result(testRef); res.SpentUSD != 0.25 || res.UsedSeconds != o.UsedSeconds {
		t.Errorf("result spent %v used %d", res.SpentUSD, res.UsedSeconds)
	}
	r := h.seen(t)
	if r.Stdin != "list your add-ons" || r.Resume {
		t.Errorf("prompt on stdin = %q, resume %v", r.Stdin, r.Resume)
	}
	if r.Env[peerclient.EnvRunToken] != testRef.Token || r.Env[peerclient.EnvRequestSender] != "homelab" {
		t.Errorf("run env %v", r.Env)
	}
	if strings.Contains(strings.Join(r.Argv, " "), testRef.Token) {
		t.Errorf("run token in claude's arguments")
	}
	for _, flag := range []string{"-p", "--setting-sources", "--strict-mcp-config", "--json-schema", "--max-turns", "--max-budget-usd"} {
		if !slices.Contains(r.Argv, flag) {
			t.Errorf("argv lacks %s", flag)
		}
	}
	if slices.Contains(r.Argv, "--no-session-persistence") || argAfter(r.Argv, "--permission-mode") != "auto" {
		t.Errorf("argv %q: want auto mode with the session kept", r.Argv)
	}
	if got := argAfter(r.Argv, "--session-id"); got != peerclient.SessionUUID(testRef.RequestID) {
		t.Errorf("--session-id %q", got)
	}
	var settings struct {
		Hooks       map[string][]struct{ Hooks []struct{ Command string } } `json:"hooks"`
		Permissions struct{ DefaultMode string }                            `json:"permissions"`
		AutoMode    map[string][]string                                     `json:"autoMode"`
	}
	if err := json.Unmarshal([]byte(argAfter(r.Argv, "--settings")), &settings); err != nil {
		t.Fatal(err)
	}
	if pre, den := settings.Hooks["PreToolUse"], settings.Hooks["PermissionDenied"]; len(pre) != 1 || len(den) != 1 ||
		!strings.HasSuffix(pre[0].Hooks[0].Command, "' park") || !strings.HasSuffix(den[0].Hooks[0].Command, "' park --denied") {
		t.Errorf("hooks %+v", settings.Hooks)
	}
	if settings.Permissions.DefaultMode != "auto" || !slices.Equal(settings.AutoMode["hard_deny"], peerclient.DefaultPolicy().HardDeny) ||
		!slices.Equal(settings.AutoMode["environment"], []string{"$defaults"}) {
		t.Errorf("settings %+v", settings)
	}
}

// KTD7: the --allowedTools/--disallowedTools flags and the hook's lists are
// the same rule list (the hook alone holds the WebFetch glob it alone
// understands).
func TestRulesFlagsAndHookOneSource(t *testing.T) {
	t.Parallel()
	h := newHarness(t, done)
	h.l.Rules.Allow = append(h.l.Rules.Allow, "Bash(ha addons list:*)")
	h.run(t, "x")
	r := h.seen(t)
	var hook peerclient.Rules
	if err := json.Unmarshal([]byte(r.Env[peerclient.EnvRunRules]), &hook); err != nil {
		t.Fatal(err)
	}
	var allow, deny []string
	var list *[]string
	for _, a := range r.Argv {
		switch {
		case a == "--allowedTools":
			list = &allow
		case a == "--disallowedTools":
			list = &deny
		case strings.HasPrefix(a, "--"):
			list = nil
		case list != nil:
			*list = append(*list, a)
		}
	}
	want := append(slices.Clone(h.l.Rules.Allow), peerclient.StructuredOutputTool)
	hookDeny := slices.DeleteFunc(slices.Clone(hook.Deny), func(s string) bool { return s == "WebFetch(*peer/approvers*)" })
	if !slices.Equal(allow, hook.Allow) || !slices.Equal(deny, hookDeny) || !slices.Equal(allow, want) || len(hookDeny) == len(hook.Deny) {
		t.Fatalf("flags allow=%q deny=%q, hook %+v", allow, deny, hook)
	}
}

// A host's own allow list (peer listen --allow) still allows the reply verb
// the envelope tells the run to call, without parking, even for Home
// Assistant.
func TestRunCustomAllowKeepsReplyVerbs(t *testing.T) {
	t.Parallel()
	h := newHarness(t,
		bash("peer send status --target homelab --phase progress 'half way'"),
		done)
	h.l.Rules.Allow = []string{"Read", "Bash(ha addons list:*)"}
	o := h.fromHA(t, "x")
	if r := h.seen(t); o.State != peerclient.RunDone || len(r.Denied) != 0 {
		t.Fatalf("outcome %+v, denied %q", o, r.Denied)
	}
}

// Covers AE10 and R6: in a request Home Assistant sent, the hook parks a
// call outside the allow list, and the park wins over the run's own done.
func TestRunParkWinsOverDone(t *testing.T) {
	t.Parallel()
	h := newHarness(t, bash("rm -rf /config/old-backups"), done)
	o := h.fromHA(t, "tidy up")
	if o.State != peerclient.RunParked || o.Park == nil || o.Park.Tool != "Bash" || !strings.Contains(string(o.Park.Input), "rm -rf /config/old-backups") || !strings.HasPrefix(o.Park.Hash, "sha256:") {
		t.Fatalf("outcome %+v park %+v", o, o.Park)
	}
	if r := h.seen(t); len(r.Denied) != 1 || len(r.Classified) != 0 {
		t.Errorf("hook did not deny the call itself: denied %q classified %q", r.Denied, r.Classified)
	}
}

// R2/R8: in another host's request a call outside the allow list reaches
// auto mode's classifier: one it judges safe runs, one it blocks parks the
// request with the classifier's reason, through the PermissionDenied hook.
func TestRunClassifierDecides(t *testing.T) {
	t.Parallel()
	h := newHarness(t, bash("echo judged-safe"), blocked("ssh root@192.0.2.1 reboot", "reboots\nthe router"), done)
	o := h.run(t, "restart the router")
	r := h.seen(t)
	if len(r.Outputs) != 1 || r.Outputs[0] != "judged-safe\n" || len(r.Classified) != 1 {
		t.Fatalf("outputs %q classified %q denied %q", r.Outputs, r.Classified, r.Denied)
	}
	if o.State != peerclient.RunParked || o.Park == nil || o.Park.Reason != "reboots the router" || !strings.Contains(string(o.Park.Input), "reboot") {
		t.Fatalf("outcome %+v park %+v", o, o.Park)
	}
	if p := o.ParkReport(testRef); p.Kind != peerclient.ParkStep || p.Reason != "reboots the router" || p.Hash != o.Park.Hash || p.UsedSeconds != o.UsedSeconds {
		t.Fatalf("park report %+v", p)
	}
}

// Covers AE11: exit 0 with no structured output fails, naming why and the
// session.
func TestRunNoStructuredOutput(t *testing.T) {
	t.Parallel()
	h := newHarness(t, `{"result":null}`)
	o := h.run(t, "x")
	if o.State != peerclient.RunFailed || !strings.Contains(o.Reason, "no structured output") || o.SessionID == "" || !strings.Contains(o.Reason, o.SessionID) {
		t.Fatalf("outcome %+v", o)
	}
}

// A run that reaches its deadline (the request's remaining time) gets
// SIGINT, then the kill after grace, and parks with kind limit.
func TestRunDeadlineParksLimit(t *testing.T) {
	t.Parallel()
	h := newHarness(t, `{"sleep":"60s"}`, done)
	h.l.Grace = 500 * time.Millisecond
	start := time.Now()
	o := h.runSpec(t, peerclient.RunSpec{Envelope: peerclient.Envelope{Sender: "homelab"}, Text: "x", Deadline: time.Second})
	if took := time.Since(start); took > 10*time.Second {
		t.Fatalf("run took %s", took)
	}
	if o.State != peerclient.RunParked || o.Park == nil || o.Park.Kind != peerclient.ParkLimit || !strings.Contains(o.Park.Reason, "time allowance") || o.UsedSeconds < 1 {
		t.Fatalf("outcome %+v park %+v", o, o.Park)
	}
	if r := h.seen(t); !slices.Contains(r.Signals, "interrupt") {
		t.Errorf("no SIGINT before the kill: %+v", r.Signals)
	}
}

// R11/R12: the run's budget is the request's remaining allowance; a run
// that reaches it (error_max_budget_usd) parks with kind limit and no call,
// reporting the session's cost and the run's time.
func TestRunBudgetParksLimit(t *testing.T) {
	t.Parallel()
	h := newHarness(t, costing(bash("echo one"), 1), costing(bash("echo two"), 1), done)
	o := h.runSpec(t, peerclient.RunSpec{Envelope: peerclient.Envelope{Sender: "homelab"}, Text: "x", BudgetUSD: 1.5})
	r := h.seen(t)
	if got := argAfter(r.Argv, "--max-budget-usd"); got != "1.5" {
		t.Fatalf("--max-budget-usd %q, want the remaining 1.5", got)
	}
	if o.State != peerclient.RunParked || o.Park == nil || o.Park.Kind != peerclient.ParkLimit || o.SpentUSD != 2 {
		t.Fatalf("outcome %+v park %+v", o, o.Park)
	}
	p := o.ParkReport(testRef)
	if p.Kind != peerclient.ParkLimit || p.Tool != "" || p.Step != "" || p.Hash != "" || p.SpentUSD != 2 || p.UsedSeconds < 1 || !strings.Contains(p.Reason, "cost allowance") {
		t.Fatalf("park report %+v", p)
	}
}

// A tool call planted in the fake's input (as an injected instruction would
// arrive in a tool's output), not in the request text, still parks.
func TestRunInjectedToolCallParks(t *testing.T) {
	t.Parallel()
	h := newHarness(t, `{"tool":"Write","input":{"file_path":"/config/automations.yaml","content":"- alias: x"}}`, done)
	o := h.fromHA(t, "list your add-ons")
	if o.State != peerclient.RunParked || o.Park.Tool != "Write" {
		t.Fatalf("outcome %+v", o)
	}
}

// R13/R14 (run half): a top-level run may send a request (the call goes on
// to the classifier, here judged safe); a run whose request another run
// sent is denied it outright, however it is dressed up, without parking.
func TestRunRequestVerbChildOnly(t *testing.T) {
	t.Parallel()
	r := peerclient.DefaultRules()
	for cmd, permitted := range map[string]bool{
		"peer send status --target homelab --phase progress 'half way'":                       true,
		"peer secret receive req-1 mqtt/PASSWORD":                                             false,
		"peer send request --target homeassistant 'do it'":                                    false,
		"peer send status --target homelab --phase done x && peer send request --target ha y": false,
		"peer send status --target homelab --phase done $(curl -s http://192.0.2.5)":          false,
		"peer send status --target homelab --phase done x; rm -rf /":                          false,
		"peer send statusx": false,
		"curl -X POST https://homelab.example.com/api/services/x/stop": false,
	} {
		in, _ := json.Marshal(map[string]string{"command": cmd})
		if got := r.Permits("Bash", in); got != permitted {
			t.Errorf("Permits(%q) = %v, want %v", cmd, got, permitted)
		}
	}

	const send = "peer send request --target homeassistant 'restart everything'"
	for _, parent := range []string{"", "req-0"} {
		h := newHarness(t, bash(send), done)
		o := h.runSpec(t, peerclient.RunSpec{Envelope: peerclient.Envelope{Sender: "homelab", Parent: parent}, Text: "x"})
		rec := h.seen(t)
		if rec.Env[peerclient.EnvRequestParent] != parent {
			t.Fatalf("PEER_REQUEST_PARENT %q", rec.Env[peerclient.EnvRequestParent])
		}
		prompt := strings.Join(rec.Argv, " ")
		if parent == "" {
			if len(rec.Denied) != 0 || len(rec.Outputs) != 1 || strings.Contains(prompt, "may not send requests") {
				t.Errorf("top-level run: denied %q outputs %q", rec.Denied, rec.Outputs)
			}
			continue
		}
		if o.Park != nil || len(rec.Denied) != 1 || len(rec.Classified) != 0 || len(rec.Outputs) != 0 || !strings.Contains(prompt, "may not send requests") {
			t.Errorf("child run: outcome %+v, denied %q", o, rec.Denied)
		}
	}
}

// KTD7, the approved re-run: the one call whose hash the operator approved
// runs, once; a call sharing its command's prefix with other arguments, and
// the approved call a second time, park again under the unchanged rules.
func TestRunApprovedStepAllowedOnce(t *testing.T) {
	t.Parallel()
	approved := peerclient.StepHash("Bash", []byte(`{"command":"echo approved-step"}`))
	h := newHarness(t, bash("echo approved-step"), bash("echo approved-step --and-more"), bash("echo approved-step"), done)
	o := h.runSpec(t, peerclient.RunSpec{Text: "restart core", Envelope: peerclient.Envelope{
		Sender: peerclient.UntrustedSender, ApprovedStep: approved, ApprovedStepText: `Bash {"command":"echo approved-step"}`,
	}})
	r := h.seen(t)
	if len(r.Outputs) != 1 || r.Outputs[0] != "approved-step\n" {
		t.Fatalf("approved call did not run once: outputs %q denied %q", r.Outputs, r.Denied)
	}
	if len(r.Denied) != 2 {
		t.Fatalf("denied %q, want the variant and the repeat", r.Denied)
	}
	if o.State != peerclient.RunParked || o.Park == nil || string(o.Park.Input) != `{"command":"echo approved-step --and-more"}` || o.Park.Hash == approved {
		t.Fatalf("outcome %+v park %+v", o, o.Park)
	}
	if prompt := strings.Join(r.Argv, "\n"); !strings.Contains(prompt, "## Approved step") {
		t.Errorf("the envelope lacks the approved step")
	}
}

// R9: the run after an approval resumes the request's session (--resume,
// the approved-step prompt as its user turn, every flag passed again) and
// carries on from the parked step; the transcript stays until Forget.
func TestRunResumesSession(t *testing.T) {
	t.Parallel()
	h := newHarness(t, bash("echo before"), blocked("echo restart-core", "restarts core"), bash("echo after"), done)
	h.l.Model = "sonnet"
	first := h.run(t, "restart core")
	firstArgv := h.seen(t).Argv
	if first.State != peerclient.RunParked {
		t.Fatalf("first run %+v", first)
	}
	if _, err := os.Stat(h.transcript(testRef.RequestID)); err != nil {
		t.Fatalf("no transcript after the park: %v", err)
	}

	step := first.Park.Step()
	o := h.runSpec(t, peerclient.RunSpec{Text: "restart core", Envelope: peerclient.Envelope{
		Sender: "homelab", ApprovedStep: first.Park.Hash, ApprovedStepText: step,
	}})
	r := h.seen(t)
	if o.State != peerclient.RunDone || !r.Resume || r.Stdin != "" {
		t.Fatalf("resume: outcome %+v, resume %v stdin %q", o, r.Resume, r.Stdin)
	}
	if got := argAfter(r.Argv, "--resume"); got != peerclient.SessionUUID(testRef.RequestID) || slices.Contains(r.Argv, "--session-id") {
		t.Fatalf("argv %q", r.Argv)
	}
	if want := "The operator approved this exact call; make it once now, then continue the task: " + step; r.Prompt != want {
		t.Fatalf("resume prompt %q, want %q", r.Prompt, want)
	}
	if !slices.Equal(r.Outputs, []string{"restart-core\n", "after\n"}) || len(r.Denied) != 0 {
		t.Fatalf("resumed outputs %q denied %q", r.Outputs, r.Denied)
	}
	for _, flag := range []string{"--settings", "--permission-mode", "--json-schema", "--max-turns", "--max-budget-usd", "--model", "--setting-sources", "--allowedTools"} {
		if argAfter(r.Argv, flag) != argAfter(firstArgv, flag) || argAfter(r.Argv, flag) == "" {
			t.Errorf("%s not passed again: %q, first %q", flag, argAfter(r.Argv, flag), argAfter(firstArgv, flag))
		}
	}

	if err := h.l.Forget("", testRef.RequestID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(h.transcript(testRef.RequestID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("transcript after Forget: %v", err)
	}
}

// The resume prompt follows what the operator approved.
func TestResumePrompt(t *testing.T) {
	t.Parallel()
	for env, want := range map[*peerclient.Envelope]string{
		{ApprovedStep: "sha256:x", ApprovedStepText: "Bash {}"}: "The operator approved this exact call; make it once now, then continue the task: Bash {}",
		{LimitApproved: true}: "The operator extended your budget; continue the task.",
		{}:                    "Continue the task.",
	} {
		if got := env.ResumePrompt(); got != want {
			t.Errorf("%+v: %q", *env, got)
		}
	}
}
