package peerclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// RunRef binds a run to its request: the claim's attempt and listener
// instance, and the per-run token the hub issued at claim.
type RunRef struct {
	RequestID string `json:"request_id"`
	Attempt   int    `json:"attempt"`
	Instance  string `json:"instance"`
	Token     string `json:"token"`
}

// RunRefFromEnv reads the ref the launcher put in a run's environment.
func RunRefFromEnv(env func(string) string) (RunRef, error) {
	ref := RunRef{RequestID: env(EnvRequestID), Instance: env(EnvInstance), Token: env(EnvRunToken)}
	if ref.RequestID == "" || ref.Token == "" {
		return ref, errors.New("not inside a peer run (no PEER_REQUEST_ID / PEER_RUN_TOKEN)")
	}
	n, err := strconv.Atoi(env(EnvAttempt))
	if err != nil {
		return ref, fmt.Errorf("PEER_ATTEMPT: %w", err)
	}
	ref.Attempt = n
	return ref, nil
}

// ParkRequest reports a park: a blocked step (Kind ParkStep, the default),
// or a run that reached its cost or time allowance (Kind ParkLimit, with no
// tool, step or hash).
type ParkRequest struct {
	RunRef
	Kind        string  `json:"kind,omitempty"`
	Tool        string  `json:"tool,omitempty"`
	Step        string  `json:"step,omitempty"` // scrubbed
	Hash        string  `json:"hash,omitempty"`
	Reason      string  `json:"reason,omitempty"` // one line, at most 300 characters
	SpentUSD    float64 `json:"spent_usd,omitempty"`
	UsedSeconds int64   `json:"used_seconds,omitempty"`
}

// ResultRequest is a run's derived outcome, scrubbed.
type ResultRequest struct {
	RunRef
	Outcome     string      `json:"outcome"` // done, failed, parked
	Summary     string      `json:"summary,omitempty"`
	Actions     []string    `json:"actions,omitempty"`
	Reason      string      `json:"reason,omitempty"`
	Code        string      `json:"code,omitempty"` // failed only: the hub's reason code
	SessionID   string      `json:"session_id,omitempty"`
	Park        *ParkRecord `json:"park,omitempty"`
	SpentUSD    float64     `json:"spent_usd,omitempty"`
	UsedSeconds int64       `json:"used_seconds,omitempty"`
}

// HubRunAPI is the hub's run-scoped operations as the run side needs them;
// the integration maps them onto the hub's wire operations.
type HubRunAPI interface {
	Park(ctx context.Context, r ParkRequest) error
	PostResult(ctx context.Context, r ResultRequest) error
}

// Launcher defaults. A request's run takes its budget and deadline from the
// claim (the request's remaining allowance); these apply to a run without
// them (the canary).
const (
	DefaultRunTimeout   = 30 * time.Minute
	DefaultRunGrace     = 10 * time.Second
	DefaultMaxTurns     = 50
	DefaultMaxBudgetUSD = 2.0
	// DefaultSettingSources loads the working directory's project settings
	// and CLAUDE.md (the host's own agent instructions) but not the user's
	// or local settings, whose allow rules, hooks and plugins belong to the
	// operator's interactive sessions.
	DefaultSettingSources = "project"
)

// Launcher starts constrained headless Claude Code runs in auto mode.
type Launcher struct {
	Claude string // claude binary; "claude" on PATH when empty
	Peer   string // peer binary the hooks run as `<Peer> park`; this executable when empty
	Dir    string // working directory of a run whose spec names none
	Rules  Rules
	// Policy is the auto-mode classifier's policy; zero is DefaultPolicy.
	Policy Policy

	Model string
	// Timeout and MaxBudgetUSD apply to a run whose spec sets no deadline
	// or budget.
	Timeout, Grace time.Duration
	MaxTurns       int
	MaxBudgetUSD   float64
	SettingSources string
	// RunRoot holds each run's private directory (its park file);
	// os.TempDir when empty.
	RunRoot string
	Env     []string // extra environment for runs
	Log     *slog.Logger

	// observe keeps the run going after a park, and inspect sees the run's
	// park file before it is removed (the canary).
	observe bool
	inspect func(parkFile string)
}

// RunSpec is one run of a request.
type RunSpec struct {
	Ref      RunRef
	Envelope Envelope // RequestID and Sender default from Ref and the request
	Text     string   // the request text, the first run's prompt
	// Dir is the run's working directory (the request's worktree); empty
	// is Launcher.Dir.
	Dir string
	// BudgetUSD and Deadline are the request's remaining cost and time
	// allowance; zero is Launcher.MaxBudgetUSD and Launcher.Timeout.
	BudgetUSD float64
	Deadline  time.Duration
}

// Outcome is what the listener derived from a run.
type Outcome struct {
	State   string // RunDone, RunFailed, RunParked
	Summary string
	Actions []string
	Reason  string // why, for failed and parked
	// Code is a failure's reason code on the hub (PeerRequestReason):
	// ReasonRunFailed, ReasonNoOutput or ReasonInvalidOutput.
	Code      string
	SessionID string
	Park      *ParkRecord // parked only; Kind ParkLimit at the allowance
	// SpentUSD is the session's cost so far (claude's total_cost_usd, which
	// counts every resume), 0 when the run printed none; UsedSeconds is
	// this run's wall time, rounded up.
	SpentUSD    float64
	UsedSeconds int64
}

func (o Outcome) Result(ref RunRef) ResultRequest {
	return ResultRequest{RunRef: ref, Outcome: o.State, Summary: o.Summary,
		Actions: o.Actions, Reason: o.Reason, Code: o.Code, SessionID: o.SessionID, Park: o.Park,
		SpentUSD: o.SpentUSD, UsedSeconds: o.UsedSeconds}
}

// ParkReport is a parked outcome as the hub's park.
func (o Outcome) ParkReport(ref RunRef) ParkRequest {
	p := ParkRequest{RunRef: ref, Kind: ParkStep, Reason: o.Park.Reason, SpentUSD: o.SpentUSD, UsedSeconds: o.UsedSeconds}
	if o.Park.Kind == ParkLimit {
		p.Kind = ParkLimit
	} else {
		p.Tool, p.Step, p.Hash = o.Park.Tool, o.Park.Step(), o.Park.Hash
	}
	return p
}

// claudeResult is the part of `--output-format json` the launcher reads.
type claudeResult struct {
	Type             string          `json:"type"`
	Subtype          string          `json:"subtype"`
	IsError          bool            `json:"is_error"`
	SessionID        string          `json:"session_id"`
	Result           string          `json:"result"`
	TotalCostUSD     float64         `json:"total_cost_usd"`
	StructuredOutput json.RawMessage `json:"structured_output"`
}

// subtypeMaxBudget ends a run that reached --max-budget-usd.
const subtypeMaxBudget = "error_max_budget_usd"

// Run executes one run of a request and derives its outcome. The session is
// the request's (SessionUUID): a run whose transcript exists resumes it with
// the envelope's resume prompt, any other starts it with the request text.
// Run never returns an error: a run that cannot start is a failed outcome
// naming why.
func (l *Launcher) Run(ctx context.Context, spec RunSpec) Outcome {
	log := l.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	sessionID := SessionUUID(spec.Ref.RequestID)
	fail := func(reason string) Outcome { return failed(ReasonRunFailed, reason, sessionID) }

	tmp, err := os.MkdirTemp(l.RunRoot, "peer-run-")
	if err != nil {
		return fail("creating the run directory: " + err.Error())
	}
	defer os.RemoveAll(tmp)
	parkFile := filepath.Join(tmp, "park.json")

	env := spec.Envelope
	if env.RequestID == "" {
		env.RequestID = spec.Ref.RequestID
	}
	dir := spec.Dir
	if dir == "" {
		dir = l.Dir
	}
	budget := spec.BudgetUSD
	if budget <= 0 {
		budget = l.MaxBudgetUSD
	}
	if budget <= 0 {
		budget = DefaultMaxBudgetUSD
	}
	deadline := spec.Deadline
	if deadline <= 0 {
		deadline = l.Timeout
	}
	if deadline <= 0 {
		deadline = DefaultRunTimeout
	}
	environ := runEnviron(l.Env)
	_, serr := os.Stat(TranscriptPath(claudeConfigDir(environ), dir, sessionID))
	resume := serr == nil

	args, err := l.args(env, sessionID, resume, budget)
	if err != nil {
		return fail(err.Error())
	}
	rules, _ := json.Marshal(l.Rules.forRun(env.Parent != ""))
	claude := l.Claude
	if claude == "" {
		claude = "claude"
	}
	cmd := exec.Command(claude, args...)
	cmd.Dir = dir
	if !resume {
		cmd.Stdin = strings.NewReader(spec.Text)
	}
	var stdout, stderr capped
	stdout.max, stderr.max = 8<<20, 16<<10
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	started := time.Now()
	cmd.Env = append(environ,
		EnvRequestID+"="+spec.Ref.RequestID,
		EnvAttempt+"="+strconv.Itoa(spec.Ref.Attempt),
		EnvInstance+"="+spec.Ref.Instance,
		EnvRunToken+"="+spec.Ref.Token,
		EnvParkFile+"="+parkFile,
		EnvRunRules+"="+string(rules),
		EnvApprovedStep+"="+env.ApprovedStep,
		EnvRequestSender+"="+env.Sender,
		EnvRequestParent+"="+env.Parent,
	)
	if l.observe {
		cmd.Env = append(cmd.Env, EnvParkObserve+"=1")
	}
	grace := l.Grace
	if grace <= 0 {
		grace = DefaultRunGrace
	}
	cmd.WaitDelay = grace

	if err := cmd.Start(); err != nil {
		return fail("starting claude: " + err.Error())
	}
	log.Info("run started", "request", spec.Ref.RequestID, "attempt", spec.Ref.Attempt, "session", sessionID, "resume", resume,
		"budget_usd", budget, "deadline", deadline.String(), "pid", cmd.Process.Pid)
	pgid := cmd.Process.Pid
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()

	timer := time.NewTimer(deadline)
	defer timer.Stop()
	poll := time.NewTicker(500 * time.Millisecond)
	defer poll.Stop()

	stopReason := ""
	var waitErr error
wait:
	for {
		select {
		case waitErr = <-exited:
			break wait
		case <-poll.C:
			if !l.observe {
				if _, err := os.Stat(parkFile); err == nil {
					stopReason = "parked"
				}
			}
		case <-timer.C:
			stopReason = stopTimeout
		case <-ctx.Done():
			stopReason = stopListener
		}
		if stopReason != "" {
			waitErr = stop(pgid, exited, grace)
			break wait
		}
	}
	_ = syscall.Kill(-pgid, syscall.SIGKILL)
	used := usedSeconds(time.Since(started))
	log.Info("run ended", "request", spec.Ref.RequestID, "session", sessionID, "stopped", stopReason, "exit", fmt.Sprint(waitErr), "used_seconds", used)

	o := l.derive(parkFile, stopReason, deadline, waitErr, stdout.Bytes(), stderr.String(), sessionID)
	o.UsedSeconds = used
	if l.inspect != nil {
		l.inspect(parkFile)
	}
	return o
}

// Forget deletes the Claude session of request id's runs in dir (the
// transcript, which holds every value the run was handed, with it), once
// the request has ended.
func (l *Launcher) Forget(dir, id string) error {
	if dir == "" {
		dir = l.Dir
	}
	return forgetSession(claudeConfigDir(runEnviron(l.Env)), dir, SessionUUID(id))
}

// usedSeconds is d in whole seconds, rounded up.
func usedSeconds(d time.Duration) int64 {
	return int64((max(d, 0) + time.Second - 1) / time.Second)
}

// derive: a recorded park wins, then reaching the allowance (the deadline or
// the budget: a limit park), then the run's structured output, then a
// failure naming why. The session's cost is read whenever claude printed it.
func (l *Launcher) derive(parkFile, stopReason string, deadline time.Duration, waitErr error, stdout []byte, stderr, sessionID string) Outcome {
	var res claudeResult
	jerr := json.Unmarshal(bytes.TrimSpace(stdout), &res)
	o := l.deriveState(parkFile, stopReason, deadline, waitErr, res, jerr == nil, stderr, sessionID)
	if jerr == nil {
		o.SpentUSD = res.TotalCostUSD
	}
	return o
}

func (l *Launcher) deriveState(parkFile, stopReason string, deadline time.Duration, waitErr error, res claudeResult, printed bool, stderr, sessionID string) Outcome {
	fail := func(code, reason string) Outcome { return failed(code, reason, sessionID) }
	limit := func(reason string) Outcome {
		return Outcome{State: RunParked, Reason: reason, SessionID: sessionID, Park: &ParkRecord{Kind: ParkLimit, Reason: reason, At: time.Now().UTC()}}
	}
	park, err := ReadPark(parkFile)
	if err != nil {
		return fail(ReasonRunFailed, "reading the park record: "+err.Error())
	}
	if park != nil {
		return Outcome{State: RunParked, Reason: "parked on " + park.Tool, SessionID: sessionID, Park: park}
	}
	switch stopReason {
	case stopTimeout:
		return limit("reached the request's time allowance (" + deadline.String() + " left at the start of this run)")
	case stopListener:
		return fail(ReasonRunFailed, "interrupted: the listener is stopping")
	}
	if printed {
		if res.Subtype == subtypeMaxBudget {
			return limit("reached the request's cost allowance")
		}
		if s, ok := parseStructured(res.StructuredOutput); ok {
			o := Outcome{State: s.Outcome, Summary: s.Summary, Actions: s.Actions, SessionID: sessionID}
			if o.State == RunFailed {
				o.Code = ReasonRunFailed
			}
			return o
		}
		if raw := bytes.TrimSpace(res.StructuredOutput); len(raw) > 0 && string(raw) != "null" {
			return fail(ReasonInvalidOutput, "structured output does not match the schema")
		}
		why := "no structured output"
		if res.Subtype != "" && res.Subtype != "success" {
			why += " (" + res.Subtype + ")"
		}
		return fail(ReasonNoOutput, why)
	}
	if waitErr != nil {
		return fail(ReasonRunFailed, "claude exited: "+waitErr.Error()+tail(stderr))
	}
	return fail(ReasonNoOutput, "no structured output"+tail(stderr))
}

// Why the launcher stopped a run early. A park stops it too (logged as
// "parked"), but derive reads the park file for that.
const (
	stopTimeout  = "timeout"
	stopListener = "listener stopping"
)

// Failure reason codes a listener posts (PeerRequestReason).
const (
	ReasonRunFailed     = "run_failed"
	ReasonNoOutput      = "no_output"
	ReasonInvalidOutput = "invalid_output"
	ReasonTimeout       = "timeout"
)

func failed(code, reason, sessionID string) Outcome {
	return Outcome{State: RunFailed, Code: code, Reason: reason + " (session " + sessionID + ")", SessionID: sessionID}
}

func tail(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if len(s) > 300 {
		s = "…" + s[len(s)-300:]
	}
	return ": " + s
}

// stop sends SIGINT to the run's process group, then SIGKILL after grace.
func stop(pgid int, exited <-chan error, grace time.Duration) error {
	_ = syscall.Kill(-pgid, syscall.SIGINT)
	select {
	case err := <-exited:
		return err
	case <-time.After(grace):
	}
	_ = syscall.Kill(-pgid, syscall.SIGKILL)
	return <-exited
}

// args is claude's command line. A resume names the session with --resume
// and takes the envelope's resume prompt as its positional prompt; a first
// run names it with --session-id and reads the request text on stdin. Every
// other flag is the same on both, since a resume does not keep them.
func (l *Launcher) args(env Envelope, sessionID string, resume bool, budget float64) ([]string, error) {
	peer := l.Peer
	if peer == "" {
		exe, err := os.Executable()
		if err != nil {
			return nil, fmt.Errorf("locating the peer binary for the hook: %w", err)
		}
		peer = exe
	}
	hook := func(command string) []any {
		return []any{map[string]any{
			"matcher": "*",
			"hooks":   []any{map[string]any{"type": "command", "command": command, "timeout": 30}},
		}}
	}
	settings, err := json.Marshal(map[string]any{
		// Wins over a project setting that would turn hooks off: --settings
		// ranks above every file source.
		"disableAllHooks": false,
		"hooks": map[string]any{
			"PreToolUse":       hook(shellQuote(peer) + " park"),
			"PermissionDenied": hook(shellQuote(peer) + " park --denied"),
		},
		"permissions": map[string]any{"defaultMode": "auto", "disableBypassPermissionsMode": "disable"},
		"autoMode":    l.Policy.forRun().autoMode(),
	})
	if err != nil {
		return nil, err
	}
	sources := l.SettingSources
	if sources == "" {
		sources = DefaultSettingSources
	}
	turns := l.MaxTurns
	if turns <= 0 {
		turns = DefaultMaxTurns
	}
	args := []string{"-p"}
	if resume {
		// The prompt right after -p: the rule lists at the end are
		// variadic and would take a trailing one.
		args = append(args, env.ResumePrompt(), "--resume", sessionID)
	} else {
		args = append(args, "--session-id", sessionID)
	}
	args = append(args,
		"--output-format", "json",
		"--json-schema", OutputSchema,
		"--append-system-prompt", env.SystemPrompt(),
		"--permission-mode", "auto",
		"--setting-sources", sources,
		"--strict-mcp-config",
		"--settings", string(settings),
		"--max-turns", strconv.Itoa(turns),
		"--max-budget-usd", strconv.FormatFloat(budget, 'f', -1, 64),
	)
	if l.Model != "" {
		args = append(args, "--model", l.Model)
	}
	// Rules last: the variadic rule lists end at the next flag or the end.
	return append(args, l.Rules.forRun(env.Parent != "").Flags()...), nil
}

// runEnviron is the listener's environment without any run variables it may
// itself have inherited, plus extra.
func runEnviron(extra []string) []string {
	var out []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "PEER_") || strings.HasPrefix(kv, EnvHubURL+"=") {
			out = append(out, kv)
		}
	}
	return append(out, extra...)
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// capped is a buffer that keeps the first max bytes.
type capped struct {
	bytes.Buffer
	max int
}

func (c *capped) Write(p []byte) (int, error) {
	if room := c.max - c.Len(); room > 0 {
		c.Buffer.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}
