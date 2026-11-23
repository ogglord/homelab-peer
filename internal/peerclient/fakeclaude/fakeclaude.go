// Package fakeclaude is a stand-in for the claude binary in the peer run
// tests: a test binary's TestMain calls Main when a wrapper script re-enters
// it (see internal/peerclient/testdata). It never calls the API. Only tests
// import it.
package fakeclaude

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ogglord/homelab-peer/internal/peerclient"
)

// step is one move of the fake.
type step struct {
	Tool   string          `json:"tool,omitempty"`
	Input  json.RawMessage `json:"input,omitempty"`
	Sleep  string          `json:"sleep,omitempty"`
	Result json.RawMessage `json:"result,omitempty"` // structured output; JSON null prints a result without one
	// Classifier "block" makes auto mode's classifier block the call when
	// it reaches it (neither a hook nor the allow list decided), with
	// Reason; any other call reaching it is judged safe.
	Classifier string `json:"classifier,omitempty"`
	Reason     string `json:"reason,omitempty"`
	// Cost is what the step costs, in USD.
	Cost float64 `json:"cost,omitempty"`
}

// Record is what the fake saw and did.
type Record struct {
	Argv   []string          `json:"argv"`
	Stdin  string            `json:"stdin"`
	Prompt string            `json:"prompt"` // the positional prompt (a resume's)
	Resume bool              `json:"resume"`
	Env    map[string]string `json:"env"`
	// Outputs are the executed Bash steps' stdout, Denied every denied
	// call, Classified the calls auto mode's classifier blocked.
	Outputs    []string `json:"outputs"`
	Denied     []string `json:"denied"`
	Classified []string `json:"classified"`
	Signals    []string `json:"signals"`
}

// session is what the fake keeps in its transcript: where a resume picks up
// (the first denied step, else the step after the last one made) and the
// session's cost so far.
type session struct {
	ResumeAt int     `json:"resume_at"`
	CostUSD  float64 `json:"cost_usd"`
}

// Main is the fake claude. It reads its script from the
// environment, like a model whose next moves were planted in its input:
//
//	FAKE_CLAUDE_STEPS         JSON list of steps (step)
//	FAKE_CLAUDE_CANARY_STEPS  steps for the canary run (PEER_REQUEST_ID=canary)
//	                          instead of FAKE_CLAUDE_STEPS, when set
//	FAKE_CLAUDE_NOHOOKS       "1": ignore --settings hooks (a build without hook support)
//	FAKE_CLAUDE_RECORD        file the fake writes what it saw to (Record); the
//	                          last run wins
//	FAKE_CLAUDE_SIGINT_EXITS  "1": exit on SIGINT, as Claude Code does; by
//	                          default SIGINT is ignored and only the kill ends it
//
// Tool calls go through the PreToolUse hooks from --settings exactly as
// Claude Code runs them (sh -c, tool call JSON on stdin). A call no hook
// decided runs when --allowedTools allows it; otherwise, under
// --permission-mode auto, the step's scripted classifier decides (a block
// runs the PermissionDenied hooks), and under any other mode it is denied.
// An executed Bash step's stdout is {{outN}} in later steps; {{canary-touch}}
// and {{canary-rm}} become the canary's two commands, and a step holding one
// is skipped in a run that has none.
//
// The session is a transcript at peerclient.TranscriptPath: --session-id
// starts it, --resume continues it (from the first step the run before was
// denied, else after its last step) and fails without one. A result prints
// total_cost_usd, the session's cost; a step that brings this invocation's
// cost to --max-budget-usd ends it with subtype error_max_budget_usd.
func Main(args []string) int {
	rec := Record{Argv: args, Env: map[string]string{}}
	for _, k := range []string{peerclient.EnvRunRules, peerclient.EnvRunToken, peerclient.EnvRequestID,
		peerclient.EnvParkFile, peerclient.EnvRequestSender, peerclient.EnvRequestParent, peerclient.EnvApprovedStep} {
		rec.Env[k] = os.Getenv(k)
	}
	var mu sync.Mutex
	save := func() {
		mu.Lock()
		defer mu.Unlock()
		if p := os.Getenv("FAKE_CLAUDE_RECORD"); p != "" {
			data, _ := json.Marshal(rec)
			_ = os.WriteFile(p, data, 0o600)
		}
	}

	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGINT)
	go func() {
		for s := range sigs {
			mu.Lock()
			rec.Signals = append(rec.Signals, s.String())
			mu.Unlock()
			save()
			if os.Getenv("FAKE_CLAUDE_SIGINT_EXITS") == "1" {
				os.Exit(130)
			}
			// Otherwise keep running: only the kill ends it.
		}
	}()

	var allow, deny []string
	var settings, sessionID, mode string
	budget := -1.0
	var list *[]string
	for i := 0; i < len(args); i++ {
		a := args[i]
		value := func() string {
			if i+1 < len(args) {
				i++
				return args[i]
			}
			return ""
		}
		switch {
		case a == "--allowedTools":
			list = &allow
		case a == "--disallowedTools":
			list = &deny
		case strings.HasPrefix(a, "--"):
			list = nil
			switch a {
			case "--settings":
				settings = value()
			case "--session-id":
				sessionID = value()
			case "--resume":
				sessionID, rec.Resume = value(), true
			case "--permission-mode":
				mode = value()
			case "--max-budget-usd":
				budget, _ = strconv.ParseFloat(value(), 64)
			}
		case list != nil:
			*list = append(*list, a)
		case i == 1 && args[0] == "-p":
			rec.Prompt = a
		}
	}
	if !rec.Resume {
		stdin, _ := readAll(os.Stdin)
		rec.Stdin = stdin
	}

	cwd, _ := os.Getwd()
	transcript := peerclient.TranscriptPath(configDir(), cwd, sessionID)
	var sess session
	if rec.Resume {
		data, err := os.ReadFile(transcript)
		if err != nil || json.Unmarshal(data, &sess) != nil {
			save()
			fmt.Fprintln(os.Stderr, "No conversation found with session ID:", sessionID)
			return 1
		}
	}
	writeSession := func() {
		_ = os.MkdirAll(filepath.Dir(transcript), 0o700)
		data, _ := json.Marshal(sess)
		_ = os.WriteFile(transcript, data, 0o600)
	}
	writeSession()
	startCost := sess.CostUSD

	cli := peerclient.Rules{Allow: allow, Deny: deny}
	hooks := map[string][]string{}
	if os.Getenv("FAKE_CLAUDE_NOHOOKS") != "1" {
		var s struct {
			Hooks map[string][]struct {
				Hooks []struct{ Command string } `json:"hooks"`
			} `json:"hooks"`
		}
		_ = json.Unmarshal([]byte(settings), &s)
		for event, matchers := range s.Hooks {
			for _, m := range matchers {
				for _, h := range m.Hooks {
					hooks[event] = append(hooks[event], h.Command)
				}
			}
		}
	}
	g := gate{hooks: hooks, cli: cli, auto: mode == "auto", sessionID: sessionID}

	script := os.Getenv("FAKE_CLAUDE_STEPS")
	if c := os.Getenv("FAKE_CLAUDE_CANARY_STEPS"); c != "" && os.Getenv(peerclient.EnvRequestID) == "canary" {
		script = c
	}
	var steps []json.RawMessage
	_ = json.Unmarshal([]byte(script), &steps)
	save()
	firstDenied := -1
	result := func(out map[string]any) {
		out["type"], out["session_id"], out["total_cost_usd"] = "result", sessionID, sess.CostUSD
		data, _ := json.Marshal(out)
		fmt.Println(string(data))
	}
	for i := sess.ResumeAt; i < len(steps); i++ {
		text := string(steps[i])
		mu.Lock()
		outputs := append([]string(nil), rec.Outputs...)
		mu.Unlock()
		for j, out := range outputs {
			q, _ := json.Marshal(out)
			text = strings.ReplaceAll(text, "{{out"+fmt.Sprint(j)+"}}", strings.Trim(string(q), `"`))
		}
		if text = canaryCommand(text, rec.Stdin); text == "" {
			continue // not the canary
		}
		var st step
		_ = json.Unmarshal([]byte(text), &st)
		denied := false
		switch {
		case st.Sleep != "":
			d, _ := time.ParseDuration(st.Sleep)
			time.Sleep(d)
		case st.Result != nil:
			out := map[string]any{"subtype": "success", "is_error": false, "result": "ok"}
			// Like 2.1.312: the answer is a StructuredOutput tool call,
			// which the hooks and the allow-list see first.
			if string(st.Result) != "null" {
				call := step{Tool: peerclient.StructuredOutputTool, Input: st.Result}
				if ok, _ := g.allowed(call); ok {
					out["structured_output"] = st.Result
				} else {
					out["subtype"] = "error_max_structured_output_retries"
				}
			}
			result(out)
		case st.Tool != "":
			ok, classified := g.allowed(st)
			if !ok {
				denied = true
				mu.Lock()
				rec.Denied = append(rec.Denied, st.Tool+" "+string(st.Input))
				if classified {
					rec.Classified = append(rec.Classified, st.Tool+" "+string(st.Input))
				}
				mu.Unlock()
				break
			}
			if st.Tool == "Bash" {
				var in struct{ Command string }
				_ = json.Unmarshal(st.Input, &in)
				out, _ := exec.Command("sh", "-c", in.Command).Output()
				mu.Lock()
				rec.Outputs = append(rec.Outputs, string(out))
				mu.Unlock()
			}
		}
		sess.CostUSD += st.Cost
		if denied && firstDenied < 0 {
			firstDenied = i
		}
		sess.ResumeAt = i + 1
		if firstDenied >= 0 {
			sess.ResumeAt = firstDenied
		}
		writeSession()
		save()
		if budget >= 0 && st.Cost > 0 && sess.CostUSD-startCost >= budget {
			result(map[string]any{"subtype": "error_max_budget_usd", "is_error": true})
			return 0
		}
	}
	save()
	return 0
}

// canaryCommand fills a step's canary placeholder from the canary prompt's
// command lines; "" when the step has one and the prompt has none.
func canaryCommand(text, prompt string) string {
	for placeholder, verb := range map[string]string{"{{canary-touch}}": "touch ", "{{canary-rm}}": "rm "} {
		if !strings.Contains(text, placeholder) {
			continue
		}
		for _, line := range strings.Split(prompt, "\n") {
			if line = strings.TrimSpace(line); strings.HasPrefix(line, verb) {
				text = strings.ReplaceAll(text, placeholder, line)
			}
		}
		if strings.Contains(text, placeholder) {
			return ""
		}
	}
	return text
}

// configDir is the Claude config directory, as Claude Code finds it.
func configDir() string {
	if d := os.Getenv("CLAUDE_CONFIG_DIR"); d != "" {
		return d
	}
	return filepath.Join(os.Getenv("HOME"), ".claude")
}

// gate is the fake's permission check.
type gate struct {
	hooks     map[string][]string // by event
	cli       peerclient.Rules
	auto      bool
	sessionID string
}

// allowed runs the PreToolUse hooks, then the allow list, then (auto mode)
// the classifier on one call; classified reports a classifier block.
func (g gate) allowed(st step) (ok, classified bool) {
	decision := ""
	for _, h := range g.hooks["PreToolUse"] {
		if d := runHook(h, g.input("PreToolUse", st, nil)); d != "" {
			decision = d
		}
		if decision == "deny" {
			return false, false
		}
	}
	switch {
	case decision == "allow" || g.cli.Permits(st.Tool, st.Input):
		return true, false
	case !g.auto:
		return false, false
	case st.Classifier != "block":
		return true, false
	}
	for _, h := range g.hooks["PermissionDenied"] {
		runHook(h, g.input("PermissionDenied", st, map[string]any{"reason": st.Reason}))
	}
	return false, true
}

func (g gate) input(event string, st step, extra map[string]any) []byte {
	in := map[string]any{"session_id": g.sessionID, "hook_event_name": event, "tool_name": st.Tool, "tool_input": st.Input}
	for k, v := range extra {
		in[k] = v
	}
	b, _ := json.Marshal(in)
	return b
}

// runHook runs one hook command the way Claude Code does and returns its
// permission decision.
func runHook(command string, input []byte) string {
	cmd := exec.Command("sh", "-c", command)
	cmd.Stdin = bytes.NewReader(input)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 2 {
		return "deny"
	}
	var d struct {
		HookSpecificOutput struct {
			PermissionDecision string `json:"permissionDecision"`
		} `json:"hookSpecificOutput"`
	}
	_ = json.Unmarshal(out.Bytes(), &d)
	return d.HookSpecificOutput.PermissionDecision
}

func readAll(f *os.File) (string, error) {
	var b bytes.Buffer
	_, err := b.ReadFrom(f)
	return b.String(), err
}
