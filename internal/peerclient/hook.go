package peerclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Rules is a run's tool rule list in Claude Code permission-rule syntax. The
// launcher passes Allow as --allowedTools and Deny as --disallowedTools, and
// hands the same value to the PreToolUse hook (PEER_RUN_RULES), so the CLI's
// own allow-list mode and the hook cannot drift.
//
// The hook understands a subset of the syntax and parks anything it does not
// understand:
//   - a bare tool name ("Read") matches every call of that tool; an MCP server
//     name ("mcp__ha") matches every tool of that server;
//   - Bash(prefix:*) matches a command that is the prefix or the prefix and a
//     space-separated rest, Bash(cmd) matches exactly. A compound command (|,
//     ||, &&, ;) matches only when every part does. Output discarded or
//     merged (2>&1, 1>&2, >&2, >/dev/null, 1>, 2> and &> /dev/null) is
//     dropped before matching; any other redirection, command or process
//     substitution, variables, subshells, background & and newlines never
//     match, so the hook is stricter than the CLI, never looser;
//   - a Bash spec with a * elsewhere (Bash(*peer/approvers*)) is a glob over
//     the command's words, quotes dropped;
//   - WebFetch(domain:host) matches a URL on exactly that host, and
//     WebFetch(domain:*.suffix) any host under suffix; any other WebFetch
//     spec is a glob over the URL, which only the hook checks (Flags leaves
//     it out).
//
// A Deny match blocks the call even when an Allow rule also matches, and even
// with an approval, so the hook denies it outright instead of parking it. A
// Bash command the hook cannot split matches a Bash deny rule when the rule's
// command words appear as consecutive words anywhere in it, so an approval
// never runs one. Deny rules are best effort: an absolute path
// (/run/current-system/sw/bin/curl), a wrapper such as env or command, a
// variable, or WebFetch to an IP spells a blocked call another way and is not
// caught. Such a call still parks as an ordinary step; the approval gate and
// the allow list are the control.
type Rules struct {
	Allow []string `json:"allow"`
	Deny  []string `json:"deny"`
}

// DefaultRules is the first, deliberately small list: read-only file tools,
// the reply verbs and the read-only text filters. Every other call goes to
// Claude Code's auto-mode classifier under the host's Policy, or parks when
// Home Assistant sent the request.
//
// The deny list is a backstop for the CLI layer, in case a setting the run
// still loads (project settings) allows more: the usual ways to the
// dashboard API on homelab (curl/wget, the homelab CLI). The host's own
// domain is the installer's to add (`--deny 'WebFetch(domain:*.example.com)'`).
// WebFetch is not allowed by default at all; a host that needs it adds
// WebFetch(domain:<host>). forRun adds the hard-deny floor whatever the
// host's deny list says.
func DefaultRules() Rules {
	return Rules{
		Allow: slices.Concat([]string{"Read", "Grep", "Glob"}, replyVerbs, readFilters),
		Deny: []string{
			"Bash(curl:*)", "Bash(wget:*)",
			"Bash(homelab:*)",
		},
	}
}

// requestVerbRules deny sending a request. forRun adds them for a run whose
// request another run sent (R14: one level deep); a top-level run may send
// requests to other hosts.
var requestVerbRules = []string{"Bash(peer send request:*)", "Bash(peer --json send request:*)"}

// approverRules deny a run the daemon's approver routes (/peer/approvers,
// /api/peer/approvers): enrolling or revoking the phone that signs
// approvals. Best effort, by substring of the command or the URL.
var approverRules = []string{"Bash(*peer/approvers*)", "WebFetch(*peer/approvers*)"}

// replyVerbs are the peer commands the run envelope tells every run to use;
// every run's list allows them.
var replyVerbs = []string{
	"Bash(peer send status:*)",
}

// readFilters are text filters a pipeline ends in to trim a command's output
// (ha addons list | head). They only read, as Read already does, so every
// run's list allows them. tail (-f never ends) and sort (-o writes) are left
// out.
var readFilters = []string{"Bash(head:*)", "Bash(grep:*)", "Bash(wc:*)", "Bash(jq:*)"}

// StructuredOutputTool is the tool Claude Code 2.1.312 calls to return the
// --json-schema answer. It passes through PreToolUse hooks like any other
// tool, so a run must always allow it or every run would park at its end.
const StructuredOutputTool = "StructuredOutput"

// forRun is the list a run gets: the host's rules plus the reply verbs, the
// read filters and the structured output tool, so a host's own allow list
// cannot drop what the envelope tells the run to call; and the hard-deny
// floor, so a host's own deny list cannot drop it: the approver routes
// always, the request verb when child (another run sent the run's request).
// Both the flags and the hook take this one value.
func (r Rules) forRun(child bool) Rules {
	add := func(list []string, rules ...string) []string {
		for _, rule := range rules {
			if !slices.Contains(list, rule) {
				list = append(list, rule)
			}
		}
		return list
	}
	allow := add(slices.Clone(r.Allow), slices.Concat(replyVerbs, readFilters, []string{StructuredOutputTool})...)
	deny := add(slices.Clone(r.Deny), approverRules...)
	if child {
		deny = add(deny, requestVerbRules...)
	}
	return Rules{Allow: allow, Deny: deny}
}

// Flags is the rule list as claude arguments; each rule is its own argument
// because rules contain spaces. A rule only the hook understands (WebFetch
// by URL substring) stays out of the flags.
func (r Rules) Flags() []string {
	cli := func(rules []string) []string { return slices.DeleteFunc(slices.Clone(rules), hookOnly) }
	var out []string
	if allow := cli(r.Allow); len(allow) > 0 {
		out = append(append(out, "--allowedTools"), allow...)
	}
	if deny := cli(r.Deny); len(deny) > 0 {
		out = append(append(out, "--disallowedTools"), deny...)
	}
	return out
}

// hookOnly reports a rule the CLI has no syntax for: a WebFetch rule other
// than WebFetch(domain:...).
func hookOnly(rule string) bool {
	spec, ok := strings.CutPrefix(rule, "WebFetch(")
	return ok && !strings.HasPrefix(spec, "domain:")
}

// Permits reports whether the hook lets this call through to the CLI's own
// permission check: no Deny rule matches, and an Allow rule matches the call
// or, for Bash, each part of the command (parts may match different rules).
func (r Rules) Permits(tool string, input json.RawMessage) bool {
	if r.Denies(tool, input) {
		return false
	}
	if slices.ContainsFunc(r.Allow, func(rule string) bool { return matchRule(rule, tool, input) }) {
		return true
	}
	specs := bashSpecs(r.Allow)
	if tool != "Bash" || len(specs) == 0 {
		return false
	}
	cmd, ok := bashCommand(input)
	if !ok {
		return false
	}
	parts, ok := splitCommand(cmd)
	return ok && !slices.ContainsFunc(parts, func(p string) bool {
		return !slices.ContainsFunc(specs, func(spec string) bool { return matchCommand(spec, p) })
	})
}

// Denies reports whether a Deny rule matches. For Bash a deny matches when any
// part of a compound command matches; in a command the hook cannot split,
// when the rule's command words appear anywhere in it (commandWords), so an
// approval never runs one.
func (r Rules) Denies(tool string, input json.RawMessage) bool {
	if slices.ContainsFunc(r.Deny, func(rule string) bool { return matchRule(rule, tool, input) }) {
		return true
	}
	specs := bashSpecs(r.Deny)
	if tool != "Bash" || len(specs) == 0 {
		return false
	}
	cmd, ok := bashCommand(input)
	if !ok {
		return true // fail closed
	}
	parts, ok := splitCommand(cmd)
	if !ok {
		words := commandWords(cmd)
		return slices.ContainsFunc(specs, func(spec string) bool {
			if isGlob(spec) {
				return globMatch(spec, strings.Join(words, " "))
			}
			return containsWords(words, commandWords(strings.TrimSuffix(spec, ":*")))
		})
	}
	return slices.ContainsFunc(parts, func(p string) bool {
		return slices.ContainsFunc(specs, func(spec string) bool { return matchCommand(spec, p) })
	})
}

// bashSpecs returns the specs of the Bash(spec) rules in rules.
func bashSpecs(rules []string) []string {
	var specs []string
	for _, rule := range rules {
		if spec, ok := strings.CutPrefix(rule, "Bash("); ok && strings.HasSuffix(spec, ")") {
			specs = append(specs, strings.TrimSuffix(spec, ")"))
		}
	}
	return specs
}

func bashCommand(input json.RawMessage) (string, bool) {
	var in struct {
		Command string `json:"command"`
	}
	err := json.Unmarshal(input, &in)
	return in.Command, err == nil
}

// matchRule matches one rule that is not a Bash(spec) rule (Permits and
// Denies take those per command part).
func matchRule(rule, tool string, input json.RawMessage) bool {
	name, spec, hasSpec := strings.Cut(rule, "(")
	if !hasSpec {
		return name == tool || (strings.HasPrefix(name, "mcp__") && strings.HasPrefix(tool, name+"__"))
	}
	if name != tool || tool != "WebFetch" || !strings.HasSuffix(spec, ")") {
		return false
	}
	var in struct {
		URL string `json:"url"`
	}
	if json.Unmarshal(input, &in) != nil {
		return false
	}
	host, ok := strings.CutPrefix(strings.TrimSuffix(spec, ")"), "domain:")
	if !ok {
		return globMatch(strings.TrimSuffix(spec, ")"), in.URL)
	}
	u, err := url.Parse(in.URL)
	if err != nil || u.Hostname() == "" {
		return false
	}
	h := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if suffix, wild := strings.CutPrefix(host, "*."); wild {
		return strings.HasSuffix(h, "."+strings.ToLower(suffix))
	}
	return h == strings.ToLower(host)
}

func matchCommand(spec, cmd string) bool {
	if isGlob(spec) {
		return globMatch(spec, strings.Join(commandWords(cmd), " "))
	}
	if prefix, ok := strings.CutSuffix(spec, ":*"); ok {
		rest, ok := strings.CutPrefix(cmd, prefix)
		return ok && (rest == "" || rest[0] == ' ' || rest[0] == '\t')
	}
	return cmd == spec
}

// isGlob reports a Bash spec with a * other than the :* suffix of a prefix
// rule. Its * matches any text; it is matched against the command's words
// (commandWords, so quotes cannot split what it names) joined by blanks.
func isGlob(spec string) bool {
	return strings.Contains(strings.TrimSuffix(spec, ":*"), "*")
}

// globMatch matches s against pattern, whose * matches any text.
func globMatch(pattern, s string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return s == pattern
	}
	rest, ok := strings.CutPrefix(s, parts[0])
	if !ok {
		return false
	}
	for _, p := range parts[1 : len(parts)-1] {
		i := strings.Index(rest, p)
		if i < 0 {
			return false
		}
		rest = rest[i+len(p):]
	}
	return strings.HasSuffix(rest, parts[len(parts)-1])
}

// splitCommand splits a shell command into the parts joined by |, ||, && and
// ;, honouring quotes, and drops the harmless redirections (harmlessRedirect)
// that start a word. It refuses (ok false) anything whose meaning depends on
// more than the words: other redirections, $ and backticks outside single
// quotes, subshells and groups, a lone &, newlines and unterminated quotes.
func splitCommand(s string) (parts []string, ok bool) {
	var cur strings.Builder
	flush := func() bool {
		p := strings.TrimSpace(cur.String())
		cur.Reset()
		if p == "" {
			return false
		}
		parts = append(parts, p)
		return true
	}
	wordStart := true
	for i := 0; i < len(s); i++ {
		if wordStart {
			if n := harmlessRedirect(s[i:]); n > 0 {
				i += n - 1
				continue
			}
		}
		c := s[i]
		wordStart = false
		switch c {
		case '\'':
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				return nil, false
			}
			cur.WriteString(s[i : i+j+2])
			i += j + 1
		case '"':
			j := i + 1
			for ; j < len(s) && s[j] != '"'; j++ {
				switch s[j] {
				case '$', '`', '\n', '\r':
					return nil, false
				case '\\':
					j++
				}
			}
			if j >= len(s) {
				return nil, false
			}
			cur.WriteString(s[i : j+1])
			i = j
		case '\\':
			if i+1 >= len(s) || s[i+1] == '\n' {
				return nil, false
			}
			cur.WriteString(s[i : i+2])
			i++
		case '|', '&', ';':
			double := i+1 < len(s) && s[i+1] == c
			if c == '&' && !double {
				return nil, false
			}
			if double {
				if c == ';' {
					return nil, false
				}
				i++
			}
			if !flush() {
				return nil, false
			}
			wordStart = true
		case '$', '`', '<', '>', '(', ')', '{', '}', '\n', '\r':
			return nil, false
		default:
			cur.WriteByte(c)
			wordStart = c == ' ' || c == '\t'
		}
	}
	if !flush() {
		return nil, false
	}
	return parts, true
}

// harmlessRedirect returns the length of the redirection s starts with when
// it only discards output or merges stdout and stderr (2>&1, 1>&2, >&2, or
// >, 1>, 2>, &> to /dev/null, optionally after blanks) and ends a word; 0
// for anything else, which leaves the command unsplittable.
func harmlessRedirect(s string) int {
	ends := func(n int) bool { return n == len(s) || strings.IndexByte(" \t|;&", s[n]) >= 0 }
	for _, dup := range []string{"2>&1", "1>&2", ">&2"} {
		if strings.HasPrefix(s, dup) && ends(len(dup)) {
			return len(dup)
		}
	}
	for _, op := range []string{">", "1>", "2>", "&>"} {
		if rest, ok := strings.CutPrefix(s, op); ok {
			target := strings.TrimLeft(rest, " \t")
			if n := len(s) - len(target) + len("/dev/null"); strings.HasPrefix(target, "/dev/null") && ends(n) {
				return n
			}
		}
	}
	return 0
}

// commandWords splits a command for the deny scan of one the hook cannot
// split: line continuations, quotes and backslashes are dropped (so c"ur"l
// and c\url read as curl), and blanks and shell operator characters end a
// word. Quoted text splits into words too, which errs towards a deny.
func commandWords(cmd string) []string {
	cmd = strings.NewReplacer("\\\n", "", `'`, "", `"`, "", `\`, "").Replace(cmd)
	return strings.FieldsFunc(cmd, func(r rune) bool {
		return unicode.IsSpace(r) || strings.ContainsRune("|&;<>()`${}", r)
	})
}

// containsWords reports whether seq appears as consecutive words in words.
func containsWords(words, seq []string) bool {
	for i := 0; i+len(seq) <= len(words); i++ {
		if slices.Equal(words[i:i+len(seq)], seq) {
			return true
		}
	}
	return false
}

// Environment the launcher sets for the run; the hook and the peer client
// commands the run calls read it. The token never appears in the prompt.
const (
	EnvRunToken     = "PEER_RUN_TOKEN"
	EnvRequestID    = "PEER_REQUEST_ID"
	EnvAttempt      = "PEER_ATTEMPT"
	EnvInstance     = "PEER_INSTANCE"
	EnvParkFile     = "PEER_PARK_FILE"
	EnvRunRules     = "PEER_RUN_RULES"
	EnvApprovedStep = "PEER_APPROVED_STEP"
	// EnvRequestSender is the host that sent the run's request; a request
	// from UntrustedSender parks on every call outside the allow list.
	EnvRequestSender = "PEER_REQUEST_SENDER"
	// EnvRequestParent is the request whose run sent this run's request,
	// empty for a top-level request; a child run may not send requests.
	EnvRequestParent = "PEER_REQUEST_PARENT"
	// EnvParkObserve is the canary's mode: the hook records but reports
	// nothing to the hub; only the first recorded park is denied, so later
	// calls reach the auto-mode classifier, and a classifier denial is
	// recorded beside the park file (DeniedFile).
	EnvParkObserve = "PEER_PARK_OBSERVE"
)

// UntrustedSender is the host whose requests park on every call outside the
// allow list, without the classifier (R6): Home Assistant handles the most
// untrusted input.
const UntrustedSender = "homeassistant"

// Park kinds (PeerPark.kind).
const (
	ParkStep  = "step"
	ParkLimit = "limit"
)

// maxParkReason is the hub's limit on a park's reason, in runes.
const maxParkReason = 300

// ParkRecord is the step a run parked on. A limit park (Kind ParkLimit) has
// no call.
type ParkRecord struct {
	Kind   string          `json:"kind,omitempty"` // "" is ParkStep
	Tool   string          `json:"tool,omitempty"`
	Input  json.RawMessage `json:"input,omitempty"`
	Hash   string          `json:"hash,omitempty"`
	Reason string          `json:"reason,omitempty"` // the classifier's, one line
	At     time.Time       `json:"at"`
}

// DeniedFile is where the canary's PermissionDenied hook records (observe
// mode), so its record does not lose to the PreToolUse one.
func DeniedFile(parkFile string) string { return parkFile + ".denied" }

// Step is the record as one line of text for the hub and the operator (its
// StepText); "" for a limit park.
func (p ParkRecord) Step() string {
	if p.Tool == "" {
		return ""
	}
	return StepText(p.Tool, p.Input)
}

// stepHashPrefix leads every StepHash; the hub takes the bare hex digest.
const stepHashPrefix = "sha256:"

// maxStepRunes is the hub's limit on a step park's text, in runes. A longer
// call is never parked: its text would have to be cut, and the operator
// would approve a call they did not fully see.
const maxStepRunes = 8192

// StepText is a call as the operator sees it and approves it: the tool name,
// a space and the canonical (sorted keys) input. For Bash only the
// command counts: the model rewrites the description and timeout fields
// freely, so the re-run's call would otherwise never match.
func StepText(tool string, canonicalInput []byte) string {
	if tool == "Bash" {
		var in map[string]any
		dec := json.NewDecoder(bytes.NewReader(canonicalInput))
		dec.UseNumber()
		if dec.Decode(&in) == nil {
			delete(in, "description")
			delete(in, "timeout")
			if b, err := json.Marshal(in); err == nil {
				if c, err := canonicalJSON(b); err == nil {
					canonicalInput = c
				}
			}
		}
	}
	return tool + " " + string(canonicalInput)
}

// StepHash names a call for approval: the SHA-256 of its StepText, the same
// hash the hub derives from the step text it stores (prefixed here).
func StepHash(tool string, canonicalInput []byte) string {
	sum := sha256.Sum256([]byte(StepText(tool, canonicalInput)))
	return stepHashPrefix + hex.EncodeToString(sum[:])
}

// Decision is the hook's answer to Claude Code. Permission "" leaves the call
// to the CLI's own rules.
type Decision struct {
	Permission string // "", "allow" or "deny"
	Reason     string
}

// Emit writes the decision in the PreToolUse output schema Claude Code 2.1.312
// reads (hookSpecificOutput.permissionDecision) and returns the exit code. A
// deny that cannot be written falls back to exit 2, which also blocks.
func (d Decision) Emit(stdout, stderr io.Writer) int {
	if d.Permission == "" {
		return 0
	}
	out, _ := json.Marshal(map[string]any{"hookSpecificOutput": map[string]string{
		"hookEventName":            "PreToolUse",
		"permissionDecision":       d.Permission,
		"permissionDecisionReason": d.Reason,
	}})
	if _, err := stdout.Write(append(out, '\n')); err != nil && d.Permission == "deny" {
		fmt.Fprintln(stderr, d.Reason)
		return 2
	}
	return 0
}

// Park is the PreToolUse hook (`peer park`): stdin is Claude Code's hook
// input, env the run's environment (os.Getenv). In order:
//
//  1. a call a Deny rule matches (the hard-deny floor included) is denied
//     without a park: no approval could run it, so the run is told to do
//     without it;
//  2. the one call matching the approved step hash is allowed once;
//  3. a call the allow list permits is allowed;
//  4. in a request UntrustedSender sent, any other call is parked: recorded
//     to the park file (the first park wins), reported to the hub when hub
//     is set, and denied;
//  5. otherwise the hook gives no decision, and auto mode's classifier
//     judges the call under the host's policy (a block parks through
//     ParkDenied).
//
// Every failure path denies.
func Park(ctx context.Context, stdin io.Reader, env func(string) string, hub HubRunAPI) Decision {
	call, err := readHookInput(stdin)
	if err != nil {
		return deny("peer park: unreadable hook input; the call is blocked")
	}
	var rules Rules
	if json.Unmarshal([]byte(env(EnvRunRules)), &rules) != nil {
		return deny("peer park: the run has no rule list; every call is blocked")
	}
	if rules.Denies(call.ToolName, call.ToolInput) {
		return deny("This command is always blocked on this host (its deny list); operator approval cannot allow it, so the request was not parked. Do without it: do not retry it or a variant of it; finish another way or report that it cannot be done here.")
	}

	parkFile := env(EnvParkFile)
	if approved := env(EnvApprovedStep); approved != "" && parkFile != "" {
		if rec, err := newParkRecord(env, call); err == nil && rec.Hash == approved {
			if f, cerr := os.OpenFile(parkFile+".approved", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600); cerr == nil {
				f.Close()
				return Decision{Permission: "allow", Reason: "operator approved this step"}
			}
		}
	}
	if rules.Permits(call.ToolName, call.ToolInput) {
		return Decision{Permission: "allow", Reason: "on this host's allow list"}
	}
	if env(EnvRequestSender) != UntrustedSender {
		return Decision{}
	}

	rec, _ := newParkRecord(env, call)
	if rec.tooLong() {
		return deny(fmt.Sprintf("This call is too long to park for operator approval (over %d characters as text). Split it into smaller calls and make those instead.", maxStepRunes))
	}
	won := recordAndReport(ctx, env, hub, parkFile, rec)
	if env(EnvParkObserve) == "1" {
		if !won {
			return Decision{}
		}
		// The canary's first call: the run must go on to its second call,
		// so the real park message (which tells the run to stop) is wrong here.
		return deny("This call is denied for this permissions self-test. Do not retry it; go on to the next call.")
	}
	return deny("This step needs operator approval, so the request is parked and this run ends now. Do not retry or work around it; stop. The run resumes here after the operator decides.")
}

// ParkDenied is the PermissionDenied hook (`peer park --denied`): auto mode's
// classifier blocked a call. It records the park the way Park does, with
// the classifier's reason on one line, and writes nothing, so Claude Code
// does not retry the call; the listener stops the run once the park file
// appears. In observe mode (the canary) it records to DeniedFile instead.
func ParkDenied(ctx context.Context, stdin io.Reader, env func(string) string, hub HubRunAPI) error {
	call, err := readHookInput(stdin)
	if err != nil {
		return fmt.Errorf("peer park --denied: unreadable hook input: %w", err)
	}
	rec, _ := newParkRecord(env, call)
	if rec.tooLong() {
		fmt.Fprintln(os.Stderr, "peer park --denied: the call is too long to park; the classifier's denial stands")
		return nil
	}
	rec.Reason = oneLine(call.Reason)
	parkFile := env(EnvParkFile)
	if env(EnvParkObserve) == "1" && parkFile != "" {
		parkFile = DeniedFile(parkFile)
	}
	recordAndReport(ctx, env, hub, parkFile, rec)
	return nil
}

// hookInput is the part of a PreToolUse or PermissionDenied hook's input the
// hooks read.
type hookInput struct {
	ToolName  string          `json:"tool_name"`
	ToolInput json.RawMessage `json:"tool_input"`
	Reason    string          `json:"reason"` // PermissionDenied only
}

func readHookInput(stdin io.Reader) (hookInput, error) {
	var call hookInput
	raw, err := io.ReadAll(io.LimitReader(stdin, 4<<20))
	if err == nil {
		err = json.Unmarshal(raw, &call)
	}
	if err == nil && call.ToolName == "" {
		err = errors.New("no tool_name")
	}
	if len(call.ToolInput) == 0 {
		call.ToolInput = json.RawMessage("{}")
	}
	return call, err
}

// newParkRecord is the call as a step park, its input canonical; err is set
// (and the input withheld) when it could not be canonicalised.
func newParkRecord(_ func(string) string, call hookInput) (ParkRecord, error) {
	input, err := canonicalJSON(call.ToolInput)
	if err != nil {
		input, _ = json.Marshal("[input withheld: " + err.Error() + "]")
	}
	return ParkRecord{Tool: call.ToolName, Input: input, Hash: StepHash(call.ToolName, input), At: time.Now().UTC()}, err
}

// tooLong reports whether rec's step text is over the hub's limit.
func (p ParkRecord) tooLong() bool { return utf8.RuneCountInString(p.Step()) > maxStepRunes }

// recordAndReport records rec to parkFile (the first park wins) and, when
// it won and the run is not the canary, reports it to the hub with the run
// time so far. It reports whether rec won.
func recordAndReport(ctx context.Context, env func(string) string, hub HubRunAPI, parkFile string, rec ParkRecord) bool {
	won := false
	if parkFile != "" {
		won, _ = recordPark(parkFile, rec)
	}
	if !won || hub == nil || env(EnvParkObserve) == "1" { // the canary has no request on the hub
		return won
	}
	// Inside Claude Code's 30 s hook timeout; the park file already decides
	// the outcome if the hub is slow. The run's cost and time are not
	// reported here: the listener's park report, once the run stopped,
	// adds them to the parked request (reporting time here too would count
	// it twice).
	rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ref, _ := RunRefFromEnv(env)
	p := ParkRequest{RunRef: ref, Kind: ParkStep, Tool: rec.Tool, Step: rec.Step(), Hash: rec.Hash, Reason: rec.Reason}
	if err := hub.Park(rctx, p); err != nil {
		fmt.Fprintln(os.Stderr, "peer park: reporting to the hub:", err)
	}
	return won
}

// oneLine collapses s's whitespace runs, newlines included, to single spaces
// and cuts it to the hub's reason limit.
func oneLine(s string) string {
	return truncRunes(strings.Join(strings.Fields(s), " "), maxParkReason)
}

func deny(reason string) Decision { return Decision{Permission: "deny", Reason: reason} }

// recordPark writes rec to path unless a park is already recorded: written to
// a temp file and hard-linked into place, so the first park wins atomically.
func recordPark(path string, rec ParkRecord) (bool, error) {
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false) // keep Input byte for byte what was hashed
	if err := enc.Encode(rec); err != nil {
		return false, err
	}
	data := []byte(buf.String())
	tmp, err := writeTemp(filepath.Dir(path), ".park-*", data)
	if err != nil {
		return false, err
	}
	defer os.Remove(tmp)
	if err := os.Link(tmp, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// ReadPark returns the recorded park, or nil when none was recorded.
func ReadPark(path string) (*ParkRecord, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var rec ParkRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

// canonicalJSON re-encodes raw with sorted keys and no HTML escaping.
func canonicalJSON(raw json.RawMessage) (json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return json.RawMessage(strings.TrimSuffix(b.String(), "\n")), nil
}
