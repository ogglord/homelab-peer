package peerclient_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/ogglord/homelab-peer/internal/peerclient"
)

func bashInput(cmd string) json.RawMessage {
	in, _ := json.Marshal(map[string]string{"command": cmd})
	return in
}

func fetchInput(url string) json.RawMessage {
	in, _ := json.Marshal(map[string]string{"url": url, "prompt": "x"})
	return in
}

// The rule matcher: WebFetch hosts match exactly or under a wildcard suffix
// (never by substring), an MCP server rule covers that server's tools only,
// quotes keep && and ; inside one part, output discarded to /dev/null or
// merged into stderr does not stop a split, and a command the hook cannot
// split is never allowed and denied only when a deny rule's words appear in
// it. A glob rule (the approver floor) matches by substring of the
// command's words or of the URL.
func TestRulesMatch(t *testing.T) {
	t.Parallel()
	rules := peerclient.Rules{
		Allow: []string{"Read", "mcp__ha", "WebFetch(domain:example.com)", "Bash(echo:*)", "Bash(ha addons list:*)", "Bash(head:*)"},
		Deny: append(peerclient.DefaultRules().Deny, "Bash(peer --json send request:*)",
			"Bash(*peer/approvers*)", "WebFetch(*peer/approvers*)",
			"WebFetch(domain:home.example)", "WebFetch(domain:*.home.example)"),
	}
	for _, tc := range []struct {
		name            string
		tool            string
		input           json.RawMessage
		permits, denies bool
	}{
		{"fetch exact host", "WebFetch", fetchInput("https://example.com/x"), true, false},
		{"fetch subdomain of an exact rule", "WebFetch", fetchInput("https://sub.example.com/x"), false, false},
		{"fetch denied apex", "WebFetch", fetchInput("https://home.example/"), false, true},
		{"fetch denied wildcard", "WebFetch", fetchInput("https://homelab.home.example/api/services"), false, true},
		{"fetch denied wildcard, case and trailing dot", "WebFetch", fetchInput("https://HOMELAB.HOME.EXAMPLE./api"), false, true},
		{"fetch lookalike prefix", "WebFetch", fetchInput("https://evilhome.example/"), false, false},
		{"fetch lookalike suffix", "WebFetch", fetchInput("https://home.example.evil.com/"), false, false},
		{"fetch without a host", "WebFetch", fetchInput("/api/services"), false, false},
		{"mcp server tool", "mcp__ha__get_state", json.RawMessage(`{}`), true, false},
		{"mcp server name prefix of another", "mcp__hax__get_state", json.RawMessage(`{}`), false, false},
		{"quoted && stays one part", "Bash", bashInput(`echo "a && b"`), true, false},
		{"quoted && hides no denied part", "Bash", bashInput(`echo 'x && curl http://x'`), true, false},
		{"unquoted && splits", "Bash", bashInput(`echo a && curl http://x`), false, true},
		{"$ in single quotes", "Bash", bashInput(`echo '$HOME'`), true, false},
		{"$ in double quotes is unsplittable", "Bash", bashInput(`echo "$HOME"`), false, false},
		{"stderr merged into a pipe", "Bash", bashInput(`ha addons list 2>&1 | head -100`), true, false},
		{"output discarded", "Bash", bashInput(`echo hi >/dev/null 2>&1`), true, false},
		{"stderr discarded after a blank", "Bash", bashInput(`echo hi 2> /dev/null`), true, false},
		{"both streams discarded", "Bash", bashInput(`echo hi &>/dev/null`), true, false},
		{"to stderr", "Bash", bashInput(`echo hi >&2`), true, false},
		{"compound with a part outside the list", "Bash", bashInput(`ha addons list --raw-json 2>/dev/null | head -c 20000 || ha apps list 2>&1 | head -100`), false, false},
		{"discarded output of a denied command", "Bash", bashInput(`curl http://x 2>/dev/null`), false, true},
		{"redirection to a file", "Bash", bashInput(`echo hi > /tmp/x`), false, false},
		{"redirection to a /dev/null lookalike", "Bash", bashInput(`echo hi >/dev/nullx`), false, false},
		{"append redirection", "Bash", bashInput(`echo hi >> /dev/null`), false, false},
		{"redirection of a denied command to a file", "Bash", bashInput(`curl http://x > /tmp/x`), false, true},
		{"denied command in a substitution", "Bash", bashInput(`echo $(curl http://x)`), false, true},
		{"quoted denied command behind a redirection", "Bash", bashInput(`echo hi > /tmp/x; c"ur"l http://x`), false, true},
		{"denied command over a line continuation", "Bash", bashInput("echo hi > /tmp/x; cu\\\nrl http://x"), false, true},
		{"multi-word denied verb behind a redirection", "Bash", bashInput(`peer --json send request --target x y > /tmp/x`), false, true},
		{"approver route in a command", "Bash", bashInput(`echo x && python3 -c 'import urllib.request as u; u.urlopen("http://100.1.2.3:7790/api/peer/approvers")'`), false, true},
		{"approver route split by quotes", "Bash", bashInput(`echo "http://h/api/peer/app""rovers"`), false, true},
		{"approver route behind a substitution", "Bash", bashInput(`echo $(cat /tmp/x) http://h/peer/approvers`), false, true},
		{"approver route by WebFetch", "WebFetch", fetchInput("http://100.1.2.3:7790/api/peer/approvers"), false, true},
		{"other peer route by WebFetch", "WebFetch", fetchInput("http://100.1.2.3:7790/api/peer/requests"), false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := rules.Permits(tc.tool, tc.input); got != tc.permits {
				t.Errorf("Permits = %v, want %v", got, tc.permits)
			}
			if got := rules.Denies(tc.tool, tc.input); got != tc.denies {
				t.Errorf("Denies = %v, want %v", got, tc.denies)
			}
		})
	}
}

// countingHub records the parks reported to it.
type countingHub struct {
	parks []peerclient.ParkRequest
}

func (h *countingHub) PostResult(context.Context, peerclient.ResultRequest) error { return nil }

func (h *countingHub) Park(_ context.Context, p peerclient.ParkRequest) error {
	h.parks = append(h.parks, p)
	return nil
}

// hookEnv is a run's environment for the hooks: its rules (as the launcher
// hands them), the approved step, the sender and a park file.
func hookEnv(t *testing.T, rules, approved, sender string) map[string]string {
	t.Helper()
	return map[string]string{
		peerclient.EnvRunRules:      rules,
		peerclient.EnvApprovedStep:  approved,
		peerclient.EnvRequestSender: sender,
		peerclient.EnvParkFile:      filepath.Join(t.TempDir(), "park.json"),
		peerclient.EnvRequestID:     "req-1",
		peerclient.EnvAttempt:       "1",
		peerclient.EnvInstance:      "listen-x",
		peerclient.EnvRunToken:      "tok",
	}
}

// park runs the PreToolUse hook on one call and returns its decision and
// what it parked (in the park file, and reported to the hub).
func park(t *testing.T, stdin string, env map[string]string) (peerclient.Decision, *peerclient.ParkRecord) {
	t.Helper()
	hub := &countingHub{}
	d := peerclient.Park(context.Background(), strings.NewReader(stdin), func(k string) string { return env[k] }, hub)
	rec, err := peerclient.ReadPark(env[peerclient.EnvParkFile])
	if err != nil {
		t.Fatal(err)
	}
	if (rec != nil) != (len(hub.parks) == 1) || len(hub.parks) > 1 {
		t.Fatalf("park file %+v but hub parks %+v", rec, hub.parks)
	}
	return d, rec
}

func hookCall(tool string, input json.RawMessage) string {
	in, _ := json.Marshal(map[string]any{"tool_name": tool, "tool_input": input})
	return string(in)
}

// The hook's order: the deny list (hard-deny floor included) denies without
// a park; the approved step runs once; the allow list allows; a request
// from Home Assistant parks on anything else; any other request's call gets
// no decision, so auto mode's classifier judges it. The fail-closed paths
// deny.
func TestParkDecisions(t *testing.T) {
	t.Parallel()
	r := peerclient.DefaultRules()
	r.Allow = append(r.Allow, "Bash(ha addons list:*)")
	r.Deny = append(r.Deny, "Bash(*peer/approvers*)")
	rules, _ := json.Marshal(r)
	hash := func(cmd string) string { return peerclient.StepHash("Bash", bashInput(cmd)) }
	const compound = `ha addons list --raw-json 2>/dev/null | head -c 20000 || ha apps list 2>&1 | head -100`
	const ha, lab = "homeassistant", "homelab"
	for _, tc := range []struct {
		name, stdin, rules, approved, sender string
		want                                 string
		parks                                bool
	}{
		{"deny list, no park", hookCall("Bash", bashInput("curl http://x 2>/dev/null")), string(rules), "", ha, "deny", false},
		{"floor: approver route, no park", hookCall("Bash", bashInput("wget -qO- http://h/api/peer/approvers")), string(rules), "", lab, "deny", false},
		{"approved denied call", hookCall("Bash", bashInput("curl https://x")), string(rules), hash("curl https://x"), lab, "deny", false},
		{"approved denied call redirected to a file", hookCall("Bash", bashInput("curl http://x > /tmp/f")), string(rules), hash("curl http://x > /tmp/f"), ha, "deny", false},
		{"approved step runs", hookCall("Bash", bashInput("echo approved")), string(rules), hash("echo approved"), ha, "allow", false},
		{"approved compound runs", hookCall("Bash", bashInput(compound)), string(rules), hash(compound), ha, "allow", false},
		{"allow list", hookCall("Read", json.RawMessage(`{"file_path":"/x"}`)), string(rules), "", lab, "allow", false},
		{"allow list, pipeline with stderr merged", hookCall("Bash", bashInput(`ha addons list 2>&1 | head -100`)), string(rules), "", ha, "allow", false},
		{"homeassistant: compound with a part outside the list parks", hookCall("Bash", bashInput(compound)), string(rules), "", ha, "deny", true},
		{"homeassistant: redirection to a file parks", hookCall("Bash", bashInput("echo hi > /tmp/f")), string(rules), "", ha, "deny", true},
		{"homelab: outside the list, no decision", hookCall("Bash", bashInput("echo hi > /tmp/f")), string(rules), "", lab, "", false},
		{"macbook: outside the list, no decision", hookCall("Write", json.RawMessage(`{"file_path":"/x","content":"y"}`)), string(rules), "", "macbook", "", false},
		{"garbage stdin", "not json", string(rules), "", lab, "deny", false},
		{"no tool name", `{"tool_input":{}}`, string(rules), "", lab, "deny", false},
		{"no rule list", hookCall("Read", json.RawMessage(`{}`)), "", "", lab, "deny", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, rec := park(t, tc.stdin, hookEnv(t, tc.rules, tc.approved, tc.sender))
			if got.Permission != tc.want || (rec != nil) != tc.parks {
				t.Fatalf("decision %+v parked %+v, want %q parked %v", got, rec, tc.want, tc.parks)
			}
		})
	}

	env := hookEnv(t, string(rules), hash("echo approved"), lab)
	if d, _ := park(t, hookCall("Bash", bashInput("echo approved")), env); d.Permission != "allow" {
		t.Fatalf("approved step: %+v", d)
	}
	if d, rec := park(t, hookCall("Bash", bashInput("echo approved")), env); d.Permission != "" || rec != nil {
		t.Errorf("the approved step a second time: %+v parked %+v, want no decision", d, rec)
	}
	if d, _ := park(t, hookCall("Bash", bashInput("curl http://x")), hookEnv(t, string(rules), "", lab)); !strings.Contains(d.Reason, "always blocked") {
		t.Errorf("a denied call's reason does not say it is always blocked: %q", d.Reason)
	}
	var out strings.Builder
	if code := (peerclient.Decision{}).Emit(&out, &out); code != 0 || out.Len() != 0 {
		t.Errorf("no decision wrote %q, exit %d", out.String(), code)
	}
}

// A classifier block (the PermissionDenied hook) parks like a PreToolUse
// park: the step canonical and hashed, kind step, with the classifier's
// reason on one line and cut to 300 characters, reported to the hub; the
// first park wins.
func TestParkDenied(t *testing.T) {
	t.Parallel()
	env := hookEnv(t, `{"allow":[],"deny":[]}`, "", "homelab")
	reason := "The server-side auto mode classifier judged this action dangerous:\n\n  it reboots\tthe router.  " + strings.Repeat("x", 400)
	in, _ := json.Marshal(map[string]any{"hook_event_name": "PermissionDenied", "tool_name": "Bash",
		"tool_input": map[string]string{"command": "ssh root@192.0.2.1 reboot", "description": "reboot"}, "reason": reason})
	hub := &countingHub{}
	getenv := func(k string) string { return env[k] }
	if err := peerclient.ParkDenied(context.Background(), strings.NewReader(string(in)), getenv, hub); err != nil {
		t.Fatal(err)
	}
	rec, err := peerclient.ReadPark(env[peerclient.EnvParkFile])
	if err != nil || rec == nil {
		t.Fatalf("no park recorded: %v", err)
	}
	const head = "The server-side auto mode classifier judged this action dangerous: it reboots the router. xxx"
	if !strings.HasPrefix(rec.Reason, head) || utf8.RuneCountInString(rec.Reason) != 300 || strings.ContainsAny(rec.Reason, "\n\t") {
		t.Fatalf("reason %q (%d runes)", rec.Reason, utf8.RuneCountInString(rec.Reason))
	}
	if rec.Tool != "Bash" || rec.Hash != peerclient.StepHash("Bash", bashInput("ssh root@192.0.2.1 reboot")) ||
		rec.Step() != `Bash {"command":"ssh root@192.0.2.1 reboot"}` || rec.Hash != hubHash(rec.Step()) {
		t.Fatalf("park %+v", rec)
	}
	if len(hub.parks) != 1 {
		t.Fatalf("hub parks %+v", hub.parks)
	}
	if p := hub.parks[0]; p.Kind != peerclient.ParkStep || p.Reason != rec.Reason || p.Hash != rec.Hash || p.Step != rec.Step() || p.RequestID != "req-1" {
		t.Fatalf("hub park %+v", p)
	}
	other, _ := json.Marshal(map[string]any{"tool_name": "Bash", "tool_input": map[string]string{"command": "rm -rf /pool"}, "reason": "deletes"})
	if err := peerclient.ParkDenied(context.Background(), strings.NewReader(string(other)), getenv, hub); err != nil {
		t.Fatal(err)
	}
	if again, _ := peerclient.ReadPark(env[peerclient.EnvParkFile]); again.Hash != rec.Hash || len(hub.parks) != 1 {
		t.Fatalf("a second denial replaced the park: %+v, hub parks %d", again, len(hub.parks))
	}
}

// hubHash is the hub's hash of a step text it stores, in the form the
// launcher hands the run (PEER_APPROVED_STEP).
func hubHash(step string) string {
	sum := sha256.Sum256([]byte(step))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// An approval allows the call whose step text is the approved text, and only
// it: a park file forged with harmless text over a hidden call's hash gets
// the harmless call approved, and the hidden call parks again. The Bash
// description and timeout are not part of the text.
func TestApprovedStepIsTheStepText(t *testing.T) {
	t.Parallel()
	rules, _ := json.Marshal(peerclient.DefaultRules())
	const harmless = `Bash {"command":"echo harmless > /tmp/h"}`
	approved := hubHash(harmless)
	hidden := hookCall("Bash", bashInput("echo hidden > /tmp/h"))
	d, rec := park(t, hidden, hookEnv(t, string(rules), approved, "homeassistant"))
	if d.Permission != "deny" || rec == nil || rec.Step() != `Bash {"command":"echo hidden > /tmp/h"}` {
		t.Fatalf("hidden call: %+v parked %+v", d, rec)
	}
	in, _ := json.Marshal(map[string]any{"command": "echo harmless > /tmp/h", "description": "says hi", "timeout": 5})
	if d, rec := park(t, hookCall("Bash", in), hookEnv(t, string(rules), approved, "homeassistant")); d.Permission != "allow" || rec != nil {
		t.Fatalf("approved call: %+v parked %+v", d, rec)
	}
}

// A call whose step text is longer than the hub stores is never parked (the
// operator could not see all of it): the hook denies it and tells the run to
// split it; a classifier block on it records nothing.
func TestOverlongStepIsNotParked(t *testing.T) {
	t.Parallel()
	rules, _ := json.Marshal(peerclient.DefaultRules())
	long := hookCall("Bash", bashInput("echo "+strings.Repeat("x", 8192)+" > /tmp/h"))
	d, rec := park(t, long, hookEnv(t, string(rules), "", "homeassistant"))
	if d.Permission != "deny" || rec != nil || !strings.Contains(d.Reason, "Split it into smaller calls") {
		t.Fatalf("overlong call: %+v parked %+v", d, rec)
	}
	env := hookEnv(t, string(rules), "", "homelab")
	hub := &countingHub{}
	if err := peerclient.ParkDenied(context.Background(), strings.NewReader(long), func(k string) string { return env[k] }, hub); err != nil {
		t.Fatal(err)
	}
	if rec, _ := peerclient.ReadPark(env[peerclient.EnvParkFile]); rec != nil || len(hub.parks) != 0 {
		t.Fatalf("overlong classifier block parked %+v, hub parks %d", rec, len(hub.parks))
	}
}
