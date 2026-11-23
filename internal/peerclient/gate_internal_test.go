package peerclient

import (
	"encoding/json"
	"slices"
	"testing"
)

// forRun keeps the hard-deny floor whatever the host's deny list: the
// approver routes always, the request verb only for a run whose request
// another run sent. A top-level run may send a request.
func TestForRunKeepsTheFloor(t *testing.T) {
	t.Parallel()
	custom := Rules{Allow: []string{"Read"}, Deny: []string{"Bash(rm:*)"}}
	cmd := func(c string) json.RawMessage { in, _ := json.Marshal(map[string]string{"command": c}); return in }
	url := func(u string) json.RawMessage { in, _ := json.Marshal(map[string]string{"url": u}); return in }
	for _, tc := range []struct {
		name  string
		child bool
		tool  string
		input json.RawMessage
		deny  bool
	}{
		{"top-level run sends a request", false, "Bash", cmd("peer send request --target homeassistant 'list add-ons'"), false},
		{"child run sends a request", true, "Bash", cmd("peer send request --target homeassistant 'list add-ons'"), true},
		{"child run sends one with --json", true, "Bash", cmd("peer --json send request --target macbook x"), true},
		{"top-level run reaches the approver route", false, "Bash", cmd("curl -X DELETE http://100.1.2.3:7790/api/peer/approvers"), true},
		{"child run fetches the approver route", true, "WebFetch", url("http://100.1.2.3:7790/peer/approvers"), true},
		{"the host's own deny rule", false, "Bash", cmd("rm -rf /tmp/x"), true},
		{"an ordinary command", false, "Bash", cmd("systemctl restart caddy"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := custom.forRun(tc.child).Denies(tc.tool, tc.input); got != tc.deny {
				t.Fatalf("Denies = %v, want %v", got, tc.deny)
			}
		})
	}
	if slices.Contains(DefaultRules().Deny, "Bash(peer send request:*)") {
		t.Error("the default deny list still blocks top-level requests")
	}
	if flags := custom.forRun(true).Flags(); slices.Contains(flags, "WebFetch(*peer/approvers*)") || !slices.Contains(flags, "Bash(*peer/approvers*)") {
		t.Errorf("flags %q: the hook-only WebFetch rule must stay out, the Bash glob in", flags)
	}
}

// The policy a run gets always hard-denies the approver actions; none set is
// the generic default.
func TestPolicyForRun(t *testing.T) {
	t.Parallel()
	if got := (Policy{}).forRun(); !slices.Equal(got.HardDeny, DefaultPolicy().HardDeny) || !slices.Equal(got.Allow, []string{"$defaults"}) {
		t.Fatalf("zero policy %+v", got)
	}
	p := Policy{Environment: []string{"$defaults", "This is the homelab host."}, HardDeny: []string{"$defaults", "Rebooting the router"}}
	if got := p.forRun(); !slices.Equal(got.HardDeny, []string{"$defaults", "Rebooting the router", approverHardDeny}) {
		t.Fatalf("hard_deny %q", got.HardDeny)
	}
}

// A request's session is a UUIDv5 of its id, and its transcript sits where
// Claude Code 2.1.323 put it in the spike: the cwd with every non-alphanumeric
// character turned into '-'.
func TestSessionAndTranscriptPath(t *testing.T) {
	t.Parallel()
	if got := SessionUUID("req-1"); got != "6379d2d3-e4c6-5cfc-98fc-1817ad4fa861" { // python3 uuid.uuid5
		t.Fatalf("SessionUUID = %s", got)
	}
	if SessionUUID("req-1") == SessionUUID("req-2") {
		t.Fatal("two requests share a session")
	}
	const cwd = "/tmp/claude-1000/-home-ogge-repos-homelab/43730b81-12cd-4ef5-a732-a6da1defc3c4/scratchpad/spike/work"
	const want = "/home/x/.claude/projects/-tmp-claude-1000--home-ogge-repos-homelab-43730b81-12cd-4ef5-a732-a6da1defc3c4-scratchpad-spike-work/u.jsonl"
	if got := TranscriptPath("/home/x/.claude", cwd, "u"); got != want {
		t.Fatalf("TranscriptPath =\n%s\nwant\n%s", got, want)
	}
	for _, tc := range []struct {
		environ []string
		want    string
	}{
		{[]string{"HOME=/h"}, "/h/.claude"},
		{[]string{"HOME=/h", "CLAUDE_CONFIG_DIR=/c"}, "/c"},
		{[]string{"HOME=/h", "HOME=/run/home"}, "/run/home/.claude"},
	} {
		if got := claudeConfigDir(tc.environ); got != tc.want {
			t.Errorf("claudeConfigDir(%q) = %s, want %s", tc.environ, got, tc.want)
		}
	}
}

// A request id names its runs directory entry, reversibly, and never as a
// dot name or a path.
func TestRunDirName(t *testing.T) {
	t.Parallel()
	for _, id := range []string{"req-1", "Ab3_x.y", "../etc", "a/b", ".canary", "-x", "é"} {
		name := runDirName(id)
		if runIDOf(name) != id || name == "" || name[0] == '.' || slices.Contains([]byte(name), '/') {
			t.Errorf("runDirName(%q) = %q, back %q", id, name, runIDOf(name))
		}
	}
	if runIDOf(canaryDirName) != "" {
		t.Error("the canary's worktree reads as a request")
	}
}
