package main

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/ogglord/homelab-peer/internal/peerclient"
)

// The default policy parses, keeps Claude Code's defaults in every list,
// and holds the rules an unattended run must not break.
func TestDefaultPolicy(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, peerclient.DefaultPolicyFile(), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := peerclient.LoadPolicy(path)
	if err != nil {
		t.Fatal(err)
	}
	for name, l := range map[string][]string{"environment": p.Environment, "allow": p.Allow, "hard_deny": p.HardDeny} {
		if !slices.Contains(l, "$defaults") {
			t.Errorf("%s lacks $defaults", name)
		}
	}
	all := strings.Join(p.HardDeny, "\n")
	for _, want := range []string{"Deleting", "SSH", "Rebooting", "secrets"} {
		if !strings.Contains(all, want) {
			t.Errorf("hard_deny lacks a rule on %q", want)
		}
	}
}

// init writes the default once and keeps an edited file unless --force;
// show prints it; default prints the embedded policy.
func TestPolicyCommands(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	path := filepath.Join(home, ".config", "peer", "policy.json")

	if r := peerCmd("", "policy", "show"); r.code == 0 || !strings.Contains(r.stderr, "peer policy init") {
		t.Fatalf("show without a file: %d %q", r.code, r.stderr)
	}
	if r := peerCmd("", "policy", "init"); r.code != 0 || !strings.Contains(r.out, path) {
		t.Fatalf("init: %d %q %q", r.code, r.out, r.stderr)
	}
	if b, _ := os.ReadFile(path); string(b) != string(peerclient.DefaultPolicyFile()) {
		t.Fatal("init did not write the default")
	}
	edited := `{"environment": ["$defaults"], "allow": ["$defaults"], "hard_deny": ["$defaults"]}`
	if err := os.WriteFile(path, []byte(edited), 0o644); err != nil {
		t.Fatal(err)
	}
	if r := peerCmd("", "policy", "init"); r.code == 0 || !strings.Contains(r.stderr, "--force") {
		t.Fatalf("init over an edit: %d %q", r.code, r.stderr)
	}
	if r := peerCmd("", "policy", "show"); r.code != 0 || !strings.Contains(r.out, edited) {
		t.Fatalf("show: %d %q", r.code, r.out)
	}
	if r := peerCmd("", "policy", "init", "--force"); r.code != 0 {
		t.Fatalf("init --force: %d %q", r.code, r.stderr)
	}
	if r := peerCmd("", "policy", "default"); r.code != 0 || r.out != string(peerclient.DefaultPolicyFile()) {
		t.Fatalf("default: %d", r.code)
	}
	if err := os.WriteFile(path, []byte(`{"allow": [`), 0o644); err != nil {
		t.Fatal(err)
	}
	if r := peerCmd("", "policy", "show"); r.code == 0 {
		t.Fatal("show accepted a policy that does not parse")
	}
}

// service install without --policy-file runs the listener on the host's
// policy file; a dry run names it and writes nothing.
func TestServiceInstallUsesThePolicyFile(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("service install supports Linux and macOS")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	path := filepath.Join(home, ".config", "peer", "policy.json")
	r := peerCmd("", "--hub", "http://100.64.0.10:7790", "service", "install", "--dry-run", "--peer", "/bin/sh")
	if r.code != 0 || !strings.Contains(r.out, path) {
		t.Fatalf("dry run: %d %q %q", r.code, r.out, r.stderr)
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("a dry run wrote the policy")
	}
	r = peerCmd("", "--hub", "http://100.64.0.10:7790", "service", "install", "--dry-run", "--peer", "/bin/sh", "--policy-file", "/etc/peer.json")
	if strings.Contains(r.out, path) || !strings.Contains(r.out, "/etc/peer.json") {
		t.Fatalf("explicit policy file: %q", r.out)
	}
}
