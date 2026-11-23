package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func installFixture() installSettings {
	return installSettings{
		Peer: "/home/u/.nix-profile/bin/peer", Hub: "http://100.64.0.10:7790",
		Listen: []string{"--claude", "/home/u/.local/bin/claude", "--deny", "WebFetch(domain:example.com)", "--allow", "Bash(echo $HOME 100%)"},
		Path:   "/home/u/.nix-profile/bin:/run/current-system/sw/bin", Home: "/home/u", StateDir: "/home/u/.local/state/homelab-peer",
	}
}

// The unit runs the profile's peer and watches the same path, restarts
// except when superseded (exit 3), and escapes what systemd would expand.
func TestSystemdUnit(t *testing.T) {
	t.Parallel()
	u := systemdUnit(installFixture())
	for _, want := range []string{
		`ExecStart="/home/u/.nix-profile/bin/peer" "--hub" "http://100.64.0.10:7790" "listen" "--restart-on-upgrade" "/home/u/.nix-profile/bin/peer" "--claude" "/home/u/.local/bin/claude"`,
		`"--allow" "Bash(echo $$HOME 100%%)"`,
		`Environment="PEER_HUB_URL=http://100.64.0.10:7790"`,
		"StateDirectory=homelab-peer\n",
		"Restart=always\n", "RestartPreventExitStatus=3\n", "WantedBy=default.target\n",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("unit lacks %q:\n%s", want, u)
		}
	}
}

// The agent runs the supervisor in the foreground (restarted by launchd only
// after a failure), with runs off unless --claude was given.
func TestLaunchdAgent(t *testing.T) {
	t.Parallel()
	a := launchdAgent(installFixture())
	for _, want := range []string{
		"<string>service</string>", "<string>--foreground</string>", "<string>--restart-on-upgrade</string>",
		"<string>--claude</string>\n    <string>/home/u/.local/bin/claude</string>",
		"<key>SuccessfulExit</key><false/>",
		"<string>Bash(echo $HOME 100%)</string>",
	} {
		if !strings.Contains(a, want) {
			t.Errorf("agent lacks %q:\n%s", want, a)
		}
	}
	s := installFixture()
	s.Listen = nil
	if a := launchdAgent(s); !strings.Contains(a, "<string>--claude</string>\n    <string>none</string>") {
		t.Errorf("agent without --claude runs requests:\n%s", a)
	}
}

// Without --hub or PEER_HUB_URL, peer finds the hub that `service install`
// saved under the user's config directory.
func TestSavedHub(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	if h := savedHub(); h != "" {
		t.Fatalf("no file: %q", h)
	}
	if err := os.MkdirAll(filepath.Join(home, ".config", "peer"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".config", hubFileName), []byte("http://100.64.0.10:7790\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if h := savedHub(); h != "http://100.64.0.10:7790" {
		t.Fatalf("saved hub: %q", h)
	}
}
