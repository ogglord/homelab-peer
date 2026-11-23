package main

// `peer service install` makes this host's listener a user service from the
// peer installed in a nix profile: a systemd user unit on Linux, a launchd
// agent on macOS. Both start the listener from the profile's peer, a
// symlink, so after `peer update` (nix profile upgrade) the listener sees a
// newer binary and restarts itself once no run is in progress
// (--restart-on-upgrade); a deploy or an update never kills a run. It also
// links the skill shipped in the profile into ~/.claude/skills/peer.

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/ogglord/homelab-peer/internal/peerclient"
	"github.com/urfave/cli/v2"
)

const (
	// unitName is the systemd user unit (journalctl --user -u homelab-peer).
	unitName = "homelab-peer.service"
	// agentLabel is the launchd agent's label.
	agentLabel = "com.ogglord.homelab-peer"
	// profileEntry is the default nix profile entry `peer update` upgrades:
	// what `nix profile install github:ogglord/homelab-peer` names it.
	profileEntry = "homelab-peer"
)

// installSettings is what an installed service runs.
type installSettings struct {
	Peer     string   // the profile's peer (a symlink), started and watched
	Hub      string   // hub origin
	Listen   []string // listen flags: --claude, --checkout, --allow, ...
	Path     string   // PATH of the listener and its runs
	Home     string
	StateDir string // ~/.local/state/homelab-peer
}

func installCommand(e env) *cli.Command {
	return &cli.Command{
		Name:  "install",
		Usage: "Install this host's listener as a user service (systemd on Linux, launchd on macOS) and link the peer skill",
		Description: "The service runs `peer listen` from the nix profile's peer (--peer, default ~/.nix-profile/bin/peer) with " +
			"--restart-on-upgrade on that path, so `peer update` takes effect once no run is in progress. Restart: always, " +
			"after 10 s, except when a newer listener for this host superseded it. The listener's PATH is the PATH this " +
			"command runs with (--path overrides it), with the peer's directory first. Run it again to change the flags.",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "peer", Usage: "installed peer to run and watch (default: ~/.nix-profile/bin/peer, else this executable)"},
			&cli.StringFlag{Name: "claude", Usage: "claude binary; enables request runs (see listen --claude)"},
			&cli.StringFlag{Name: "checkout", Usage: "git checkout each request runs in a worktree of (see listen --checkout)"},
			&cli.StringSliceFlag{Name: "allow", Usage: "tool rule a run may use without approval (repeatable)"},
			&cli.StringSliceFlag{Name: "deny", Usage: "tool rule a run may never use (repeatable)"},
			&cli.StringFlag{Name: "policy-file", Usage: "auto-mode policy file for runs (default: ~/.config/peer/policy.json, written from `peer policy default` when missing)"},
			&cli.StringFlag{Name: "model", Usage: "model for runs"},
			&cli.StringFlag{Name: "path", Usage: "PATH for the listener and its runs (default: this command's PATH)"},
			&cli.BoolFlag{Name: "no-skill", Usage: "do not link ~/.claude/skills/peer"},
			&cli.BoolFlag{Name: "dry-run", Usage: "print the unit or agent instead of installing it"},
		},
		Action: e.serviceInstall,
	}
}

func uninstallCommand(e env) *cli.Command {
	return &cli.Command{
		Name:   "uninstall",
		Usage:  "Stop and remove the listener's user service (the skill link stays)",
		Action: e.serviceUninstall,
	}
}

func (e env) serviceInstall(c *cli.Context) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	s := installSettings{Home: home, StateDir: filepath.Join(home, ".local", "state", "homelab-peer")}
	if s.Peer, err = installedPeer(c.String("peer"), home); err != nil {
		return err
	}
	s.Hub = rootHub(c)
	if s.Hub == "" {
		return fmt.Errorf("no hub: pass --hub or set %s", peerclient.EnvHubURL)
	}
	if _, err := peerclient.New(s.Hub); err != nil {
		return err
	}
	for _, f := range []string{"claude", "checkout", "policy-file"} {
		if v := c.String(f); v != "" {
			abs, err := filepath.Abs(v)
			if err != nil {
				return err
			}
			s.Listen = append(s.Listen, "--"+f, abs)
		}
	}
	// Without --policy-file the host's policy file, made from the default
	// the first time.
	if c.String("policy-file") == "" {
		policy := filepath.Join(userConfigDir(home), policyFileName)
		if !c.Bool("dry-run") {
			wrote, err := writeDefaultPolicy(policy, false)
			if err != nil {
				return err
			}
			if wrote {
				fmt.Fprintf(e.out, "wrote %s: the default policy; review it, and restart the listener after an edit\n", policy)
			}
		}
		s.Listen = append(s.Listen, "--policy-file", policy)
	}
	if v := c.String("model"); v != "" {
		s.Listen = append(s.Listen, "--model", v)
	}
	for _, r := range c.StringSlice("allow") {
		s.Listen = append(s.Listen, "--allow", r)
	}
	for _, r := range c.StringSlice("deny") {
		s.Listen = append(s.Listen, "--deny", r)
	}
	s.Path = c.String("path")
	if s.Path == "" {
		s.Path = os.Getenv("PATH")
	}
	s.Path = prependPath(filepath.Dir(s.Peer), s.Path)

	var file, content string
	switch runtime.GOOS {
	case "linux":
		file, content = filepath.Join(userConfigDir(home), "systemd", "user", unitName), systemdUnit(s)
	case "darwin":
		file, content = filepath.Join(home, "Library", "LaunchAgents", agentLabel+".plist"), launchdAgent(s)
	default:
		return fmt.Errorf("peer service install supports Linux and macOS, not %s", runtime.GOOS)
	}
	if c.Bool("dry-run") {
		fmt.Fprintf(e.out, "# %s\n%s", file, content)
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(s.StateDir, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(file, []byte(content), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(e.out, "wrote %s\n", file)
	hubFile := filepath.Join(userConfigDir(home), hubFileName)
	if err := os.MkdirAll(filepath.Dir(hubFile), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(hubFile, []byte(s.Hub+"\n"), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(e.out, "wrote %s\n", hubFile)
	if err := startService(c.Context, file); err != nil {
		return err
	}
	fmt.Fprintln(e.out, "listener started")
	if runtime.GOOS == "linux" && !lingering() {
		fmt.Fprintln(e.out, "note: this user does not linger, so the listener starts at login only; `loginctl enable-linger` (or users.users.<name>.linger on NixOS) starts it at boot")
	}
	if !c.Bool("no-skill") {
		e.linkSkill(s.Peer, home)
	}
	return nil
}

func (e env) serviceUninstall(c *cli.Context) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	var file string
	switch runtime.GOOS {
	case "linux":
		file = filepath.Join(userConfigDir(home), "systemd", "user", unitName)
		_ = runQuiet(c.Context, "systemctl", "--user", "disable", "--now", unitName)
	case "darwin":
		file = filepath.Join(home, "Library", "LaunchAgents", agentLabel+".plist")
		_ = runQuiet(c.Context, "launchctl", "bootout", launchdDomain()+"/"+agentLabel)
	default:
		return fmt.Errorf("peer service uninstall supports Linux and macOS, not %s", runtime.GOOS)
	}
	if err := os.Remove(file); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if runtime.GOOS == "linux" {
		_ = runQuiet(c.Context, "systemctl", "--user", "daemon-reload")
	}
	fmt.Fprintf(e.out, "removed %s\n", file)
	return nil
}

// rootHub is --hub from any level of the command line, else PEER_HUB_URL.
func rootHub(c *cli.Context) string {
	for _, ctx := range c.Lineage() {
		if ctx.IsSet("hub") || ctx.String("hub") != "" {
			if v := ctx.String("hub"); v != "" {
				return v
			}
		}
	}
	return os.Getenv(peerclient.EnvHubURL)
}

// hubFileName is the hub's address under the user's config directory,
// written by `service install` so that every later `peer` finds the hub.
const hubFileName = "peer/hub"

// savedHub is the hub when neither --hub nor PEER_HUB_URL gives one: the
// hub in peer.json beside this binary (the Home Assistant add-on), else
// ~/.config/peer/hub. Unreadable files count as absent.
func savedHub() string {
	if exe, err := os.Executable(); err == nil {
		if exe, err = filepath.EvalSymlinks(exe); err == nil {
			if f, err := loadServiceFile(filepath.Join(filepath.Dir(exe), serviceConfigName), false); err == nil && f.Hub != "" {
				return f.Hub
			}
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	b, err := os.ReadFile(filepath.Join(userConfigDir(home), hubFileName))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// installedPeer is the peer the service runs: the given path, else the
// user's nix profile's (~/.nix-profile, or the XDG one), else this
// executable. It stays a symlink: the listener watches where it points.
func installedPeer(set, home string) (string, error) {
	if set != "" {
		return filepath.Abs(set)
	}
	state := os.Getenv("XDG_STATE_HOME")
	if !filepath.IsAbs(state) {
		state = filepath.Join(home, ".local", "state")
	}
	for _, p := range []string{
		filepath.Join(home, ".nix-profile", "bin", "peer"),
		filepath.Join(state, "nix", "profile", "bin", "peer"),
	} {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	exe, err := os.Executable()
	if err == nil && strings.HasPrefix(exe, "/nix/store/") {
		return "", errors.New("peer runs from the nix store but no profile holds it: pass --peer with the profile's bin/peer, or the listener never sees an update")
	}
	return exe, err
}

func userConfigDir(home string) string {
	if d := os.Getenv("XDG_CONFIG_HOME"); filepath.IsAbs(d) {
		return d
	}
	return filepath.Join(home, ".config")
}

// prependPath puts dir first in path, once.
func prependPath(dir, path string) string {
	parts := []string{dir}
	for _, p := range filepath.SplitList(path) {
		if p != "" && p != dir {
			parts = append(parts, p)
		}
	}
	return strings.Join(parts, string(os.PathListSeparator))
}

// listenCommand is the listener's command line.
func (s installSettings) listenCommand() []string {
	return append([]string{s.Peer, "--hub", s.Hub, "listen", "--restart-on-upgrade", s.Peer}, s.Listen...)
}

// systemdUnit is the user unit. It is not restarted by a deploy or an
// update: the listener restarts itself when idle (--restart-on-upgrade,
// after `systemctl --user daemon-reload`), and exit 3 (superseded) stays
// down so two listeners of one host never supersede each other forever.
func systemdUnit(s installSettings) string {
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f, a...) }
	w("# Written by `peer service install`; run it again to change this file.\n")
	w("[Unit]\nDescription=Homelab peer listener\n\n")
	w("[Service]\n")
	w("ExecStart=%s\n", systemdArgs(s.listenCommand()))
	w("Environment=%s\n", systemdQuote(peerclient.EnvHubURL+"="+s.Hub))
	w("Environment=%s\n", systemdQuote("PATH="+s.Path))
	w("WorkingDirectory=%%h\n")
	// ~/.local/state/homelab-peer, passed as $STATE_DIRECTORY (listen's
	// --state-dir): the result outbox and the per-request worktrees.
	w("StateDirectory=homelab-peer\n")
	w("StandardInput=null\n")
	w("Restart=always\nRestartSec=10\nRestartPreventExitStatus=3\n\n")
	w("[Install]\nWantedBy=default.target\n")
	return b.String()
}

// systemdArgs quotes each argument for ExecStart.
func systemdArgs(args []string) string {
	q := make([]string, len(args))
	for i, a := range args {
		q[i] = systemdQuote(a)
	}
	return strings.Join(q, " ")
}

// systemdQuote double-quotes s for a unit file, escaping what systemd
// would otherwise expand ($, %, \ and ").
func systemdQuote(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "$", "$$", "%", "%%")
	return `"` + r.Replace(s) + `"`
}

// launchdAgent is the launchd agent. launchd cannot restart on one exit
// status and not another, so it runs the supervisor of `peer service` in
// the foreground: that restarts the listener (also on an upgrade) and
// returns 0 once a newer listener supersedes it, and KeepAlive restarts
// the supervisor only when it failed.
func launchdAgent(s installSettings) string {
	args := []string{s.Peer, "service", "--foreground", "--hub", s.Hub, "--log", "-",
		"--lock", filepath.Join(s.StateDir, "peer.lock"), "--restart-on-upgrade", s.Peer}
	claude := "none"
	for i := 0; i+1 < len(s.Listen); i += 2 {
		if s.Listen[i] == "--claude" {
			claude = s.Listen[i+1]
			continue
		}
		args = append(args, s.Listen[i], s.Listen[i+1])
	}
	args = append(args, "--claude", claude)
	log := filepath.Join(s.Home, "Library", "Logs", "homelab-peer.log")
	var b bytes.Buffer
	b.WriteString(xml.Header)
	b.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	b.WriteString("<!-- Written by `peer service install`; run it again to change this file. -->\n")
	b.WriteString("<plist version=\"1.0\">\n<dict>\n")
	kv := func(k, v string) { fmt.Fprintf(&b, "  <key>%s</key><string>%s</string>\n", k, xmlEscape(v)) }
	kv("Label", agentLabel)
	b.WriteString("  <key>ProgramArguments</key>\n  <array>\n")
	for _, a := range args {
		fmt.Fprintf(&b, "    <string>%s</string>\n", xmlEscape(a))
	}
	b.WriteString("  </array>\n")
	b.WriteString("  <key>EnvironmentVariables</key>\n  <dict>\n")
	fmt.Fprintf(&b, "    <key>%s</key><string>%s</string>\n", peerclient.EnvHubURL, xmlEscape(s.Hub))
	fmt.Fprintf(&b, "    <key>PATH</key><string>%s</string>\n", xmlEscape(s.Path))
	fmt.Fprintf(&b, "    <key>XDG_STATE_HOME</key><string>%s</string>\n", xmlEscape(filepath.Dir(s.StateDir)))
	b.WriteString("  </dict>\n")
	kv("WorkingDirectory", s.Home)
	b.WriteString("  <key>RunAtLoad</key><true/>\n")
	b.WriteString("  <key>KeepAlive</key>\n  <dict><key>SuccessfulExit</key><false/></dict>\n")
	b.WriteString("  <key>ThrottleInterval</key><integer>10</integer>\n")
	kv("StandardOutPath", log)
	kv("StandardErrorPath", log)
	b.WriteString("</dict>\n</plist>\n")
	return b.String()
}

func xmlEscape(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

func launchdDomain() string { return "gui/" + strconv.Itoa(os.Getuid()) }

// startService loads the written unit or agent and (re)starts it.
func startService(ctx context.Context, file string) error {
	switch runtime.GOOS {
	case "linux":
		if err := runQuiet(ctx, "systemctl", "--user", "daemon-reload"); err != nil {
			return err
		}
		if err := runQuiet(ctx, "systemctl", "--user", "enable", unitName); err != nil {
			return err
		}
		return runQuiet(ctx, "systemctl", "--user", "restart", unitName)
	case "darwin":
		_ = runQuiet(ctx, "launchctl", "bootout", launchdDomain()+"/"+agentLabel)
		return runQuiet(ctx, "launchctl", "bootstrap", launchdDomain(), file)
	}
	return nil
}

// restartService restarts an installed listener now, run or not.
func restartService(ctx context.Context) error {
	switch runtime.GOOS {
	case "linux":
		return runQuiet(ctx, "systemctl", "--user", "restart", unitName)
	case "darwin":
		return runQuiet(ctx, "launchctl", "kickstart", "-k", launchdDomain()+"/"+agentLabel)
	}
	return nil
}

// serviceInstalled reports whether `peer service install` wrote a unit or
// an agent for this user.
func serviceInstalled(home string) bool {
	var file string
	switch runtime.GOOS {
	case "linux":
		file = filepath.Join(userConfigDir(home), "systemd", "user", unitName)
	case "darwin":
		file = filepath.Join(home, "Library", "LaunchAgents", agentLabel+".plist")
	default:
		return false
	}
	_, err := os.Stat(file)
	return err == nil
}

func lingering() bool {
	u := os.Getenv("USER")
	if u == "" {
		return true
	}
	_, err := os.Stat(filepath.Join("/var/lib/systemd/linger", u))
	return err == nil
}

func runQuiet(ctx context.Context, name string, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// linkSkill points ~/.claude/skills/peer at the skill shipped next to the
// installed peer (<profile>/share/claude/skills/peer), so the skill
// always matches the CLI. An existing symlink is replaced; a real
// directory is left alone.
func (e env) linkSkill(peer, home string) {
	target := filepath.Join(filepath.Dir(filepath.Dir(peer)), "share", "claude", "skills", "peer")
	if _, err := os.Stat(filepath.Join(target, "SKILL.md")); err != nil {
		fmt.Fprintf(e.err, "warning: no skill at %s; ~/.claude/skills/peer is not linked\n", target)
		return
	}
	link := filepath.Join(home, ".claude", "skills", "peer")
	if fi, err := os.Lstat(link); err == nil && fi.Mode()&fs.ModeSymlink == 0 {
		fmt.Fprintf(e.err, "warning: %s is not a symlink; leaving it, the peer skill is not linked\n", link)
		return
	}
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		fmt.Fprintf(e.err, "warning: linking the skill: %v\n", err)
		return
	}
	tmp := link + ".tmp"
	_ = os.Remove(tmp)
	if err := os.Symlink(target, tmp); err == nil {
		err = os.Rename(tmp, link)
		if err == nil {
			fmt.Fprintf(e.out, "linked %s -> %s\n", link, target)
			return
		}
	}
	fmt.Fprintf(e.err, "warning: could not link %s\n", link)
}

// ── update ──────────────────────────────────────────────────────────────

func updateCommand(e env) *cli.Command {
	return &cli.Command{
		Name:  "update",
		Usage: "Upgrade peer in its nix profile; an installed listener restarts itself once no run is in progress",
		Description: "Runs `nix profile upgrade` on the profile entry that installed peer (--entry, default " + profileEntry +
			"). The listener of `peer service install` watches the profile's peer and restarts on the new one when idle; " +
			"--now restarts it at once, ending a run in progress.",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "entry", Value: profileEntry, Usage: "nix profile entry to upgrade (see `nix profile list`)"},
			&cli.StringFlag{Name: "profile", Usage: "nix profile (default: the user's)"},
			&cli.BoolFlag{Name: "now", Usage: "restart the installed listener now, even mid-run"},
		},
		Action: e.update,
	}
}

func (e env) update(c *cli.Context) error {
	args := []string{"profile", "upgrade"}
	if p := c.String("profile"); p != "" {
		args = append(args, "--profile", p)
	}
	args = append(args, c.String("entry"))
	cmd := exec.CommandContext(c.Context, "nix", args...)
	cmd.Stdout, cmd.Stderr = e.out, e.err
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nix %s: %w", strings.Join(args, " "), err)
	}
	home, err := os.UserHomeDir()
	if err != nil || !serviceInstalled(home) {
		return nil
	}
	if c.Bool("now") {
		if err := restartService(c.Context); err != nil {
			return err
		}
		fmt.Fprintln(e.out, "listener restarted")
		return nil
	}
	fmt.Fprintln(e.out, "the listener restarts on the new peer once no run is in progress (or run `peer update --now`)")
	return nil
}
