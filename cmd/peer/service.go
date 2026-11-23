package main

// `peer service` runs the listener supervised, for hosts without a service
// manager: the Home Assistant add-on runs its init commands as root, each
// bounded at about two minutes, and supervises nothing. Its init command is
// just `/data/peer service`: settings come from peer.json next to the
// binary, the command returns once a detached supervisor holds the lock, and
// the supervisor restarts the listener until a newer one supersedes it.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ogglord/homelab-peer/internal/peerclient"
	"github.com/urfave/cli/v2"
)

// Service defaults.
const (
	serviceConfigName = "peer.json"
	serviceLogName    = "peer.log"
	serviceLockName   = "peer.lock"
	serviceLogMax     = 5 << 20
	serviceLogCheck   = time.Minute
	// The listener's restart backoff: 5 s doubling to 5 min, back to 5 s
	// after a run that lasted longer than 5 min.
	serviceMinBackoff = 5 * time.Second
	serviceMaxBackoff = 5 * time.Minute
	serviceResetAfter = 5 * time.Minute
	// serviceStopGrace is how long a stopping listener gets to post the
	// result of a run it interrupts (resultPostTimeout is 30 s) before the
	// kill.
	serviceStopGrace = 45 * time.Second
)

// dataHomeClaude is where the Home Assistant add-on installs claude, the
// last place `claude: auto` looks.
var dataHomeClaude = "/data/home/.local/bin/claude"

func serviceCommand(e env) *cli.Command {
	return &cli.Command{
		Name:  "service",
		Usage: "Run the listener detached and supervised, with settings from peer.json next to this binary",
		Description: "Starts a supervisor in a new session and returns once it holds the lock; a second `peer service` " +
			"exits 0 while one runs. The supervisor runs `peer listen` with the resolved settings, restarts it on exit " +
			"(5 s doubling to 5 min), stops for good when a newer listener for this host supersedes it, and stops the " +
			"listener on SIGTERM or SIGINT.\n\n" +
			"Settings come from flags, then the config file, then PEER_HUB_URL for the hub. The config file is JSON " +
			"with the fields hub, allow, deny, policy_file, model, max_budget_usd (ignored), log, home, claude, checkout and " +
			"restart_on_upgrade; relative paths in " +
			"it are relative to its directory.\n\n" +
			"claude \"auto\" (the default) looks on PATH, then at $HOME/.local/bin/claude, then at " + dataHomeClaude +
			"; \"none\", or no claude found, runs no requests and the listener only receives status and results. The listener's HOME is " +
			"--home, else the home whose .local/bin holds claude, else this process's; its PATH starts with this " +
			"binary's directory and claude's.\n\n" +
			"With restart_on_upgrade the supervisor starts the listener from that installed binary, and the listener " +
			"exits 0 to be restarted once it resolves to a newer one and no run is in progress (see listen --restart-on-upgrade).",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "config", Usage: "config file (default: " + serviceConfigName + " next to this binary; may be absent)"},
			&cli.StringFlag{Name: "hub", Usage: "hub origin by tailnet IPv4, e.g. http://100.64.0.1:7790 (else the config file, else PEER_HUB_URL)"},
			&cli.StringSliceFlag{Name: "allow", Usage: "tool rule a run may use without approval (repeatable)"},
			&cli.StringSliceFlag{Name: "deny", Usage: "tool rule a run may never use (repeatable)"},
			&cli.StringFlag{Name: "policy-file", Usage: "auto-mode policy file for runs (see listen --policy-file)"},
			&cli.StringFlag{Name: "model", Usage: "model for runs"},
			&cli.StringFlag{Name: "claude", Usage: `claude binary, "auto" or "none"`},
			&cli.StringFlag{Name: "checkout", Usage: "git checkout each request runs in a worktree of, kept until the request ends"},
			&cli.StringFlag{Name: "restart-on-upgrade", Usage: "installed peer binary (a symlink) to run the listener from and restart it on when it changes"},
			&cli.StringFlag{Name: "log", Usage: "log file, rotated to <log>.1 past 5 MB (default: " + serviceLogName + " next to this binary; - for stderr)"},
			&cli.StringFlag{Name: "home", Usage: "HOME for the listener and its runs"},
			&cli.StringFlag{Name: "lock", Usage: "lock file (default: " + serviceLockName + " next to this binary)"},
			&cli.BoolFlag{Name: "foreground", Usage: "supervise in this process instead of detaching"},
			// The detached supervisor's inherited lock.
			&cli.IntFlag{Name: "lock-fd", Hidden: true},
		},
		Action:      e.service,
		Subcommands: []*cli.Command{installCommand(e), uninstallCommand(e)},
	}
}

// serviceFile is peer.json.
type serviceFile struct {
	Hub          string   `json:"hub"`
	Allow        []string `json:"allow"`
	Deny         []string `json:"deny"`
	PolicyFile   string   `json:"policy_file"`
	Model        string   `json:"model"`
	MaxBudgetUSD *float64 `json:"max_budget_usd"` // accepted from older peer.json files and ignored
	Log          string   `json:"log"`
	Home         string   `json:"home"`
	Claude       string   `json:"claude"`
	Checkout     string   `json:"checkout"`
	// RestartOnUpgrade is listen's --restart-on-upgrade.
	RestartOnUpgrade string `json:"restart_on_upgrade"`
}

// loadServiceFile reads the config file at path; a missing file is empty
// unless required. Relative paths in it become relative to its directory.
func loadServiceFile(path string, required bool) (serviceFile, error) {
	var f serviceFile
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) && !required {
		return f, nil
	}
	if err != nil {
		return f, fmt.Errorf("reading the config: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return f, fmt.Errorf("%s: %s", path, strings.TrimPrefix(err.Error(), "json: "))
	}
	if dec.More() {
		return f, fmt.Errorf("%s: more than one JSON value", path)
	}
	dir := filepath.Dir(path)
	for _, p := range []*string{&f.Log, &f.Home, &f.Checkout, &f.PolicyFile, &f.RestartOnUpgrade} {
		if *p != "" && !filepath.IsAbs(*p) {
			*p = filepath.Join(dir, *p)
		}
	}
	if f.Claude != "" && f.Claude != "auto" && f.Claude != "none" && !filepath.IsAbs(f.Claude) {
		f.Claude = filepath.Join(dir, f.Claude)
	}
	return f, nil
}

// serviceSettings is what the supervisor runs with.
type serviceSettings struct {
	Hub         string
	Allow, Deny []string
	PolicyFile  string
	Model       string
	Log         string // "-": stderr
	Lock        string
	Checkout    string
	Claude      string // "" when none was found: no runs
	Home        string // "" inherits
	// RestartOnUpgrade is the installed peer the listener runs from and
	// restarts on; "" runs Peer and never restarts on an upgrade.
	RestartOnUpgrade string
	// Peer is this binary, Config the config file read.
	Peer, Config string
}

// resolveService merges flags over the config file over PEER_HUB_URL, with
// defaults next to peer (this binary, symlinks resolved).
func resolveService(c *cli.Context, peer string, getenv func(string) string) (serviceSettings, error) {
	dir := filepath.Dir(peer)
	s := serviceSettings{Peer: peer, Config: c.String("config")}
	required := s.Config != ""
	if !required {
		s.Config = filepath.Join(dir, serviceConfigName)
	}
	f, err := loadServiceFile(s.Config, required)
	if err != nil {
		return s, err
	}
	pick := func(flag, file string) string {
		if c.IsSet(flag) {
			return c.String(flag)
		}
		return file
	}
	// The service's --hub, then the root one (`peer --hub X service`, which
	// PEER_HUB_URL also sets), then the file, then PEER_HUB_URL.
	s.Hub = c.String("hub")
	for _, ctx := range c.Lineage()[1:] {
		if v := ctx.String("hub"); s.Hub == "" && v != getenv(peerclient.EnvHubURL) {
			s.Hub = v
		}
	}
	if s.Hub == "" {
		s.Hub = f.Hub
	}
	if s.Hub == "" {
		s.Hub = getenv(peerclient.EnvHubURL)
	}
	if s.Hub == "" {
		return s, fmt.Errorf("no hub: pass --hub, set hub in %s or set %s", s.Config, peerclient.EnvHubURL)
	}
	s.Allow, s.Deny = f.Allow, f.Deny
	if c.IsSet("allow") {
		s.Allow = c.StringSlice("allow")
	}
	if c.IsSet("deny") {
		s.Deny = c.StringSlice("deny")
	}
	s.PolicyFile = pick("policy-file", f.PolicyFile)
	s.Model = pick("model", f.Model)
	s.Checkout = pick("checkout", f.Checkout)
	s.RestartOnUpgrade = pick("restart-on-upgrade", f.RestartOnUpgrade)
	s.Log = pick("log", f.Log)
	if s.Log == "" {
		s.Log = filepath.Join(dir, serviceLogName)
	}
	s.Lock = c.String("lock")
	if s.Lock == "" {
		s.Lock = filepath.Join(dir, serviceLockName)
	}
	for _, p := range []*string{&s.Checkout, &s.Lock, &s.PolicyFile, &s.RestartOnUpgrade} {
		if *p != "" {
			if *p, err = filepath.Abs(*p); err != nil {
				return s, err
			}
		}
	}
	if s.Log != "-" {
		if s.Log, err = filepath.Abs(s.Log); err != nil {
			return s, err
		}
	}

	claude := pick("claude", f.Claude)
	switch claude {
	case "", "auto":
		s.Claude = findClaude(getenv("HOME"))
	case "none":
	default:
		if s.Claude, err = filepath.Abs(claude); err != nil {
			return s, err
		}
		if !isExecutable(s.Claude) {
			return s, fmt.Errorf("claude %s is not an executable file", s.Claude)
		}
	}
	s.Home = listenerHome(pick("home", f.Home), s.Claude)
	if s.Home != "" {
		if s.Home, err = filepath.Abs(s.Home); err != nil {
			return s, err
		}
	}
	return s, nil
}

// findClaude is `claude: auto`: on PATH, then the home's .local/bin, then
// the add-on's; "" when none is there.
func findClaude(home string) string {
	if p, err := exec.LookPath("claude"); err == nil {
		if abs, err := filepath.Abs(p); err == nil {
			return abs
		}
	}
	var candidates []string
	if home != "" {
		candidates = append(candidates, filepath.Join(home, ".local", "bin", "claude"))
	}
	for _, p := range append(candidates, dataHomeClaude) {
		if isExecutable(p) {
			return p
		}
	}
	return ""
}

func isExecutable(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0
}

// claudeHomeSuffix is where a home keeps its claude.
const claudeHomeSuffix = "/.local/bin/claude"

// listenerHome is the listener's HOME: the one set, else the home whose
// .local/bin holds claude (its login lives there), else "" (inherit).
func listenerHome(set, claude string) string {
	if set != "" {
		return set
	}
	if home, ok := strings.CutSuffix(claude, claudeHomeSuffix); ok {
		if home == "" {
			return "/"
		}
		return home
	}
	return ""
}

// listenArgs is the listener's command line after the binary.
func (s serviceSettings) listenArgs() []string {
	a := []string{"--hub", s.Hub, "listen"}
	if s.Claude != "" {
		a = append(a, "--claude", s.Claude)
	}
	for _, r := range s.Allow {
		a = append(a, "--allow", r)
	}
	for _, r := range s.Deny {
		a = append(a, "--deny", r)
	}
	if s.PolicyFile != "" {
		a = append(a, "--policy-file", s.PolicyFile)
	}
	if s.Model != "" {
		a = append(a, "--model", s.Model)
	}
	if s.Checkout != "" {
		a = append(a, "--checkout", s.Checkout)
	}
	if s.RestartOnUpgrade != "" {
		a = append(a, "--restart-on-upgrade", s.RestartOnUpgrade)
	}
	return a
}

// listenEnv is environ with the listener's HOME and PATH: this binary's
// directory, then claude's, ahead of the rest.
func (s serviceSettings) listenEnv(environ []string) []string {
	var path string
	out := make([]string, 0, len(environ)+2)
	for _, kv := range environ {
		switch {
		case strings.HasPrefix(kv, "PATH="):
			path = kv[len("PATH="):]
		case strings.HasPrefix(kv, "HOME=") && s.Home != "":
		default:
			out = append(out, kv)
		}
	}
	first := []string{filepath.Dir(s.Peer)}
	if s.Claude != "" {
		first = append(first, filepath.Dir(s.Claude))
	}
	dirs := slices.Compact(first)
	for _, d := range filepath.SplitList(path) {
		if d != "" && !slices.Contains(dirs, d) {
			dirs = append(dirs, d)
		}
	}
	out = append(out, "PATH="+strings.Join(dirs, string(filepath.ListSeparator)))
	if s.Home != "" {
		out = append(out, "HOME="+s.Home)
	}
	return out
}

// selfPath is this binary with symlinks resolved.
func selfPath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locating this binary: %w", err)
	}
	return filepath.EvalSymlinks(exe)
}

// startDetached starts the supervisor in a new session with stdin, stdout
// and stderr on /dev/null and lock as fd 3, and returns its pid.
var startDetached = func(exe string, args, environ []string, lock *os.File) (int, error) {
	cmd := exec.Command(exe, args...)
	cmd.Env = environ
	cmd.ExtraFiles = []*os.File{lock}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	pid := cmd.Process.Pid
	return pid, cmd.Process.Release()
}

// supervise runs the supervisor in this process (a variable for tests).
var supervise = func(ctx context.Context, s *supervisor) error { return s.run(ctx) }

func (e env) service(c *cli.Context) error {
	if c.NArg() > 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(c.Args().Slice(), " "))
	}
	peer, err := selfPath()
	if err != nil {
		return err
	}
	s, err := resolveService(c, peer, os.Getenv)
	if err != nil {
		return err
	}

	if s.Log == "-" && !c.Bool("foreground") {
		return errors.New("--log - (stderr) needs --foreground: a detached supervisor has no stderr")
	}
	var lock *os.File
	if fd := c.Int("lock-fd"); fd > 0 {
		lock = os.NewFile(uintptr(fd), s.Lock)
		if err := flock(lock); err != nil {
			return fmt.Errorf("the inherited lock %s: %w", s.Lock, err)
		}
	} else if lock, err = acquireLock(s.Lock); err != nil {
		var held *lockHeldError
		if errors.As(err, &held) {
			fmt.Fprintf(e.out, "peer service is already running (%s)\n", held.Error())
			return nil
		}
		return err
	}
	defer lock.Close()

	out, err := openServiceLog(s.Log, e.err)
	if err != nil {
		return err
	}
	defer out.Close()

	if !c.Bool("foreground") {
		args := append(slices.Clone(e.args[1:]), "--foreground", "--lock-fd", "3")
		pid, err := startDetached(peer, args, os.Environ(), lock)
		if err != nil {
			return fmt.Errorf("starting the supervisor: %w", err)
		}
		writeLockPID(lock, pid)
		fmt.Fprintf(e.out, "peer service started (pid %d); log %s\n", pid, s.Log)
		return nil
	}

	writeLockPID(lock, os.Getpid())
	ctx, stop := signal.NotifyContext(c.Context, os.Interrupt, syscall.SIGTERM)
	defer stop()
	log := slog.New(slog.NewTextHandler(out, nil)).With("src", "service")
	// Restarting the binary this supervisor started from would load the old
	// listener again, which would see the upgrade again, forever.
	exe := peer
	if s.RestartOnUpgrade != "" {
		exe = s.RestartOnUpgrade
	}
	sup := &supervisor{
		exe: exe, args: s.listenArgs(), env: s.listenEnv(os.Environ()), out: out, log: log,
		backoff: backoff{min: serviceMinBackoff, max: serviceMaxBackoff, reset: serviceResetAfter},
	}
	attrs := []any{"pid", os.Getpid(), "config", s.Config, "hub", s.Hub, "log", s.Log, "lock", s.Lock}
	if s.Home != "" {
		attrs = append(attrs, "home", s.Home)
	}
	if s.Claude != "" {
		log.Info("service starting", append(attrs, "claude", s.Claude)...)
	} else {
		log.Warn("service starting without runs: no claude on PATH, at $HOME/.local/bin/claude or at "+dataHomeClaude+
			"; the listener receives status and results only", attrs...)
	}
	return supervise(ctx, sup)
}

// ── lock ────────────────────────────────────────────────────────────────

// lockHeldError is a lock another process holds.
type lockHeldError struct{ path, pid string }

func (e *lockHeldError) Error() string {
	if e.pid == "" {
		return "lock " + e.path + " is held"
	}
	return "pid " + e.pid + ", lock " + e.path
}

// acquireLock takes path's exclusive flock without waiting.
func acquireLock(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return nil, fmt.Errorf("opening the lock: %w", err)
	}
	if err := flock(f); err != nil {
		data, _ := os.ReadFile(path)
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, &lockHeldError{path: path, pid: strings.TrimSpace(string(data))}
		}
		return nil, fmt.Errorf("locking %s: %w", path, err)
	}
	return f, nil
}

func flock(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
}

// writeLockPID records the supervisor's pid in the lock, for the message a
// second `peer service` prints.
func writeLockPID(f *os.File, pid int) {
	_ = f.Truncate(0)
	_, _ = f.WriteAt([]byte(strconv.Itoa(pid)+"\n"), 0)
}

// ── log ─────────────────────────────────────────────────────────────────

// serviceLog is the supervisor's and the listener's log.
type serviceLog interface {
	io.Writer
	rotate()
	Close() error
}

func openServiceLog(path string, stderr io.Writer) (serviceLog, error) {
	if path == "-" {
		return stderrLog{stderr}, nil
	}
	return openRotatingLog(path, serviceLogMax)
}

type stderrLog struct{ io.Writer }

func (stderrLog) rotate()      {}
func (stderrLog) Close() error { return nil }

// rotatingLog appends to path and moves it to path.1 once it is larger
// than max, checked when rotate is called.
type rotatingLog struct {
	path string
	max  int64
	mu   sync.Mutex
	f    *os.File
}

func openRotatingLog(path string, max int64) (*rotatingLog, error) {
	l := &rotatingLog{path: path, max: max}
	var err error
	if l.f, err = l.open(); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *rotatingLog) open() (*os.File, error) {
	f, err := os.OpenFile(l.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		return nil, fmt.Errorf("opening the log: %w", err)
	}
	return f, nil
}

func (l *rotatingLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.f.Write(p)
}

func (l *rotatingLog) rotate() {
	l.mu.Lock()
	defer l.mu.Unlock()
	fi, err := l.f.Stat()
	if err != nil || fi.Size() <= l.max {
		return
	}
	if err := os.Rename(l.path, l.path+".1"); err != nil {
		fmt.Fprintf(l.f, "rotating the log failed: %v\n", err)
		return
	}
	f, err := l.open()
	if err != nil {
		return // keep writing to the moved file
	}
	l.f.Close()
	l.f = f
}

func (l *rotatingLog) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.f.Close()
}

// ── supervisor ──────────────────────────────────────────────────────────

// backoff is the listener's restart delay.
type backoff struct {
	min, max, reset time.Duration
	cur             time.Duration
}

// next is the wait before restarting a listener that ran for ran: the
// current delay, back to min after a long run; the one after doubles.
func (b *backoff) next(ran time.Duration) time.Duration {
	if b.cur == 0 || ran >= b.reset {
		b.cur = b.min
	}
	d := b.cur
	b.cur = min(b.cur*2, b.max)
	return d
}

// supervisor runs the listener (exe args) until ctx ends or it exits
// superseded, restarting it on every other exit.
type supervisor struct {
	exe     string
	args    []string
	env     []string
	out     serviceLog
	log     *slog.Logger
	backoff backoff
	// rotateEvery is how often the log size is checked between starts;
	// zero means serviceLogCheck.
	rotateEvery time.Duration
}

func (s *supervisor) run(ctx context.Context) error {
	every := s.rotateEvery
	if every <= 0 {
		every = serviceLogCheck
	}
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.out.rotate()
			}
		}
	}()
	for {
		s.out.rotate()
		started := time.Now()
		code, err := s.once(ctx)
		if ctx.Err() != nil {
			s.log.Info("service stopped", "listener_exit", code)
			return nil
		}
		if code == exitSuperseded {
			s.log.Warn("listener superseded: a newer listener holds this host; not restarting")
			return nil
		}
		ran := time.Since(started).Round(time.Millisecond)
		wait := s.backoff.next(ran)
		s.log.Warn("listener exited; restarting", "exit", code, "error", err, "ran", ran.String(), "retry_in", wait.String())
		select {
		case <-ctx.Done():
			s.log.Info("service stopped")
			return nil
		case <-time.After(wait):
		}
	}
}

// once runs the listener to its exit and returns its exit status (-1 when
// it did not start or was killed by a signal).
func (s *supervisor) once(ctx context.Context) (int, error) {
	cmd := exec.CommandContext(ctx, s.exe, s.args...)
	cmd.Env = s.env
	cmd.Stdout, cmd.Stderr = s.out, s.out
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = serviceStopGrace
	if err := cmd.Start(); err != nil {
		return -1, err
	}
	s.log.Info("listener started", "pid", cmd.Process.Pid)
	err := cmd.Wait()
	return cmd.ProcessState.ExitCode(), err
}
