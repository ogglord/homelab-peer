package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ogglord/homelab-peer/internal/peerclient/hubtest"
)

// serviceEnv isolates claude auto-detection from the host running the
// tests (homelab has a claude on PATH and in ~/.local/bin): PATH and HOME
// are empty temporary directories and the add-on's location is under dir.
func serviceEnv(t *testing.T) (dir string) {
	t.Helper()
	dir = t.TempDir()
	for _, d := range []string{"path", "home", "data"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", filepath.Join(dir, "path"))
	t.Setenv("HOME", filepath.Join(dir, "home"))
	t.Setenv("PEER_HUB_URL", "")
	was := dataHomeClaude
	dataHomeClaude = filepath.Join(dir, "data", "home", ".local", "bin", "claude")
	t.Cleanup(func() { dataHomeClaude = was })
	return dir
}

// executable writes an executable file at path.
func executable(t *testing.T, path string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeFile(t *testing.T, path, content string) string {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// captureSupervise replaces the foreground supervisor and the detach with
// recorders for one test.
type serviceCapture struct {
	sup      *supervisor
	detached []string
	exe      string
}

func captureService(t *testing.T) *serviceCapture {
	t.Helper()
	got := &serviceCapture{}
	sup, det := supervise, startDetached
	supervise = func(_ context.Context, s *supervisor) error { got.sup = s; return nil }
	startDetached = func(exe string, args, _ []string, _ *os.File) (int, error) {
		got.exe, got.detached = exe, args
		return 4242, nil
	}
	t.Cleanup(func() { supervise, startDetached = sup, det })
	return got
}

func envValue(env []string, key string) string {
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, key+"="); ok {
			return v
		}
	}
	return ""
}

// serviceArgs is `peer service --foreground` with the lock and log in dir.
func serviceArgs(dir string, extra ...string) []string {
	return append([]string{"service", "--foreground", "--lock", filepath.Join(dir, "peer.lock"), "--log", filepath.Join(dir, "peer.log")}, extra...)
}

// The config file sets every field; relative paths are relative to it.
func TestServiceConfigFile(t *testing.T) {
	dir := serviceEnv(t)
	claude := executable(t, filepath.Join(dir, "bin", "claude"))
	cfg := writeFile(t, filepath.Join(dir, "peer.json"), `{
		"hub": "http://100.64.0.1:7790",
		"allow": ["Bash(ha addons list:*)", "Bash(echo a,b)"],
		"deny": ["Bash(rm:*)"],
		"policy_file": "policy.json",
		"model": "sonnet",
		"max_budget_usd": 1.5,
		"home": "home",
		"claude": "bin/claude",
		"checkout": "/srv/checkout"
	}`)
	got := captureService(t)
	r := peerCmd("", serviceArgs(dir, "--config", cfg)...)
	if r.code != 0 || got.sup == nil {
		t.Fatalf("service: %+v", r)
	}
	want := []string{"--hub", "http://100.64.0.1:7790", "listen", "--claude", claude,
		"--allow", "Bash(ha addons list:*)", "--allow", "Bash(echo a,b)", "--deny", "Bash(rm:*)", "--policy-file", filepath.Join(dir, "policy.json"),
		"--model", "sonnet", "--checkout", "/srv/checkout"}
	if !slices.Equal(got.sup.args, want) {
		t.Fatalf("listen args\n got %q\nwant %q", got.sup.args, want)
	}
	if h := envValue(got.sup.env, "HOME"); h != filepath.Join(dir, "home") {
		t.Errorf("HOME %q", h)
	}
	self, _ := selfPath()
	if p := envValue(got.sup.env, "PATH"); p != filepath.Dir(self)+":"+filepath.Join(dir, "bin")+":"+filepath.Join(dir, "path") {
		t.Errorf("PATH %q", p)
	}
	if got.sup.exe != self {
		t.Errorf("listener binary %q, want %q", got.sup.exe, self)
	}
}

// Flags override the file field by field; the rest comes from the file.
func TestServiceFlagsOverrideFile(t *testing.T) {
	dir := serviceEnv(t)
	cfg := writeFile(t, filepath.Join(dir, "peer.json"),
		`{"hub":"http://file:7790","allow":["Bash(a:*)"],"deny":["Bash(rm:*)"],"model":"sonnet","max_budget_usd":1}`)
	got := captureService(t)
	r := peerCmd("", serviceArgs(dir, "--config", cfg, "--hub", "http://flag:7790",
		"--allow", "Bash(b:*)", "--model", "opus")...)
	if r.code != 0 || got.sup == nil {
		t.Fatalf("service: %+v", r)
	}
	want := []string{"--hub", "http://flag:7790", "listen", "--allow", "Bash(b:*)", "--deny", "Bash(rm:*)", "--model", "opus"}
	if !slices.Equal(got.sup.args, want) {
		t.Fatalf("listen args\n got %q\nwant %q", got.sup.args, want)
	}
}

// restart_on_upgrade passes through to listen, the flag over the file, and
// the supervisor starts that installed binary, so a restart loads the new
// one rather than the binary the supervisor started from.
func TestServiceRestartOnUpgrade(t *testing.T) {
	dir := serviceEnv(t)
	cfg := writeFile(t, filepath.Join(dir, "peer.json"), `{"hub":"http://x:7790","restart_on_upgrade":"bin/peer"}`)
	for _, c := range []struct {
		name, want string
		extra      []string
	}{
		{"file, relative to it", filepath.Join(dir, "bin", "peer"), nil},
		{"flag over file", "/run/current-system/sw/bin/peer", []string{"--restart-on-upgrade", "/run/current-system/sw/bin/peer"}},
	} {
		got := captureService(t)
		if r := peerCmd("", serviceArgs(dir, append([]string{"--config", cfg}, c.extra...)...)...); r.code != 0 || got.sup == nil {
			t.Fatalf("%s: service: %+v", c.name, r)
		}
		want := []string{"--hub", "http://x:7790", "listen", "--restart-on-upgrade", c.want}
		if !slices.Equal(got.sup.args, want) || got.sup.exe != c.want {
			t.Errorf("%s: listener %q %q, want %q %q", c.name, got.sup.exe, got.sup.args, c.want, want)
		}
	}
}

// The hub: the service flag or the root one, then the file, then
// PEER_HUB_URL; none of them is an error.
func TestServiceHubPrecedence(t *testing.T) {
	dir := serviceEnv(t)
	withHub := writeFile(t, filepath.Join(dir, "hub.json"), `{"hub":"http://file:7790"}`)
	noHub := writeFile(t, filepath.Join(dir, "nohub.json"), `{}`)
	hub := func(env string, args ...string) (string, result) {
		t.Helper()
		t.Setenv("PEER_HUB_URL", env)
		got := captureService(t)
		r := peerCmd("", args...)
		if got.sup == nil {
			return "", r
		}
		return got.sup.args[1], r
	}
	for _, c := range []struct {
		name, env, want string
		args            []string
	}{
		{"file over env", "http://env:7790", "http://file:7790", serviceArgs(dir, "--config", withHub)},
		{"env fallback", "http://env:7790", "http://env:7790", serviceArgs(dir, "--config", noHub)},
		{"root flag over file", "http://env:7790", "http://root:7790", append([]string{"--hub", "http://root:7790"}, serviceArgs(dir, "--config", withHub)...)},
	} {
		if got, r := hub(c.env, c.args...); got != c.want {
			t.Errorf("%s: hub %q, want %q (%+v)", c.name, got, c.want, r)
		}
	}
	if _, r := hub("", serviceArgs(dir, "--config", noHub)...); r.code != 1 || !strings.Contains(r.stderr, "no hub") {
		t.Fatalf("no hub anywhere: %+v", r)
	}
}

// An unknown field is an error naming it; a --config that is missing is an
// error, the default one may be absent.
func TestServiceConfigErrors(t *testing.T) {
	dir := serviceEnv(t)
	captureService(t)
	cfg := writeFile(t, filepath.Join(dir, "peer.json"), `{"hub":"http://x:7790","max_budget":2}`)
	if r := peerCmd("", serviceArgs(dir, "--config", cfg)...); r.code != 1 || !strings.Contains(r.stderr, `unknown field "max_budget"`) {
		t.Fatalf("unknown field: %+v", r)
	}
	if r := peerCmd("", serviceArgs(dir, "--config", filepath.Join(dir, "missing.json"))...); r.code != 1 || !strings.Contains(r.stderr, "missing.json") {
		t.Fatalf("missing --config: %+v", r)
	}
	if _, err := loadServiceFile(filepath.Join(dir, "absent.json"), false); err != nil {
		t.Fatalf("absent default config: %v", err)
	}
}

// claude auto: PATH, then $HOME/.local/bin/claude, then the add-on's.
func TestFindClaudeOrder(t *testing.T) {
	dir := serviceEnv(t)
	home := filepath.Join(dir, "home")
	if got := findClaude(home); got != "" {
		t.Fatalf("found %q with no claude anywhere", got)
	}
	data := executable(t, dataHomeClaude)
	if got := findClaude(home); got != data {
		t.Fatalf("got %q, want the add-on's %q", got, data)
	}
	inHome := executable(t, filepath.Join(home, ".local", "bin", "claude"))
	if got := findClaude(home); got != inHome {
		t.Fatalf("got %q, want the home's %q", got, inHome)
	}
	onPath := executable(t, filepath.Join(dir, "path", "claude"))
	if got := findClaude(home); got != onPath {
		t.Fatalf("got %q, want PATH's %q", got, onPath)
	}
	// Not executable does not count.
	if err := os.Chmod(onPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := findClaude(home); got != inHome {
		t.Fatalf("got %q with PATH's claude not executable", got)
	}
}

func TestListenerHome(t *testing.T) {
	for _, c := range []struct{ set, claude, want string }{
		{"/explicit", "/data/home/.local/bin/claude", "/explicit"},
		{"", "/data/home/.local/bin/claude", "/data/home"},
		{"", "/.local/bin/claude", "/"},
		{"", "/usr/bin/claude", ""},
		{"", "", ""},
	} {
		if got := listenerHome(c.set, c.claude); got != c.want {
			t.Errorf("listenerHome(%q, %q) = %q, want %q", c.set, c.claude, got, c.want)
		}
	}
}

// With claude found in the add-on's home, the listener runs requests with
// that HOME; with none, it runs without --claude and the log says why.
func TestServiceClaudeAuto(t *testing.T) {
	dir := serviceEnv(t)
	cfg := writeFile(t, filepath.Join(dir, "peer.json"), `{"hub":"http://x:7790"}`)
	got := captureService(t)
	if r := peerCmd("", serviceArgs(dir, "--config", cfg)...); r.code != 0 || got.sup == nil {
		t.Fatalf("service: %+v", r)
	}
	if slices.Contains(got.sup.args, "--claude") || envValue(got.sup.env, "HOME") != filepath.Join(dir, "home") {
		t.Fatalf("args %q HOME %q without a claude", got.sup.args, envValue(got.sup.env, "HOME"))
	}
	if log, _ := os.ReadFile(filepath.Join(dir, "peer.log")); !strings.Contains(string(log), "service starting without runs") {
		t.Fatalf("log does not say runs are off:\n%s", log)
	}

	claude := executable(t, dataHomeClaude)
	got = captureService(t)
	if r := peerCmd("", serviceArgs(dir, "--config", cfg)...); r.code != 0 || got.sup == nil {
		t.Fatalf("service: %+v", r)
	}
	if i := slices.Index(got.sup.args, "--claude"); i < 0 || got.sup.args[i+1] != claude {
		t.Fatalf("args %q", got.sup.args)
	}
	if h := envValue(got.sup.env, "HOME"); h != filepath.Join(dir, "data", "home") {
		t.Fatalf("HOME %q, want the home that owns claude", h)
	}
}

// Without --foreground the command re-execs itself detached, handing it the
// lock, and returns; with it, it supervises in this process.
func TestServiceDetachAndForeground(t *testing.T) {
	dir := serviceEnv(t)
	cfg := writeFile(t, filepath.Join(dir, "peer.json"), `{"hub":"http://x:7790"}`)
	lock, logPath := filepath.Join(dir, "peer.lock"), filepath.Join(dir, "peer.log")

	got := captureService(t)
	r := peerCmd("", "service", "--config", cfg, "--lock", lock, "--log", logPath)
	if r.code != 0 || got.sup != nil || !strings.Contains(r.out, "peer service started (pid 4242)") {
		t.Fatalf("detach: %+v supervised in process: %v", r, got.sup != nil)
	}
	self, _ := selfPath()
	want := []string{"service", "--config", cfg, "--lock", lock, "--log", logPath, "--foreground", "--lock-fd", "3"}
	if got.exe != self || !slices.Equal(got.detached, want) {
		t.Fatalf("re-exec %q %q, want %q %q", got.exe, got.detached, self, want)
	}
	if pid, _ := os.ReadFile(lock); strings.TrimSpace(string(pid)) != "4242" {
		t.Errorf("lock holds %q, want the supervisor's pid", pid)
	}

	got = captureService(t)
	if r := peerCmd("", "service", "--foreground", "--config", cfg, "--lock", lock, "--log", logPath); r.code != 0 || got.sup == nil || got.detached != nil {
		t.Fatalf("foreground: %+v detached %q", r, got.detached)
	}
	if pid, _ := os.ReadFile(lock); strings.TrimSpace(string(pid)) != strconv.Itoa(os.Getpid()) {
		t.Errorf("lock holds %q, want this pid", pid)
	}
	if r := peerCmd("", "service", "--config", cfg, "--lock", lock, "--log", "-"); r.code != 1 {
		t.Fatalf("detached with --log -: %+v", r)
	}
}

// A second service exits 0 while the lock is held, naming the holder.
func TestServiceSingleInstance(t *testing.T) {
	dir := serviceEnv(t)
	cfg := writeFile(t, filepath.Join(dir, "peer.json"), `{"hub":"http://x:7790"}`)
	lockPath := filepath.Join(dir, "peer.lock")
	held, err := acquireLock(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	writeLockPID(held, 777)
	var lhe *lockHeldError
	if _, err := acquireLock(lockPath); !errors.As(err, &lhe) || lhe.pid != "777" {
		t.Fatalf("second lock: %v", err)
	}
	got := captureService(t)
	for _, fg := range []bool{true, false} {
		args := []string{"service", "--config", cfg, "--lock", lockPath, "--log", filepath.Join(dir, "peer.log")}
		if fg {
			args = append(args, "--foreground")
		}
		r := peerCmd("", args...)
		if r.code != 0 || !strings.Contains(r.out, "already running (pid 777") || got.sup != nil || got.detached != nil {
			t.Fatalf("foreground %v with the lock held: %+v", fg, r)
		}
	}
	held.Close()
	if f, err := acquireLock(lockPath); err != nil {
		t.Fatalf("lock after release: %v", err)
	} else {
		f.Close()
	}
}

func TestRotatingLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peer.log")
	l, err := openRotatingLog(path, 100)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	_, _ = l.Write([]byte(strings.Repeat("a", 100)))
	l.rotate() // at the threshold, not past it
	if _, err := os.Stat(path + ".1"); err == nil {
		t.Fatal("rotated at the threshold")
	}
	_, _ = l.Write([]byte("b\n"))
	l.rotate()
	_, _ = l.Write([]byte("after\n"))
	old, _ := os.ReadFile(path + ".1")
	cur, _ := os.ReadFile(path)
	if len(old) != 102 || string(cur) != "after\n" {
		t.Fatalf("after rotation: .1 has %d bytes, the log %q", len(old), cur)
	}
}

func TestBackoff(t *testing.T) {
	b := backoff{min: 5 * time.Second, max: 5 * time.Minute, reset: 5 * time.Minute}
	var got []time.Duration
	for range 8 {
		got = append(got, b.next(time.Second))
	}
	want := []time.Duration{5, 10, 20, 40, 80, 160, 300, 300}
	for i := range want {
		want[i] *= time.Second
	}
	if !slices.Equal(got, want) {
		t.Fatalf("backoff %v, want %v", got, want)
	}
	if d := b.next(6 * time.Minute); d != 5*time.Second {
		t.Fatalf("after a long run %s, want 5s", d)
	}
	if d := b.next(time.Second); d != 10*time.Second {
		t.Fatalf("after the reset %s, want 10s", d)
	}
}

// testSupervisor runs script with sh as the listener, logging to dir.
func testSupervisor(t *testing.T, dir, script string) (*supervisor, string) {
	t.Helper()
	logPath := filepath.Join(dir, "peer.log")
	out, err := openRotatingLog(logPath, serviceLogMax)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { out.Close() })
	return &supervisor{
		exe: "/bin/sh", args: []string{"-c", script}, env: append(os.Environ(), "DIR="+dir), out: out,
		log:     slog.New(slog.NewTextHandler(out, nil)),
		backoff: backoff{min: 20 * time.Millisecond, max: 80 * time.Millisecond, reset: time.Hour},
	}, logPath
}

// A listener that exits non-zero is restarted with a doubling backoff; one
// that exits superseded (3) is not, and the supervisor returns.
func TestSupervisorRestartsUntilSuperseded(t *testing.T) {
	dir := t.TempDir()
	s, logPath := testSupervisor(t, dir, `
n=$(cat "$DIR/n" 2>/dev/null || echo 0); n=$((n+1)); echo $n > "$DIR/n"
date +%s%N >> "$DIR/starts"
echo "listener run $n"
[ "$n" -ge 4 ] && exit 3
exit 1`)
	done := make(chan error, 1)
	go func() { done <- s.run(context.Background()) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the supervisor did not stop on exit 3")
	}
	data, _ := os.ReadFile(filepath.Join(dir, "starts"))
	var starts []int64
	for _, f := range strings.Fields(string(data)) {
		n, _ := strconv.ParseInt(f, 10, 64)
		starts = append(starts, n)
	}
	if len(starts) != 4 {
		t.Fatalf("%d starts, want 4", len(starts))
	}
	for i, least := range []time.Duration{20 * time.Millisecond, 40 * time.Millisecond, 80 * time.Millisecond} {
		if gap := time.Duration(starts[i+1] - starts[i]); gap < least {
			t.Errorf("restart %d after %s, want at least %s", i+1, gap, least)
		}
	}
	log, _ := os.ReadFile(logPath)
	for _, want := range []string{"listener run 1", "listener run 4", "listener exited; restarting", "exit=1", "superseded"} {
		if !strings.Contains(string(log), want) {
			t.Errorf("log lacks %q:\n%s", want, log)
		}
	}
}

// Stopping the supervisor stops the listener (SIGTERM) and returns.
func TestSupervisorStopsListener(t *testing.T) {
	dir := t.TempDir()
	s, logPath := testSupervisor(t, dir, `trap 'echo got TERM; exit 0' TERM; echo $$ > "$DIR/pid"; while :; do sleep 0.05; done`)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.run(ctx) }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(dir, "pid")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the listener did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the supervisor did not stop")
	}
	if log, _ := os.ReadFile(logPath); !strings.Contains(string(log), "got TERM") || !strings.Contains(string(log), "service stopped") {
		t.Fatalf("log:\n%s", log)
	}
}

// End to end: `peer service` returns while a detached supervisor runs the
// real listener against a hub; a second one sees it running; SIGTERM stops
// both.
func TestServiceDetachedEndToEnd(t *testing.T) {
	dir := serviceEnv(t)
	t.Setenv("PEERCLIENT_HELPER", "peer") // the detached test binary runs the CLI
	ha := hubtest.New(t).Serve(haCaller)
	cfg := writeFile(t, filepath.Join(dir, "peer.json"), `{"hub":"`+ha.URL()+`","log":"peer.log"}`)
	lock, logPath := filepath.Join(dir, "peer.lock"), filepath.Join(dir, "peer.log")
	args := []string{"service", "--config", cfg, "--lock", lock}

	r := peerCmd("", args...)
	if r.code != 0 || !strings.Contains(r.out, "peer service started") {
		t.Fatalf("service: %+v", r)
	}
	data, _ := os.ReadFile(lock)
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatalf("lock %q", data)
	}
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })

	waitLog := func(want string) {
		t.Helper()
		deadline := time.Now().Add(20 * time.Second)
		for {
			log, _ := os.ReadFile(logPath)
			if strings.Contains(string(log), want) {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("log lacks %q:\n%s", want, log)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	waitLog("hub stream open")
	if r := peerCmd("", args...); r.code != 0 || !strings.Contains(r.out, "already running (pid "+strconv.Itoa(pid)) {
		t.Fatalf("second service: %+v", r)
	}

	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	waitLog("service stopped")
	// This test process is the supervisor's parent (`peer service` ran in
	// it), so it reaps it; on the add-on the parent has exited.
	exited := make(chan syscall.WaitStatus, 1)
	go func() {
		var ws syscall.WaitStatus
		_, _ = syscall.Wait4(pid, &ws, 0, nil)
		exited <- ws
	}()
	select {
	case ws := <-exited:
		if ws.ExitStatus() != 0 {
			t.Errorf("supervisor exit status %d", ws.ExitStatus())
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the supervisor is still running after SIGTERM")
	}
	if f, err := acquireLock(lock); err != nil {
		t.Fatalf("lock still held: %v", err)
	} else {
		f.Close()
	}
}
