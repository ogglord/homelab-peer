package peerclient_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ogglord/homelab-peer/internal/peer"
	"github.com/ogglord/homelab-peer/internal/peerclient"
)

// pointAt makes link a symlink to target, replacing it atomically as a
// system switch does.
func pointAt(t *testing.T, link, target string) {
	t.Helper()
	tmp := link + ".new"
	if err := os.Symlink(target, tmp); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, link); err != nil {
		t.Fatal(err)
	}
}

// installedPeer is a stand-in for /run/current-system/sw/bin/peer pointing
// at this test binary, the listener's own executable.
func installedPeer(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "peer")
	pointAt(t, link, exe)
	return link
}

// newerPeer is another peer binary, as a switch installs.
func newerPeer(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "peer")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// upgradeListener is a run listener watching watch, checking every 20 ms.
func upgradeListener(t *testing.T, watch string, steps ...string) *runListener {
	t.Helper()
	r := newRunListener(t, nil, steps...)
	r.l.UpgradeWatch, r.l.UpgradeCheckEvery = watch, 20*time.Millisecond
	r.start(t)
	return r
}

// While the installed peer is this binary the listener keeps running; once
// it points at another and no run is in progress, Run returns ErrUpgraded.
func TestListenerRestartsOnUpgradeWhenIdle(t *testing.T) {
	t.Parallel()
	link := installedPeer(t)
	r := upgradeListener(t, link, done)
	r.eventually(t, "the gate to be verified", func() bool { return strings.Contains(r.logs.String(), "gate verified") })
	if ok, err := r.exited(200 * time.Millisecond); ok {
		t.Fatalf("returned %v while the installed peer is this binary", err)
	}
	newer := newerPeer(t)
	pointAt(t, link, newer)
	ok, err := r.exited(5 * time.Second)
	if !ok || !errors.Is(err, peerclient.ErrUpgraded) {
		t.Fatalf("returned %v (%v), want ErrUpgraded\nlog:\n%s", err, ok, r.logs.String())
	}
	if log := r.logs.String(); !strings.Contains(log, "newer peer installed; restarting to load it") || !strings.Contains(log, newer) {
		t.Fatalf("log:\n%s", log)
	}
}

// A newer peer installed during a run waits for the run to end and report;
// then the listener returns ErrUpgraded.
func TestListenerUpgradeWaitsForTheRun(t *testing.T) {
	t.Parallel()
	link := installedPeer(t)
	r := upgradeListener(t, link, `{"sleep":"2s"}`, done)
	r.hub.Request(homelabCaller, "req-up", "homeassistant", "list your add-ons")
	r.eventually(t, "the request to run", func() bool { return r.hub.Get("req-up").State == peer.ReqRunning })
	pointAt(t, link, newerPeer(t))
	if ok, err := r.exited(500 * time.Millisecond); ok {
		t.Fatalf("returned %v during the run", err)
	}
	ok, err := r.exited(20 * time.Second)
	if !ok || !errors.Is(err, peerclient.ErrUpgraded) {
		t.Fatalf("returned %v (%v), want ErrUpgraded\nlog:\n%s", err, ok, r.logs.String())
	}
	if got := r.hub.Get("req-up"); got.State != peer.ReqDone {
		t.Fatalf("request %s %s, want the run's result reported first", got.State, got.Reason)
	}
}

// An unreadable watch path is logged once and never restarts the listener.
func TestListenerUpgradeWatchMissing(t *testing.T) {
	t.Parallel()
	r := upgradeListener(t, filepath.Join(t.TempDir(), "absent"), done)
	const line = "cannot read the installed peer"
	r.eventually(t, "the unreadable path logged", func() bool { return strings.Contains(r.logs.String(), line) })
	if ok, err := r.exited(200 * time.Millisecond); ok {
		t.Fatalf("returned %v with no installed peer", err)
	}
	if n := strings.Count(r.logs.String(), line); n != 1 {
		t.Fatalf("logged %d times, want once:\n%s", n, r.logs.String())
	}
}
