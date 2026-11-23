package peerclient

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

// ErrSuperseded ends a listener: a newer instance for this host said hello.
var ErrSuperseded = errors.New("a newer listener instance holds this host")

// ErrUpgraded ends a listener: UpgradeWatch resolves to a newer peer binary
// and no run was claimed or running.
var ErrUpgraded = errors.New("a newer peer binary is installed")

// upgradeCheckEvery is how often UpgradeWatch is checked (and after every
// run) when Listener.UpgradeCheckEvery is zero.
const upgradeCheckEvery = 30 * time.Second

// Listener defaults.
const (
	DefaultMinBackoff  = time.Second
	DefaultMaxBackoff  = time.Minute
	DefaultIdleTimeout = 65 * time.Second // three missed 20 s pings
)

// Listener keeps one host's stream open: hello on every (re)connect, hand
// each message off once, acknowledge it, reconnect with capped exponential
// backoff. The hub keeps the acknowledged high-water mark and replays from
// the larger of it and the cursor, so nothing is stored locally.
//
// With Runs set it also runs the requests pushed to this host, one at a time,
// once the canary has proved the gate; the runs outlive a dropped stream.
// Every (re)connect first posts the outbox, then says hello reporting the run
// in progress (a claim in flight included), every request whose report is
// still in the outbox, and whether the gate is unverified; the hello's cancel
// list stops that run and drops those reports. A change of the gate state
// says hello again. Without Runs, request frames are ignored.
type Listener struct {
	Client *Client
	// Instance is this process's listener id; StartedAt its start. The
	// newest StartedAt for a host wins.
	Instance  string
	StartedAt time.Time
	// Deliver hands a message off. Once it returns nil the message is
	// acknowledged; an error reconnects without acknowledging.
	Deliver func(Message) error
	// OnHello, when set, sees the identity from every successful hello.
	OnHello func(Identity)
	// Runs, when set, enables request runs on this host.
	Runs *Runs
	// UpgradeWatch, when set, is the installed peer binary, a symlink (on
	// NixOS /run/current-system/sw/bin/peer). Once it resolves to another
	// file than this process's executable and no run is claimed or running,
	// the listener stops claiming and Run returns ErrUpgraded, so its
	// supervisor starts the new binary. A run in progress is never
	// interrupted: the check repeats when it ends.
	UpgradeWatch string
	// UpgradeCheckEvery is how often UpgradeWatch is checked (and after
	// every run); zero is 30 s.
	UpgradeCheckEvery time.Duration
	// Version is sent in every hello: the commit this binary was built from.
	Version string
	Log     *slog.Logger

	MinBackoff, MaxBackoff, IdleTimeout time.Duration
}

// NewInstance returns a random listener instance id.
func NewInstance() string { return "listen-" + NewID() }

// Run listens until ctx ends (nil) or a newer instance supersedes this one
// (ErrSuperseded).
func (l *Listener) Run(ctx context.Context) error {
	minB, maxB := l.MinBackoff, l.MaxBackoff
	if minB <= 0 {
		minB = DefaultMinBackoff
	}
	if maxB < minB {
		maxB = max(DefaultMaxBackoff, minB)
	}
	log := l.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	// The upgrade watch ends the listener by cancelling ctx with ErrUpgraded.
	ctx, stop := context.WithCancelCause(ctx)
	defer stop(nil)
	stopped := func() error {
		if errors.Is(context.Cause(ctx), ErrUpgraded) {
			return ErrUpgraded
		}
		return nil
	}
	s := &session{l: l, log: log}
	if l.Runs != nil {
		s.runs = newRunner(*l.Runs, l.Client, l.Instance, log)
		rctx, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() { defer close(done); s.runs.loop(rctx) }()
		// A run in progress is stopped (and its result posted) before Run
		// returns.
		defer func() { cancel(); <-done }()
	}
	if l.UpgradeWatch != "" {
		go l.watchUpgrade(ctx, s.runs, log, stop)
	}
	backoff := minB
	for {
		opened := false
		err := s.run(ctx, func() { opened = true })
		if ctx.Err() != nil {
			return stopped()
		}
		if IsProblem(err, CodeSuperseded) {
			log.Warn("superseded; exiting", "instance", l.Instance)
			return ErrSuperseded
		}
		if opened {
			backoff = minB
		}
		log.Warn("hub stream ended; reconnecting", "error", err, "retry_in", backoff.String())
		select {
		case <-ctx.Done():
			return stopped()
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, maxB)
	}
}

// watchUpgrade checks UpgradeWatch every UpgradeCheckEvery and after every
// run. Once it resolves to another binary than this one and runs (nil
// without Runs) has nothing claimed or running, runs stops claiming and
// stop ends the listener with ErrUpgraded.
func (l *Listener) watchUpgrade(ctx context.Context, runs *runner, log *slog.Logger, stop context.CancelCauseFunc) {
	self, err := os.Executable()
	if err == nil {
		self, err = filepath.EvalSymlinks(self)
	}
	if err != nil {
		log.Warn("not watching for a newer peer: locating this binary failed", "error", err)
		return
	}
	var ended <-chan struct{} // nil without runs: never ready
	if runs != nil {
		ended = runs.ended
	}
	every := l.UpgradeCheckEvery
	if every <= 0 {
		every = upgradeCheckEvery
	}
	tick := time.NewTicker(every)
	defer tick.Stop()
	warned := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		case <-ended:
		}
		installed, err := filepath.EvalSymlinks(l.UpgradeWatch)
		if err != nil {
			if !warned {
				log.Warn("cannot read the installed peer; not restarting on upgrade", "path", l.UpgradeWatch, "error", err)
				warned = true
			}
			continue
		}
		if installed == self || (runs != nil && !runs.stopIfIdle()) {
			continue
		}
		log.Info("newer peer installed; restarting to load it", "running", self, "installed", installed)
		stop(ErrUpgraded)
		return
	}
}

// errGateFlipped ends a stream so the next hello reports the new gate state.
var errGateFlipped = errors.New("the run gate changed; saying hello again")

// session is the state that outlives one connection: the cursor (highest
// sequence handed off) and the highest sequence the hub acknowledged.
type session struct {
	l           *Listener
	log         *slog.Logger
	runs        *runner // nil without Runs
	last, acked int64
}

func (s *session) run(ctx context.Context, opened func()) error {
	l := s.l
	hello := Hello{Instance: l.Instance, StartedAt: l.StartedAt, Version: l.Version}
	if s.runs != nil {
		// Reports first: the hub judges the lease on this hello, and a
		// report it takes now needs no lease.
		s.runs.flush(ctx)
		hello.Runs = s.runs.active()
		hello.GateUnverified = s.runs.unverified()
	}
	id, err := l.Client.Hello(ctx, hello)
	if err != nil {
		return fmt.Errorf("hello: %w", err)
	}
	if l.OnHello != nil {
		l.OnHello(id)
	}
	var onRequest func(RequestFrame) error
	streamCtx := ctx
	if s.runs != nil {
		s.runs.cancelRuns(id.Cancel)
		onRequest = func(f RequestFrame) error { s.runs.push(f); return nil }
		var cancel context.CancelCauseFunc
		streamCtx, cancel = context.WithCancelCause(ctx)
		defer cancel(nil)
		go func() {
			select {
			case <-s.runs.flipped:
				cancel(errGateFlipped)
			case <-streamCtx.Done():
			}
		}()
	}
	// A message handed off whose ack failed is acknowledged now.
	if s.last > s.acked {
		if err := l.Client.Ack(ctx, l.Instance, s.last); err != nil {
			return fmt.Errorf("ack: %w", err)
		}
		s.acked = s.last
	}
	idle := l.IdleTimeout
	if idle <= 0 {
		idle = DefaultIdleTimeout
	}
	connected := func() {
		opened()
		s.log.Info("hub stream open", "host", id.Host, "instance", l.Instance, "after", s.last)
	}
	err = l.Client.Stream(streamCtx, l.Instance, s.last, idle, connected, func(m Message) error {
		if m.Seq <= s.last {
			s.log.Debug("dropping duplicate delivery", "seq", m.Seq)
			return nil
		}
		if err := l.Deliver(m); err != nil {
			return fmt.Errorf("handing off message %d: %w", m.Seq, err)
		}
		s.last = m.Seq
		if err := l.Client.Ack(ctx, l.Instance, m.Seq); err != nil {
			return fmt.Errorf("ack: %w", err)
		}
		s.acked = m.Seq
		return nil
	}, onRequest)
	if cause := context.Cause(streamCtx); errors.Is(cause, errGateFlipped) {
		return cause
	}
	if err == nil {
		return errors.New("hub closed the stream")
	}
	return err
}
