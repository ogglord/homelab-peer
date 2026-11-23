package peerclient

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"
)

// Runs turns the requests pushed to this host into headless runs. A
// Listener without Runs only receives messages.
type Runs struct {
	// Launcher starts each run. The listener sets its Hub to this client's
	// run operations and adds PEER_HUB_URL to its Env, so the run's peer
	// commands and its park hook reach the same hub.
	Launcher Launcher
	// Checkout, when set, is the git checkout each request runs in a
	// worktree of: RunsDir/<request>, made at the checkout's HEAD on the
	// request's first run, kept across its resumes and removed when it
	// ends. Without it runs use Launcher.Dir.
	Checkout string
	// RunsDir holds one entry per request in progress (RunsDirName): its
	// worktree, or an empty marker without a checkout, so the listener can
	// delete the request's worktree and Claude session once the hub ends
	// it. Required with Checkout; empty keeps no record.
	RunsDir string
	// Outbox holds results and parks the hub has not taken yet.
	Outbox *Outbox
	// CanaryRetry is the wait before the canary runs again after an
	// inconclusive result; it doubles up to MaxCanaryRetry. Zero means
	// DefaultCanaryRetry.
	CanaryRetry time.Duration
}

// resultPostTimeout bounds one result post when the listener is stopping.
const resultPostTimeout = 30 * time.Second

// sweepEvery is how often an idle listener asks the hub about the requests
// it keeps a worktree or session for (one parked, then denied or expired,
// gets no frame).
const sweepEvery = 10 * time.Minute

// Canary retry backoff while the gate is unverified.
const (
	DefaultCanaryRetry = time.Minute
	MaxCanaryRetry     = 15 * time.Minute
)

// gate is the canary's verdict.
type gate int

const (
	gatePending gate = iota
	gateVerified
	gateUnverified
)

// runner executes pushed requests one at a time per host: frames queue
// in arrival order, the head is claimed at its frame's attempt, and a claim
// the hub refuses (busy, not claimable) is dropped until the next push.
type runner struct {
	cfg      Runs
	launcher Launcher
	client   *Client
	hub      HubRunAPI
	instance string
	log      *slog.Logger

	mu        sync.Mutex
	queue     []RequestFrame
	wake      chan struct{}
	gate      gate
	flipped   chan struct{} // signalled when unverified() changes
	current   RequestFrame  // frame claimed or running; zero ID when idle
	cancel    context.CancelFunc
	cancelled bool
	ended     chan struct{} // signalled when a run (or refused claim) ends
	stopping  bool          // nothing more is claimed: the listener restarts
}

func newRunner(cfg Runs, client *Client, instance string, log *slog.Logger) *runner {
	hub := client.RunAPI()
	l := cfg.Launcher
	l.Env = append(slices.Clone(l.Env), EnvHubURL+"="+client.Base())
	if l.Log == nil {
		l.Log = log
	}
	return &runner{cfg: cfg, launcher: l, client: client, hub: hub, instance: instance, log: log,
		wake: make(chan struct{}, 1), flipped: make(chan struct{}, 1), ended: make(chan struct{}, 1)}
}

// push queues a pushed request frame. A frame for the request already
// claimed or running is a repeat unless it is newer than the one that run
// started from: an approval can arrive while the run that parked is still
// winding down (the hook reports the park first), and that frame runs once
// the current run ends. A frame for a request already queued replaces it
// unless it is older. Once the gate is unverified nothing is queued: the
// request stays on the hub, unclaimed, until it expires or another listener
// takes it.
func (r *runner) push(f RequestFrame) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if f.ID == r.current.ID && !newerFrame(f, r.current) {
		return
	}
	if r.gate == gateUnverified {
		r.log.Warn("not claiming request: the gate is unverified on this host", "request", f.ID, "sender", f.Sender)
		return
	}
	if i := slices.IndexFunc(r.queue, func(q RequestFrame) bool { return q.ID == f.ID }); i >= 0 {
		if !newerFrame(r.queue[i], f) {
			r.queue[i] = f
		}
		return
	}
	r.queue = append(r.queue, f)
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

// newerFrame reports whether f moved its request on from was: a later
// attempt or approval cycle, or an approval of the same attempt.
func newerFrame(f, was RequestFrame) bool {
	switch {
	case f.Attempt != was.Attempt:
		return f.Attempt > was.Attempt
	case f.ApprovalCycles != was.ApprovalCycles:
		return f.ApprovalCycles > was.ApprovalCycles
	default:
		return f.State == StateApproved && was.State != StateApproved
	}
}

// active is the lease report for hello: the request claimed or running,
// and every request whose result or park is still in the outbox.
func (r *runner) active() []string {
	r.mu.Lock()
	current := r.current.ID
	r.mu.Unlock()
	ids := r.cfg.Outbox.Pending()
	if current != "" && !slices.Contains(ids, current) {
		ids = append(ids, current)
	}
	return ids
}

// unverified is the gate state hello reports.
func (r *runner) unverified() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.gate == gateUnverified
}

// cancelRuns stops the current run when the hub no longer holds it, and
// drops the outbox reports for requests it no longer holds (it would refuse
// them).
func (r *runner) cancelRuns(ids []string) {
	if len(ids) == 0 {
		return
	}
	r.cfg.Outbox.Drop(ids)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.current.ID != "" && slices.Contains(ids, r.current.ID) {
		r.log.Warn("the hub no longer holds this run; cancelling it", "request", r.current.ID)
		r.cancelled = true
		r.cancel()
	}
}

// flush posts the outbox's stored reports (on every reconnect, before the
// hello).
func (r *runner) flush(ctx context.Context) {
	left, err := r.cfg.Outbox.Flush(ctx, r.hub)
	if err != nil || left > 0 {
		r.log.Warn("reports left in the outbox", "left", left, "error", err)
	}
}

// setGate records the canary's verdict. An unverified gate drops the queue
// (nothing is claimed); a change of unverified() signals flipped, so the
// listener says hello again.
func (r *runner) setGate(g gate) {
	r.mu.Lock()
	defer r.mu.Unlock()
	was := r.gate == gateUnverified
	r.gate = g
	if g == gateUnverified {
		for _, f := range r.queue {
			r.log.Warn("not claiming request: the gate is unverified on this host", "request", f.ID, "sender", f.Sender)
		}
		r.queue = nil
	}
	if was != (g == gateUnverified) {
		select {
		case r.flipped <- struct{}{}:
		default:
		}
	}
}

// loop proves the gate, then runs queued requests until ctx ends.
func (r *runner) loop(ctx context.Context) {
	if !r.proveGate(ctx) {
		return
	}
	r.sweep(ctx)
	tick := time.NewTicker(sweepEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			r.sweep(ctx)
			continue
		case <-r.wake:
		}
		for ctx.Err() == nil {
			f, runCtx, ok := r.next(ctx)
			if !ok {
				break
			}
			r.handle(runCtx, f)
			r.done()
		}
	}
}

// proveGate runs the canary until it verifies the gate (true), proves it
// broken or ctx ends (false). While the canary is inconclusive the gate is
// unverified, nothing is claimed, and the canary runs again on a capped
// backoff; a broken gate stays unverified until the listener restarts.
func (r *runner) proveGate(ctx context.Context) bool {
	retry := r.cfg.CanaryRetry
	if retry <= 0 {
		retry = DefaultCanaryRetry
	}
	for {
		err := r.canary(ctx)
		if err == nil {
			r.setGate(gateVerified)
			r.log.Info("gate verified: the hook's deny blocks and a classifier block reaches the denied hook")
			return true
		}
		r.setGate(gateUnverified)
		if ctx.Err() != nil {
			return false
		}
		if errors.Is(err, ErrGateBroken) {
			r.log.Error("gate unverified: the canary proved it broken; no requests will be claimed until the listener restarts", "error", err)
			return false
		}
		r.log.Error("gate unverified: the canary was inconclusive; no requests will be claimed until it passes", "error", err, "retry_in", retry.String())
		select {
		case <-ctx.Done():
			return false
		case <-time.After(retry):
		}
		retry = min(retry*2, MaxCanaryRetry)
	}
}

// canary runs the gate proof where a request would run: a fresh worktree of
// the checkout (RunsDir/.canary, removed after), else Launcher.Dir.
func (r *runner) canary(ctx context.Context) error {
	l := r.launcher
	if r.cfg.Checkout != "" {
		l.Dir = filepath.Join(r.cfg.RunsDir, canaryDirName)
		_ = RemoveRunWorktree(ctx, r.cfg.Checkout, l.Dir) // a stale one from a killed listener
		if err := PrepareRunWorktree(ctx, r.cfg.Checkout, l.Dir); err != nil {
			return fmt.Errorf("preparing the canary worktree: %w", err)
		}
		defer func() {
			if err := RemoveRunWorktree(context.WithoutCancel(ctx), r.cfg.Checkout, l.Dir); err != nil {
				r.log.Warn("removing the canary worktree failed", "error", err)
			}
		}()
	}
	_, err := Canary(ctx, l, "")
	return err
}

// canaryDirName is the canary's worktree under RunsDir; no request's
// (runDirName never starts with a dot).
const canaryDirName = ".canary"

// runDir is the working directory of request id's runs: its worktree with a
// checkout (created on its first run), else Launcher.Dir with an empty
// marker in RunsDir, so the sweep finds the request.
func (r *runner) runDir(ctx context.Context, id string) (string, error) {
	if r.cfg.RunsDir == "" {
		return r.launcher.Dir, nil
	}
	entry := filepath.Join(r.cfg.RunsDir, runDirName(id))
	if r.cfg.Checkout != "" {
		return entry, PrepareRunWorktree(ctx, r.cfg.Checkout, entry)
	}
	return r.launcher.Dir, os.MkdirAll(entry, 0o700)
}

// finish deletes what request id kept on this host once it has ended: its
// Claude session (transcript included: it holds every value the run was
// handed) and its worktree or marker.
func (r *runner) finish(ctx context.Context, id string) {
	dir := r.launcher.Dir
	entry := ""
	if r.cfg.RunsDir != "" {
		entry = filepath.Join(r.cfg.RunsDir, runDirName(id))
		if r.cfg.Checkout != "" {
			dir = entry
		}
	}
	err := r.launcher.Forget(dir, id)
	if entry != "" {
		if r.cfg.Checkout != "" {
			err = errors.Join(err, RemoveRunWorktree(ctx, r.cfg.Checkout, entry))
		} else {
			err = errors.Join(err, os.RemoveAll(entry))
		}
	}
	if err != nil {
		r.log.Warn("cleaning up after the request failed", "request", id, "error", err)
	}
}

// sweep asks the hub about every request with an entry in RunsDir but the
// one running, and finishes those that ended (or that the hub no longer
// knows). One the hub cannot answer for now stays until the next sweep.
func (r *runner) sweep(ctx context.Context) {
	if r.cfg.RunsDir == "" {
		return
	}
	entries, err := os.ReadDir(r.cfg.RunsDir)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			r.log.Warn("listing the runs directory failed", "error", err)
		}
		return
	}
	for _, e := range entries {
		id := runIDOf(e.Name())
		r.mu.Lock()
		busy := id == r.current.ID || slices.ContainsFunc(r.queue, func(f RequestFrame) bool { return f.ID == id })
		r.mu.Unlock()
		if id == "" || busy || ctx.Err() != nil {
			continue
		}
		req, err := r.client.Wait(ctx, id, 0)
		if err == nil && !req.Terminal() {
			continue
		}
		if err != nil && !IsProblem(err, "unknown_request") {
			continue
		}
		r.log.Info("request ended; removing its worktree and session", "request", id, "state", req.State)
		r.finish(ctx, id)
	}
}

// next pops the head of the queue and marks it current before the claim, so
// a hello in between reports the claim in flight.
func (r *runner) next(ctx context.Context) (RequestFrame, context.Context, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.queue) == 0 || r.stopping {
		return RequestFrame{}, nil, false
	}
	f := r.queue[0]
	r.queue = r.queue[1:]
	runCtx, cancel := context.WithCancel(ctx)
	r.current, r.cancel, r.cancelled = f, cancel, false
	return f, runCtx, true
}

func (r *runner) done() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cancel()
	r.current, r.cancel, r.cancelled = RequestFrame{}, nil, false
	select {
	case r.ended <- struct{}{}:
	default:
	}
}

// stopIfIdle stops claiming and reports true when nothing is claimed or
// running (a parked request holds no run); false leaves the runner as is.
func (r *runner) stopIfIdle() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.current.ID != "" {
		return false
	}
	r.stopping = true
	return true
}

func (r *runner) wasCancelled() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cancelled
}

// handle claims one request, runs it and reports its outcome, a park or a
// done or failed result, through the outbox.
func (r *runner) handle(ctx context.Context, f RequestFrame) {
	log := r.log.With("request", f.ID, "sender", f.Sender)
	claim, err := r.client.Claim(ctx, f.ID, f.Attempt, r.instance)
	if err != nil {
		if IsProblem(err, CodeBusy) || IsProblem(err, CodeNotClaimable) {
			log.Info("not claimed; waiting for the next push", "attempt", f.Attempt, "error", err)
		} else {
			log.Warn("claim failed", "attempt", f.Attempt, "error", err)
		}
		return
	}
	req := claim.Request
	ref := RunRef{RequestID: req.ID, Attempt: int(req.Attempt), Instance: r.instance, Token: claim.RunToken}
	log.Info("claimed", "attempt", ref.Attempt, "remaining_usd", claim.RemainingUSD, "remaining_seconds", claim.RemainingSeconds)

	env := Envelope{RequestID: req.ID, Sender: req.Sender}
	if req.ParentID != nil {
		env.Parent = *req.ParentID
	}
	switch {
	case f.StepHash != nil && *f.StepHash != "":
		env.ApprovedStep = stepHashPrefix + *f.StepHash // the hook's StepHash form
		if req.Step != nil {
			env.ApprovedStepText = *req.Step
		}
	case f.State == StateApproved && req.ParkKind != nil && *req.ParkKind == ParkLimit:
		env.LimitApproved = true
	}

	var o Outcome
	if claim.RemainingUSD <= 0 || claim.RemainingSeconds <= 0 {
		// Nothing left to run on: ask for more instead of starting.
		reason := "the request's cost or time allowance is used up"
		o = Outcome{State: RunParked, Reason: reason, Park: &ParkRecord{Kind: ParkLimit, Reason: reason, At: time.Now().UTC()}}
	} else if dir, err := r.runDir(ctx, req.ID); err != nil {
		o = Outcome{State: RunFailed, Code: ReasonRunFailed, Reason: "preparing the run worktree: " + err.Error()}
	} else {
		o = r.launcher.Run(ctx, RunSpec{
			Ref: ref, Envelope: env, Text: req.Text, Dir: dir,
			BudgetUSD: claim.RemainingUSD, Deadline: time.Duration(claim.RemainingSeconds) * time.Second,
		})
	}
	if r.wasCancelled() {
		log.Info("run cancelled by the hub; no result posted", "outcome", o.State)
		return
	}

	// Report even when the listener is stopping: the hub is still there.
	pctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), resultPostTimeout)
	defer cancel()
	if o.State == RunParked {
		// A step park was reported by the hook already unless the hub was
		// unreachable then; a second report finds the request no longer
		// running. The worktree and session stay for the resume.
		err := r.cfg.Outbox.PostPark(pctx, r.hub, o.ParkReport(ref))
		if err != nil && !IsProblem(err, CodeNotRunning) {
			log.Warn("reporting the park failed; kept in the outbox when retryable", "error", err)
		}
		log.Info("run parked", "kind", o.ParkReport(ref).Kind, "tool", o.Park.Tool, "session", o.SessionID,
			"spent_usd", o.SpentUSD, "used_seconds", o.UsedSeconds)
		return
	}
	// The request ends with this result: nothing resumes it.
	defer r.finish(pctx, req.ID)
	if err := r.cfg.Outbox.Post(pctx, r.hub, o.Result(ref)); err != nil {
		log.Warn("posting the result failed; kept in the outbox when retryable", "outcome", o.State, "error", err)
		return
	}
	log.Info("run finished", "outcome", o.State, "session", o.SessionID, "spent_usd", o.SpentUSD, "used_seconds", o.UsedSeconds)
}
