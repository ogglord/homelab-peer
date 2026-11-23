package peer

import (
	"context"
	"slices"
	"time"
)

// A listener's hello reports the runs it still has; the hub judges listener
// loss from that report, never from a dropped connection, because the daemon
// restarts on every deploy that changes its config and runs must survive it.

// HelloResult is the hub's answer to a hello.
type HelloResult struct {
	// Cancel lists the reported runs the hub no longer holds as running for
	// this instance; the listener stops them.
	Cancel []string
	// Lost lists the running requests this hello failed as listener_lost.
	Lost []string
}

// HelloIn is a listener's hello. Runs is the lease report; GateUnverified
// says the approval gate failed its canary, so the listener claims nothing.
type HelloIn struct {
	Instance       string
	StartedAt      time.Time
	Runs           []string
	GateUnverified bool
	Version        string // the listener's build commit; "" from older clients
}

// Hello registers c's listener instance. The newest start wins: an instance
// older than the current one gets ErrSuperseded, a newer one replaces it and
// ends its stream. It also records the host's last contact and returns the
// host's delivered
// requests to the queue so the new stream replays them. While the current
// instance reports its gate unverified, the host's queued requests fail
// with gate_unverified instead (pushQueued).
func (s *Service) Hello(ctx context.Context, c Caller, in HelloIn) (HelloResult, error) {
	instance, startedAt, runs := in.Instance, in.StartedAt, in.Runs
	switch {
	case instance == "" || len(instance) > maxInstance:
		return HelloResult{}, invalid("instance must be 1 to 128 characters")
	case startedAt.IsZero():
		return HelloResult{}, invalid("started_at is required")
	case len(runs) > maxRuns:
		return HelloResult{}, invalid("at most 64 runs")
	}
	for _, id := range runs {
		if id == "" || len(id) > maxID {
			return HelloResult{}, invalid("run ids must be 1 to 64 characters")
		}
	}
	receipt := s.now()
	ok, err := s.st.Hello(ctx, c.Host, instance, startedAt, receipt)
	if err != nil {
		return HelloResult{}, err
	}
	if !ok || !s.broker.setInstance(c.Host, instance, startedAt, in.GateUnverified, in.Version) {
		return HelloResult{}, ErrSuperseded
	}

	var res HelloResult
	if res.Lost, err = s.lease(ctx, c.Host, instance, runs, receipt); err != nil {
		return HelloResult{}, err
	}
	if res.Cancel, err = s.cancelList(ctx, c.Host, instance, runs); err != nil {
		return HelloResult{}, err
	}
	s.pushQueued(ctx, c.Host)
	return res, nil
}

// lease fails host's running requests that this instance does not hold
// (not reported, or claimed by another instance) once their claim is older
// than receipt minus LeaseGrace: a claim in flight is not yet in the report.
func (s *Service) lease(ctx context.Context, host, instance string, runs []string, receipt time.Time) ([]string, error) {
	running, err := s.st.RunningRequests(ctx, host)
	if err != nil {
		return nil, err
	}
	cutoff := receipt.Add(-LeaseGrace)
	var lost []string
	for _, r := range running {
		if r.Instance == instance && slices.Contains(runs, r.ID) {
			continue
		}
		if !r.ClaimedAt.Before(cutoff) {
			continue
		}
		spec := runFinish(r, ReqFailed, FailListenerLost, receipt)
		spec.ClaimedBefore = &cutoff
		won, err := s.finish(ctx, spec)
		if err != nil {
			return nil, err
		}
		if won {
			s.log.Info("peer request failed: listener lost", "request_id", r.ID, "host", host)
			lost = append(lost, r.ID)
		}
	}
	return lost, nil
}

// cancelList is every reported run the hub does not hold as running for this
// instance. A reported request still queued for this host is a claim in
// flight and is not cancelled.
func (s *Service) cancelList(ctx context.Context, host, instance string, runs []string) ([]string, error) {
	cancel := []string{}
	for _, id := range runs {
		r, ok, err := s.st.Request(ctx, id)
		if err != nil {
			return nil, err
		}
		held := ok && r.Target == host && r.State == ReqRunning && r.Instance == instance
		pending := ok && r.Target == host && r.State.claimable()
		if !held && !pending {
			cancel = append(cancel, id)
		}
	}
	return cancel, nil
}

// Sweep ends every request whose expiry is due at now: queued and parked
// ones expire, running ones fail with timeout. Each is a compare-and-set on
// the due expiry, so a transition that moved the request first wins. It
// runs every SweepEvery and before every prune.
func (s *Service) Sweep(ctx context.Context, now time.Time) (int, error) {
	due, err := s.st.DueRequests(ctx, now)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, r := range due {
		var spec FinishSpec
		if r.State == ReqRunning {
			spec = runFinish(r, ReqFailed, FailTimeout, now)
		} else {
			spec = FinishSpec{
				ID: r.ID, From: []RequestState{ReqWaiting, ReqDelivered, ReqParked, ReqApproved},
				To: ReqExpired, Now: now,
			}
		}
		spec.DueBy = &now
		won, err := s.finish(ctx, spec)
		if err != nil {
			return n, err
		}
		if won && r.State == ReqParked {
			s.withdraw(ctx, r)
		}
		if won {
			n++
		}
	}
	return n, nil
}

// loseSilentHosts fails the running requests of every host none of whose
// listeners has been connected for ListenerLostAfter (since the hub started,
// for a host not seen since).
func (s *Service) loseSilentHosts(ctx context.Context, now time.Time) (int, error) {
	hosts, err := s.st.RunningHosts(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, h := range hosts {
		last, connected := s.broker.contact(h)
		if connected {
			continue
		}
		if last.IsZero() {
			last = s.started
		}
		if now.Sub(last) < ListenerLostAfter {
			continue
		}
		running, err := s.st.RunningRequests(ctx, h)
		if err != nil {
			return n, err
		}
		for _, r := range running {
			won, err := s.finish(ctx, runFinish(r, ReqFailed, FailListenerLost, now))
			if err != nil {
				return n, err
			}
			if won {
				s.log.Info("peer request failed: no listener", "request_id", r.ID, "host", h)
				n++
			}
		}
	}
	return n, nil
}

// requeueStale returns delivered requests nobody claimed within ClaimTimeout
// to the queue and pushes them again.
func (s *Service) requeueStale(ctx context.Context, now time.Time) error {
	hosts, err := s.st.Requeue(ctx, "", now.Add(-ClaimTimeout), now)
	if err != nil {
		return err
	}
	slices.Sort(hosts)
	for _, h := range slices.Compact(hosts) {
		s.pushQueued(ctx, h)
	}
	return nil
}

// Pruner deletes what is past retention (store.Store.Prune).
type Pruner func(ctx context.Context, now time.Time) error

// Run sweeps every SweepEvery until ctx ends, and once an hour, after the
// sweep, runs prune (nil: none). Failures are logged.
func (s *Service) Run(ctx context.Context, prune Pruner) {
	t := time.NewTicker(SweepEvery)
	defer t.Stop()
	var lastPrune time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		now := s.now()
		if _, err := s.Sweep(ctx, now); err != nil {
			s.log.Warn("peer expiry sweep failed", "error", err)
		}
		if _, err := s.loseSilentHosts(ctx, now); err != nil {
			s.log.Warn("peer listener-loss check failed", "error", err)
		}
		if err := s.requeueStale(ctx, now); err != nil {
			s.log.Warn("peer requeue of unclaimed requests failed", "error", err)
		}
		if err := s.SweepApprovals(ctx, now); err != nil {
			s.log.Warn("peer approval sweep failed", "error", err)
		}
		if prune != nil && now.Sub(lastPrune) >= time.Hour {
			lastPrune = now
			if err := prune(ctx, now); err != nil {
				s.log.Warn("peer prune failed", "error", err)
			}
		}
	}
}
