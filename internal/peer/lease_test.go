package peer

import (
	"context"
	"slices"
	"testing"
	"time"
)

// AE7 and AE14, hub half. A hello within the grace keeps an unreported run
// (a claim in flight); a reported run survives a hub restart; a hello after
// the grace without it fails it as listener lost; reported runs the hub does
// not hold come back in the cancel list; a late result is discarded.
func TestHelloLease(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h, clk := reqHub(t)
	h.hello(t, haCaller, haInst)
	h.request(t, "r1", "homeassistant")
	h.claim(t, "r1", 0)

	// Within the grace, not yet reported: kept.
	clk.set(t0.Add(LeaseGrace - time.Second))
	if res := h.hello(t, haCaller, haInst); len(res.Lost) != 0 || h.req(t, "r1").State != ReqRunning {
		t.Fatalf("hello within grace: %+v, %s", res, h.req(t, "r1").State)
	}

	// The hub restarts; the listener reconnects and reports the run.
	h.svc = New(h.svc.cfg, h.svc.st, h.svc.log)
	h.svc.now, h.svc.started = clk.now, clk.now()
	clk.set(t0.Add(time.Hour))
	if res := h.hello(t, haCaller, haInst, "r1"); len(res.Lost) != 0 || len(res.Cancel) != 0 {
		t.Fatalf("hello reporting the run: %+v", res)
	}
	if _, discarded, err := h.svc.PostResult(ctx, haCaller, ResultIn{ID: "r1", Instance: haInst, Attempt: 1, State: ReqDone}); err != nil || discarded {
		t.Fatalf("result after the restart: discarded=%v err=%v", discarded, err)
	}

	// After the grace, not reported: failed as listener lost. A reported
	// run the hub does not hold, an unknown one and another host's are
	// cancelled; a reported run still queued (a claim in flight) is not.
	h.request(t, "r2", "homeassistant")
	h.claim(t, "r2", 0)
	h.request(t, "r3", "homeassistant")
	h.request(t, "lab", "homelab")
	clk.set(clk.now().Add(LeaseGrace + time.Second))
	res := h.hello(t, haCaller, haInst, "r1", "r3", "gone", "lab")
	if !slices.Equal(res.Lost, []string{"r2"}) {
		t.Fatalf("lost %v, want r2", res.Lost)
	}
	if r := h.req(t, "r2"); r.State != ReqFailed || r.Reason != FailListenerLost {
		t.Fatalf("r2 %+v", r)
	}
	slices.Sort(res.Cancel)
	if !slices.Equal(res.Cancel, []string{"gone", "lab", "r1"}) {
		t.Fatalf("cancel %v", res.Cancel)
	}

	// A late result for an expired request is discarded.
	h.claim(t, "r3", 0)
	clk.set(clk.now().Add(runExpiry))
	if _, err := h.svc.Sweep(ctx, clk.now()); err != nil {
		t.Fatal(err)
	}
	r, discarded, err := h.svc.PostResult(ctx, haCaller, ResultIn{ID: "r3", Instance: haInst, Attempt: 1, State: ReqDone, Summary: "late"})
	if err != nil || !discarded || r.State != ReqFailed || r.Reason != FailTimeout || r.Summary != "" {
		t.Fatalf("late result: %+v discarded=%v err=%v", r, discarded, err)
	}
	if ms := h.results(t, "r3"); len(ms) != 1 {
		t.Fatalf("result messages %d", len(ms))
	}
}

// A run's result from a replaced instance or another attempt is refused as
// superseded while the request runs.
func TestResultFromOtherRunIsSuperseded(t *testing.T) {
	t.Parallel()
	h, _ := reqHub(t)
	h.hello(t, haCaller, haInst)
	h.request(t, "r1", "homeassistant")
	h.claim(t, "r1", 0)
	for _, in := range []ResultIn{
		{ID: "r1", Instance: "ha-0", Attempt: 1, State: ReqDone},
		{ID: "r1", Instance: haInst, Attempt: 2, State: ReqDone},
	} {
		if _, _, err := h.svc.PostResult(context.Background(), haCaller, in); err != ErrSuperseded {
			t.Fatalf("%+v: %v", in, err)
		}
	}
	if r := h.req(t, "r1"); r.State != ReqRunning {
		t.Fatalf("state %s", r.State)
	}
}

// A host whose listener stays away fails its running requests only after
// ListenerLostAfter; one connected is never failed for it.
func TestSilentHostLosesRuns(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h, clk := reqHub(t)
	h.hello(t, haCaller, haInst)
	h.request(t, "r1", "homeassistant")
	h.claim(t, "r1", 0)
	clk.set(t0.Add(ListenerLostAfter - time.Second))
	if n, _ := h.svc.loseSilentHosts(ctx, clk.now()); n != 0 {
		t.Fatal("failed before ListenerLostAfter")
	}
	sub, err := h.svc.Subscribe(ctx, haCaller, haInst, 0)
	if err != nil {
		t.Fatal(err)
	}
	clk.set(t0.Add(2 * ListenerLostAfter))
	if n, _ := h.svc.loseSilentHosts(ctx, clk.now()); n != 0 {
		t.Fatal("failed while a stream is attached")
	}
	sub.Close()
	clk.set(clk.now().Add(ListenerLostAfter))
	if n, _ := h.svc.loseSilentHosts(ctx, clk.now()); n != 1 {
		t.Fatal("not failed after the listener left")
	}
	if r := h.req(t, "r1"); r.State != ReqFailed || r.Reason != FailListenerLost {
		t.Fatalf("%+v", r)
	}
}
