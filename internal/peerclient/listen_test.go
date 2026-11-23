package peerclient_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ogglord/homelab-peer/internal/peerclient"
	"github.com/ogglord/homelab-peer/internal/peerclient/hubtest"
)

var (
	homelabCaller = hubtest.Caller("homelab", "request", "result", "status")
	haCaller      = hubtest.Caller("homeassistant", "result", "status")
)

func client(t *testing.T, s *hubtest.Server) *peerclient.Client {
	t.Helper()
	c, err := peerclient.New(s.URL())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func sendStatus(t *testing.T, c *peerclient.Client, body string) int64 {
	t.Helper()
	r, err := c.Send(context.Background(), peerclient.Send{ID: peerclient.NewID(), Kind: "status", Target: "homeassistant", Phase: "progress", Body: body})
	if err != nil || r.Seq == nil {
		t.Fatalf("send: %+v %v", r, err)
	}
	return *r.Seq
}

// running is a listener on its own goroutine, its deliveries on a channel.
type running struct {
	l    *peerclient.Listener
	got  chan peerclient.Message
	done chan error
	stop context.CancelFunc
}

func listen(t *testing.T, s *hubtest.Server, startedAt time.Time) *running {
	t.Helper()
	return listenWith(t, s, startedAt, nil)
}

// listenWith runs hook, when set, on the listener's goroutine before each
// delivery; its error fails the hand-off.
func listenWith(t *testing.T, s *hubtest.Server, startedAt time.Time, hook func(peerclient.Message) error) *running {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	r := &running{got: make(chan peerclient.Message, 32), done: make(chan error, 1), stop: cancel}
	r.l = &peerclient.Listener{
		Client: client(t, s), Instance: peerclient.NewInstance(), StartedAt: startedAt,
		Deliver: func(m peerclient.Message) error {
			if hook != nil {
				if err := hook(m); err != nil {
					return err
				}
			}
			r.got <- m
			return nil
		},
		MinBackoff: 10 * time.Millisecond, MaxBackoff: 50 * time.Millisecond,
	}
	go func() { r.done <- r.l.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-r.done })
	return r
}

func (r *running) next(t *testing.T) peerclient.Message {
	t.Helper()
	select {
	case m := <-r.got:
		return m
	case err := <-r.done:
		t.Fatalf("listener exited: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("no delivery")
	}
	return peerclient.Message{}
}

func ackedSeq(t *testing.T, h *hubtest.Hub, host string) (int64, string) {
	t.Helper()
	seq, inst, err := hubAcked(h, host)
	if err != nil {
		t.Fatal(err)
	}
	return seq, inst
}

func hubAcked(h *hubtest.Hub, host string) (int64, string, error) {
	st, err := h.Service().Status(context.Background())
	if err != nil {
		return 0, "", err
	}
	for _, x := range st.Hosts {
		if x.Name == host {
			return x.AckedSeq, x.Instance, nil
		}
	}
	return 0, "", nil
}

// waitAcked waits until the hub holds homeassistant's acknowledgement of seq.
func waitAcked(t *testing.T, h *hubtest.Hub, seq int64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for acked, _ := ackedSeq(t, h, "homeassistant"); acked != seq; acked, _ = ackedSeq(t, h, "homeassistant") {
		if time.Now().After(deadline) {
			t.Fatalf("acked %d, want %d", acked, seq)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A waiting status is delivered and acknowledged; a later listener does not
// get it again.
func TestListenerAcknowledgesAndDoesNotReplay(t *testing.T) {
	t.Parallel()
	h := hubtest.New(t)
	ha, lab := h.Serve(haCaller), client(t, h.Serve(homelabCaller))
	seq := sendStatus(t, lab, "waiting")

	first := listen(t, ha, time.Now())
	if m := first.next(t); m.Seq != seq || *m.Body != "waiting" || m.Sender != "homelab" {
		t.Fatalf("delivered %+v", m)
	}
	waitAcked(t, h, seq)
	first.stop()
	<-first.done
	first.done <- nil // for the cleanup

	second := listen(t, ha, time.Now())
	later := sendStatus(t, lab, "later")
	if m := second.next(t); m.Seq != later {
		t.Fatalf("second listener got seq %d first, want %d (no replay of %d)", m.Seq, later, seq)
	}
}

// A frame whose sequence was already handed off has no second effect.
func TestListenerDropsDuplicateFrames(t *testing.T) {
	t.Parallel()
	h := hubtest.New(t)
	ha, lab := h.Serve(haCaller), client(t, h.Serve(homelabCaller))
	ha.DuplicateFrames()
	want := []int64{sendStatus(t, lab, "a"), sendStatus(t, lab, "b")}
	r := listen(t, ha, time.Now())
	got := []int64{r.next(t).Seq, r.next(t).Seq}
	want = append(want, sendStatus(t, lab, "c"))
	got = append(got, r.next(t).Seq)
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("delivered %v, want %v", got, want)
		}
	}
}

// AE3, client half: the hub goes away and comes back (a daemon restart);
// the listener reconnects with backoff, says hello with the same instance
// and resumes.
func TestListenerReconnectsAfterHubRestart(t *testing.T) {
	t.Parallel()
	h := hubtest.New(t)
	ha, labSrv := h.Serve(haCaller), h.Serve(homelabCaller)
	lab := client(t, labSrv)
	r := listen(t, ha, time.Now())
	before := sendStatus(t, lab, "before")
	if m := r.next(t); m.Seq != before {
		t.Fatalf("delivered seq %d, want %d", m.Seq, before)
	}

	ha.Down()
	labSrv.Down()
	time.Sleep(100 * time.Millisecond) // a few failed reconnects
	h.Restart()
	ha.Up()
	labSrv.Up()

	after := sendStatus(t, lab, "after")
	if m := r.next(t); m.Seq != after {
		t.Fatalf("delivered seq %d, want %d", m.Seq, after)
	}
	if n := ha.Hellos(); n < 2 {
		t.Fatalf("hellos %d, want a hello per connect", n)
	}
	if _, inst := ackedSeq(t, h, "homeassistant"); inst != r.l.Instance {
		t.Fatalf("hub holds instance %q, want %q", inst, r.l.Instance)
	}
}

// A newer instance for the same host supersedes a running one: the old
// listener's loop ends with ErrSuperseded, the new one keeps receiving.
func TestNewerInstanceSupersedesRunningListener(t *testing.T) {
	t.Parallel()
	h := hubtest.New(t)
	ha, lab := h.Serve(haCaller), client(t, h.Serve(homelabCaller))
	t0 := time.Now()
	old := listen(t, ha, t0)
	probe := sendStatus(t, lab, "probe")
	old.next(t)
	waitAcked(t, h, probe)

	newer := listen(t, ha, t0.Add(time.Second))
	select {
	case err := <-old.done:
		if !errors.Is(err, peerclient.ErrSuperseded) {
			t.Fatalf("old listener returned %v", err)
		}
		old.done <- err // for the cleanup
	case <-time.After(5 * time.Second):
		t.Fatal("old listener still running")
	}
	seq := sendStatus(t, lab, "for the newer one")
	if m := newer.next(t); m.Seq != seq {
		t.Fatalf("newer got %d, want %d", m.Seq, seq)
	}
}

// A failed hand-off is not acknowledged: the hub's mark stays below the
// message, and the reconnect delivers it again.
func TestListenerRedeliversAfterFailedHandOff(t *testing.T) {
	t.Parallel()
	h := hubtest.New(t)
	ha, lab := h.Serve(haCaller), client(t, h.Serve(homelabCaller))
	first := sendStatus(t, lab, "first")
	seq := sendStatus(t, lab, "second")

	attempts := 0 // the listener's goroutine only
	var ackedBefore int64
	var ackedErr error
	r := listenWith(t, ha, time.Now(), func(m peerclient.Message) error {
		if m.Seq != seq {
			return nil
		}
		if attempts++; attempts == 1 {
			return errors.New("hand-off failed")
		}
		ackedBefore, _, ackedErr = hubAcked(h, "homeassistant")
		return nil
	})
	if m := r.next(t); m.Seq != first {
		t.Fatalf("delivered seq %d, want %d", m.Seq, first)
	}
	if m := r.next(t); m.Seq != seq {
		t.Fatalf("delivered seq %d, want %d again", m.Seq, seq)
	}
	if ackedErr != nil || ackedBefore != first {
		t.Fatalf("hub acked %d (%v) before the redelivery, want %d", ackedBefore, ackedErr, first)
	}
	if n := ha.Hellos(); n < 2 {
		t.Fatalf("hellos %d, want a reconnect", n)
	}
	waitAcked(t, h, seq)
}

// A message handed off whose ack failed is acknowledged on the next hello
// and not delivered a second time.
func TestListenerReacksAfterFailedAck(t *testing.T) {
	t.Parallel()
	h := hubtest.New(t)
	ha, lab := h.Serve(haCaller), client(t, h.Serve(homelabCaller))
	ha.FailNextAck()
	seq := sendStatus(t, lab, "once")
	r := listen(t, ha, time.Now())
	if m := r.next(t); m.Seq != seq {
		t.Fatalf("delivered seq %d, want %d", m.Seq, seq)
	}
	waitAcked(t, h, seq)
	if n := ha.Hellos(); n < 2 {
		t.Fatalf("hellos %d, want a reconnect", n)
	}
	select {
	case m := <-r.got:
		t.Fatalf("seq %d delivered again", m.Seq)
	case <-time.After(200 * time.Millisecond):
	}
}
