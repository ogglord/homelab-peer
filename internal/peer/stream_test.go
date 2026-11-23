package peer

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// sse is an open push stream.
type sse struct {
	t      *testing.T
	resp   *http.Response
	frames chan frame
	cancel context.CancelFunc
}

type frame struct {
	event string
	data  string
}

func (a *agent) hello(instance string, startedAt time.Time) reply {
	return a.do(http.MethodPost, "/api/peer/hello", map[string]any{"instance": instance, "started_at": startedAt.Format(time.RFC3339Nano)})
}

func (a *agent) ack(instance string, seq int64) reply {
	return a.do(http.MethodPost, "/api/peer/ack", map[string]any{"instance": instance, "seq": seq})
}

// stream opens the push stream; a non-200 answer is returned as a reply.
func (a *agent) stream(instance string, after int64) (*sse, reply) {
	a.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/api/peer/stream?instance=%s&after=%d", a.url, instance, after), nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		cancel()
		a.t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		defer cancel()
		defer resp.Body.Close()
		var b strings.Builder
		_, _ = bufio.NewReader(resp.Body).WriteTo(&b)
		return nil, reply{resp.StatusCode, []byte(b.String())}
	}
	s := &sse{t: a.t, resp: resp, frames: make(chan frame, 64), cancel: cancel}
	go func() {
		defer close(s.frames)
		br := bufio.NewReader(resp.Body)
		var f frame
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\n")
			switch {
			case line == "":
				if f.event != "" {
					s.frames <- f
				}
				f = frame{}
			case strings.HasPrefix(line, "event: "):
				f.event = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "data: "):
				f.data = strings.TrimPrefix(line, "data: ")
			}
		}
	}()
	a.t.Cleanup(s.close)
	return s, reply{status: http.StatusOK}
}

func (s *sse) close() { s.cancel(); s.resp.Body.Close() }

// next waits for the next event frame.
func (s *sse) next() (frame, bool) {
	s.t.Helper()
	select {
	case f, ok := <-s.frames:
		return f, ok
	case <-time.After(3 * time.Second):
		s.t.Fatal("no frame within 3s")
		return frame{}, false
	}
}

// ids reads n message frames and returns their ids and sequences.
func (s *sse) messages(n int) ([]string, []int64) {
	s.t.Helper()
	var ids []string
	var seqs []int64
	for range n {
		f, ok := s.next()
		if !ok || f.event != "message" {
			s.t.Fatalf("frame = %+v (open %v), want a message", f, ok)
		}
		var m struct {
			ID  string `json:"id"`
			Seq int64  `json:"seq"`
		}
		if err := json.Unmarshal([]byte(f.data), &m); err != nil {
			s.t.Fatal(err)
		}
		ids = append(ids, m.ID)
		seqs = append(seqs, m.Seq)
	}
	return ids, seqs
}

// quiet asserts no frame arrives for a moment.
func (s *sse) quiet() {
	s.t.Helper()
	select {
	case f, ok := <-s.frames:
		if ok {
			s.t.Fatalf("unexpected frame %+v", f)
		}
	case <-time.After(150 * time.Millisecond):
	}
}

var t0 = time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)

// A status for a host that is not listening is held, then delivered in
// order once it says hello and streams.
func TestStatusForOfflineHostDeliveredOnConnect(t *testing.T) {
	t.Parallel()
	h := newHub(t)
	lab := h.as(t, homelab)
	for _, id := range []string{"a", "b", "c"} {
		if r := lab.send(statusBody(id, "homeassistant")); r.status != http.StatusOK {
			t.Fatalf("send %s: %d %s", id, r.status, r.body)
		}
	}
	ha := h.as(t, haCaller)
	if r := ha.hello("i1", t0); r.status != http.StatusOK {
		t.Fatalf("hello: %d %s", r.status, r.body)
	}
	s, r := ha.stream("i1", 0)
	if s == nil {
		t.Fatalf("stream: %d %s", r.status, r.body)
	}
	if ids, _ := s.messages(3); strings.Join(ids, ",") != "a,b,c" {
		t.Fatalf("ids = %v", ids)
	}
	// Live delivery after the replay.
	lab.send(statusBody("d", "homeassistant"))
	if ids, _ := s.messages(1); ids[0] != "d" {
		t.Fatalf("live id = %v", ids)
	}
}

// AE3: a status committed between the subscription attach and the replay
// read is on both and is delivered once; a stale or zero cursor never
// produces a duplicate.
func TestStreamReplayAndLiveDeliverEachOnce(t *testing.T) {
	t.Parallel()
	h := newHub(t)
	lab := h.as(t, homelab)
	lab.send(statusBody("a", "homeassistant"))
	h.svc.afterSubscribe = func() {
		h.svc.afterSubscribe = nil
		if _, err := h.svc.Send(context.Background(), homelab, status("raced", "homeassistant")); err != nil {
			t.Error(err)
		}
	}
	ha := h.as(t, haCaller)
	ha.hello("i1", t0)
	s, r := ha.stream("i1", 0)
	if s == nil {
		t.Fatalf("stream: %d %s", r.status, r.body)
	}
	ids, seqs := s.messages(2)
	if strings.Join(ids, ",") != "a,raced" {
		t.Fatalf("ids = %v", ids)
	}
	s.quiet()

	// Acknowledge everything, then reconnect with a cursor of zero and with
	// a stale one: the acknowledged mark is the floor.
	if r := ha.ack("i1", seqs[1]); r.status != http.StatusNoContent {
		t.Fatalf("ack: %d %s", r.status, r.body)
	}
	s.close()
	lab.send(statusBody("b", "homeassistant"))
	for _, after := range []int64{0, seqs[0]} {
		s, r := ha.stream("i1", after)
		if s == nil {
			t.Fatalf("stream after=%d: %d %s", after, r.status, r.body)
		}
		if ids, _ := s.messages(1); ids[0] != "b" {
			t.Fatalf("after=%d: ids = %v", after, ids)
		}
		s.quiet()
		s.close()
	}
	ms, _ := h.svc.Messages(context.Background(), 10)
	for _, m := range ms {
		if want := m.Seq <= seqs[1]; m.Delivered != want {
			t.Errorf("message %s delivered = %v, want %v", m.ID, m.Delivered, want)
		}
	}
}

// A second instance's hello supersedes the first: its stream ends, and its
// acknowledge and re-attach are refused as superseded.
func TestHelloSupersedesOlderInstance(t *testing.T) {
	t.Parallel()
	h := newHub(t)
	ha := h.as(t, haCaller)
	ha.hello("old", t0)
	old, r := ha.stream("old", 0)
	if old == nil {
		t.Fatalf("stream: %d %s", r.status, r.body)
	}
	if r := ha.hello("new", t0.Add(time.Minute)); r.status != http.StatusOK {
		t.Fatalf("new hello: %d %s", r.status, r.body)
	}
	f, ok := old.next()
	if !ok || f.event != "error" || !strings.Contains(f.data, "superseded") {
		t.Fatalf("old stream frame = %+v (open %v), want a superseded error", f, ok)
	}
	if _, ok := old.next(); ok {
		t.Fatal("old stream still open")
	}
	if r := ha.ack("old", 1); r.status != http.StatusConflict || r.code() != "superseded" {
		t.Fatalf("old ack: %d %s", r.status, r.body)
	}
	if _, r := ha.stream("old", 0); r.status != http.StatusConflict || r.code() != "superseded" {
		t.Fatalf("old re-attach: %d %s", r.status, r.body)
	}
	if r := ha.hello("old", t0); r.status != http.StatusConflict || r.code() != "superseded" {
		t.Fatalf("old hello again: %d %s", r.status, r.body)
	}
	if s, r := ha.stream("new", 0); s == nil {
		t.Fatalf("new stream: %d %s", r.status, r.body)
	}
}

func TestStreamNeedsHello(t *testing.T) {
	t.Parallel()
	h := newHub(t)
	if _, r := h.as(t, haCaller).stream("i1", 0); r.status != http.StatusConflict || r.code() != "hello_required" {
		t.Fatalf("stream without hello: %d %s", r.status, r.body)
	}
}

// A client disconnect ends the stream handler and detaches it.
func TestStreamDisconnectDetaches(t *testing.T) {
	t.Parallel()
	h := newHub(t)
	ha := h.as(t, haCaller)
	ha.hello("i1", t0)
	s, r := ha.stream("i1", 0)
	if s == nil {
		t.Fatalf("stream: %d %s", r.status, r.body)
	}
	if n := h.svc.broker.streams("homeassistant"); n != 1 {
		t.Fatalf("streams = %d, want 1", n)
	}
	s.close()
	deadline := time.Now().Add(3 * time.Second)
	for h.svc.broker.streams("homeassistant") != 0 {
		if time.Now().After(deadline) {
			t.Fatal("stream still attached after the client went away")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// streams counts the open streams of host.
func (b *broker) streams(host string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	if h := b.hosts[host]; h != nil {
		return len(h.subs)
	}
	return 0
}
