package peer

import (
	"context"
	"sync"
	"time"
)

// replayPage bounds one replay read; a full page is followed by another.
const replayPage = 500

// liveBuffer is how many live messages a slow stream may lag behind before
// it is closed (the listener reconnects and replays from its cursor).
const liveBuffer = 256

// broker fans committed messages out to the connected listener streams. It
// also holds each host's current listener instance: a stream is bound to an
// instance, and a newer hello closes the streams of older ones. It is empty
// after a hub restart, so a host must say hello before it can stream.
type broker struct {
	mu    sync.Mutex
	hosts map[string]*hostStreams
	now   func() time.Time
}

type hostStreams struct {
	instance  string
	startedAt time.Time
	subs      map[*sub]struct{}
	// contact is the last hello, stream attach or stream end of the host:
	// with no stream attached, how long its listeners have been gone.
	contact time.Time
	// gateUnverified is what the current instance's last hello reported.
	gateUnverified bool
	// version is the build commit the current instance's hello reported.
	version string
}

type sub struct {
	host, instance string
	ch             chan item
	done           chan struct{}
	err            error // why done closed; set before close
}

// item is one pushed frame: a stored message, or a request (req set).
type item struct {
	msg Message
	req *Request
}

func newBroker(now func() time.Time) *broker {
	return &broker{hosts: map[string]*hostStreams{}, now: now}
}

// setInstance makes instance current for host unless a later-started one
// already is, closing every stream of another instance, and records whether
// it reported its gate unverified. It returns false when the instance is
// older than the current one.
func (b *broker) setInstance(host, instance string, startedAt time.Time, gateUnverified bool, version string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	h := b.hosts[host]
	if h == nil {
		h = &hostStreams{subs: map[*sub]struct{}{}}
		b.hosts[host] = h
	} else if startedAt.Before(h.startedAt) {
		return false
	}
	h.instance, h.startedAt, h.contact, h.gateUnverified, h.version = instance, startedAt, b.now(), gateUnverified, version
	for s := range h.subs {
		if s.instance != instance {
			b.closeLocked(h, s, ErrSuperseded)
		}
	}
	return true
}

func (b *broker) subscribe(host, instance string) (*sub, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	h := b.hosts[host]
	switch {
	case h == nil:
		return nil, ErrHelloRequired
	case h.instance != instance:
		return nil, ErrSuperseded
	}
	s := &sub{host: host, instance: instance, ch: make(chan item, liveBuffer), done: make(chan struct{})}
	h.subs[s] = struct{}{}
	h.contact = b.now()
	return s, nil
}

func (b *broker) unsubscribe(s *sub) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if h := b.hosts[s.host]; h != nil {
		if _, ok := h.subs[s]; ok {
			b.closeLocked(h, s, nil)
		}
	}
}

// publish never blocks: a stream whose buffer is full is closed instead.
func (b *broker) publish(m Message) { b.push(m.Target, item{msg: m}) }

func (b *broker) publishRequest(r Request) { b.push(r.Target, item{req: &r}) }

func (b *broker) push(host string, it item) {
	b.mu.Lock()
	defer b.mu.Unlock()
	h := b.hosts[host]
	if h == nil {
		return
	}
	for s := range h.subs {
		select {
		case s.ch <- it:
		default:
			b.closeLocked(h, s, errFellBehind)
		}
	}
}

// gateUnverified reports whether host's current listener instance said its
// gate is unverified.
func (b *broker) gateUnverified(host string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	h := b.hosts[host]
	return h != nil && h.gateUnverified
}

// hostInfo is what host's current listener instance reported in its hello:
// the gate state and its build commit.
func (b *broker) hostInfo(host string) (gateUnverified bool, version string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if h := b.hosts[host]; h != nil {
		return h.gateUnverified, h.version
	}
	return false, ""
}

func (b *broker) connected(host string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	h := b.hosts[host]
	return h != nil && len(h.subs) > 0
}

// contact is host's last listener contact (zero when none since the hub
// started) and whether a stream is attached now.
func (b *broker) contact(host string) (time.Time, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	h := b.hosts[host]
	if h == nil {
		return time.Time{}, false
	}
	return h.contact, len(h.subs) > 0
}

func (b *broker) closeLocked(h *hostStreams, s *sub, err error) {
	delete(h.subs, s)
	h.contact = b.now()
	s.err = err
	close(s.done)
}

// Subscription is one listener stream, attached but not yet replayed.
type Subscription struct {
	s     *Service
	sub   *sub
	floor int64
}

// Subscribe attaches c's listener instance to the live channel. The replay
// floor is the larger of after and the host's acknowledged sequence. Run
// must follow, or Close.
func (s *Service) Subscribe(ctx context.Context, c Caller, instance string, after int64) (*Subscription, error) {
	if after < 0 {
		return nil, invalid("after must not be negative")
	}
	h, ok, err := s.st.Host(ctx, c.Host)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrHelloRequired
	}
	sb, err := s.broker.subscribe(c.Host, instance)
	if err != nil {
		return nil, err
	}
	return &Subscription{s: s, sub: sb, floor: max(after, h.AckedSeq)}, nil
}

// Heartbeat is the stream's idle comment interval.
func (s *Service) Heartbeat() time.Duration { return s.cfg.Heartbeat }

// Close detaches the subscription.
func (sub *Subscription) Close() { sub.s.broker.unsubscribe(sub.sub) }

// Run emits every stored message after the floor, then every queued
// request, then live messages and requests, until ctx ends (nil) or the
// stream is superseded or falls behind (an error). Messages come in sequence
// order and each once; a request may come more than once (claiming it is
// what counts), and is marked delivered as it is emitted.
//
// The live channel was attached before the replay read, so a message
// committed meanwhile is on both; anything at or below the last emitted
// sequence is dropped. The replay is plain reads, never a write transaction.
func (sub *Subscription) Run(ctx context.Context, emit func(Message) error, emitRequest func(Request) error) error {
	defer sub.Close()
	if hook := sub.s.afterSubscribe; hook != nil {
		hook()
	}
	last := sub.floor
	for {
		page, err := sub.s.st.Replay(ctx, sub.sub.host, last, replayPage)
		if err != nil {
			return err
		}
		for _, m := range page {
			if err := emit(m); err != nil {
				return err
			}
			last = m.Seq
		}
		if len(page) < replayPage {
			break
		}
	}
	// Marked before the frame goes out, so a claim the frame triggers never
	// races the mark; a push lost on the wire is requeued by the next hello
	// or the claim timeout.
	pushRequest := func(r Request) error {
		sub.s.markDelivered(ctx, r)
		return emitRequest(r)
	}
	queued, err := sub.s.st.PushableRequests(ctx, sub.sub.host)
	if err != nil {
		return err
	}
	for _, r := range queued {
		if err := pushRequest(r); err != nil {
			return err
		}
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-sub.sub.done:
			return sub.sub.err
		case it := <-sub.sub.ch:
			if it.req != nil {
				if err := pushRequest(*it.req); err != nil {
					return err
				}
				continue
			}
			if it.msg.Seq <= last {
				continue
			}
			if err := emit(it.msg); err != nil {
				return err
			}
			last = it.msg.Seq
		}
	}
}
