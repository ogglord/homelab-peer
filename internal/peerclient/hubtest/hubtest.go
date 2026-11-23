// Package hubtest runs the real peer hub (internal/peer on a SQLite store)
// behind httptest servers, one per caller identity, for the client's tests.
// Only tests import it: it pulls in internal/peer, which cmd/peer must not.
package hubtest

import (
	"bytes"
	"context"
	"database/sql"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ogglord/homelab-peer/internal/peer"
	"github.com/ogglord/homelab-peer/internal/store"
)

// Hub is a hub service on a temp-dir database.
type Hub struct {
	t    testing.TB
	path string
	st   *store.Store

	mu  sync.Mutex
	svc *peer.Service
}

// New returns a hub on a fresh database.
func New(t testing.TB) *Hub {
	t.Helper()
	path := filepath.Join(t.TempDir(), "peer.db")
	st, err := store.Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	h := &Hub{t: t, path: path, st: st}
	h.Restart()
	return h
}

// Restart replaces the service on the same database, like a hub restart:
// the in-memory listener registry is empty again.
func (h *Hub) Restart() {
	h.mu.Lock()
	defer h.mu.Unlock()
	cfg := peer.Config{Hostname: "homelab-hub", Heartbeat: time.Hour}
	h.svc = peer.New(cfg, peer.NewDBStore(h.st), nil)
}

// Service is the current hub service.
func (h *Hub) Service() *peer.Service {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.svc
}

// Request sends a request from the caller's host to target, as that
// caller's `peer send request` would, and fails the test when the hub does
// not store it.
func (h *Hub) Request(from peer.Caller, id, target, text string) {
	h.t.Helper()
	r, err := h.Service().Send(context.Background(), from, peer.Send{
		ID: id, Kind: peer.KindRequest, Target: target, Text: text,
	})
	if err != nil || r.State != peer.OutcomeStored {
		h.t.Fatalf("request %s: %+v %v", id, r, err)
	}
}

// Get is request id as the hub holds it.
func (h *Hub) Get(id string) peer.Request {
	h.t.Helper()
	rs, err := h.Service().Requests(context.Background(), "", 500)
	if err != nil {
		h.t.Fatal(err)
	}
	for _, r := range rs {
		if r.ID == id {
			return r
		}
	}
	h.t.Fatalf("no request %s", id)
	return peer.Request{}
}

// AgeClaim moves request id's claim back by d, as if it had been running that
// much longer (the hub's lease judges a claim's age on the wall clock).
func (h *Hub) AgeClaim(id string, d time.Duration) {
	h.t.Helper()
	db, err := sql.Open("sqlite", "file:"+h.path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		h.t.Fatal(err)
	}
	defer db.Close()
	res, err := db.Exec(`UPDATE peer_requests SET claimed_at = claimed_at - ? WHERE id = ? AND claimed_at IS NOT NULL`, d.Milliseconds(), id)
	if err != nil {
		h.t.Fatal(err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		h.t.Fatalf("aging the claim of %s: %d rows", id, n)
	}
}

// Caller is a tailnet caller carrying the peer capability for host.
func Caller(host string, kinds ...string) peer.Caller {
	ks := make([]peer.Kind, len(kinds))
	for i, k := range kinds {
		ks[i] = peer.Kind(k)
	}
	c, err := peer.CallerFromCaps(host+"-node", []peer.CapEntry{{Host: host, Kinds: ks}})
	if err != nil {
		panic(err)
	}
	return c
}

type identity struct{ c peer.Caller }

func (i identity) Identify(context.Context, string) (peer.Caller, error) { return i.c, nil }

// Server is the hub's agent listener as one caller sees it.
type Server struct {
	h    *Hub
	c    peer.Caller
	addr string

	mu        sync.Mutex
	srv       *httptest.Server
	hellos    int
	lastHello []byte
	calls     map[string]int // "METHOD /api/path"
	duplicate bool
	failAck   bool
}

// Serve starts an agent listener that identifies every connection as c.
func (h *Hub) Serve(c peer.Caller) *Server {
	s := &Server{h: h, c: c}
	s.Up()
	h.t.Cleanup(s.Down)
	return s
}

// URL is the listener's origin; it stays the same across Down and Up.
func (s *Server) URL() string { return "http://" + s.addr }

// Up (re)starts the listener on its address with the hub's current service.
func (s *Server) Up() {
	s.mu.Lock()
	defer s.mu.Unlock()
	addr := s.addr
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	var ln net.Listener
	var err error
	for range 50 { // the old socket may linger briefly after Down
		if ln, err = net.Listen("tcp", addr); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		s.h.t.Fatal(err)
	}
	s.addr = ln.Addr().String()
	agent := peer.AgentHandler(s.h.Service(), identity{s.c}, slog.New(slog.DiscardHandler))
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var hello []byte
		if r.Method == http.MethodPost && r.URL.Path == "/api/peer/hello" {
			hello, _ = io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(hello))
		}
		s.mu.Lock()
		if hello != nil {
			s.hellos++
			s.lastHello = hello
		}
		if s.calls == nil {
			s.calls = map[string]int{}
		}
		s.calls[r.Method+" "+r.URL.Path]++
		dup := s.duplicate
		failAck := s.failAck && r.Method == http.MethodPost && r.URL.Path == "/api/peer/ack"
		if failAck {
			s.failAck = false
		}
		s.mu.Unlock()
		if failAck {
			http.Error(w, "ack refused by hubtest", http.StatusServiceUnavailable)
			return
		}
		if dup && r.URL.Path == "/api/peer/stream" {
			w = duplicating{w}
		}
		agent.ServeHTTP(w, r)
	}))
	srv.Listener.Close()
	srv.Listener = ln
	srv.Start()
	s.srv = srv
}

// Down stops the listener, cutting open streams.
func (s *Server) Down() {
	s.mu.Lock()
	srv := s.srv
	s.srv = nil
	s.mu.Unlock()
	if srv != nil {
		srv.CloseClientConnections()
		srv.Close()
	}
}

// Hellos counts the hello requests the listener answered.
func (s *Server) Hellos() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hellos
}

// LastHello is the body of the last hello the listener answered.
func (s *Server) LastHello() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastHello
}

// Calls counts the requests the listener answered for method and path, such
// as "POST /api/peer/claim".
func (s *Server) Calls(methodPath string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls[methodPath]
}

// DuplicateFrames makes streams opened from now on write every message
// frame twice, as a retransmitting path would.
func (s *Server) DuplicateFrames() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.duplicate = true
}

// FailNextAck makes the next acknowledgement fail with a 503 without
// reaching the hub.
func (s *Server) FailNextAck() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failAck = true
}

// duplicating writes each message frame twice (the hub writes one frame per
// Write call).
type duplicating struct{ http.ResponseWriter }

func (d duplicating) Write(b []byte) (int, error) {
	if strings.HasPrefix(string(b), "event: message\n") {
		if _, err := d.ResponseWriter.Write(b); err != nil {
			return 0, err
		}
	}
	return d.ResponseWriter.Write(b)
}

func (d duplicating) Unwrap() http.ResponseWriter { return d.ResponseWriter }

func (d duplicating) Flush() { http.NewResponseController(d.ResponseWriter).Flush() }
