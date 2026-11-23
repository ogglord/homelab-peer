package peer

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/ogglord/homelab-peer/internal/store"
)

// hub is a Service on a real SQLite store, with its log captured.
type hub struct {
	svc    *Service
	st     *store.Store
	dbPath string
	logs   *syncBuffer
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) Bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return bytes.Clone(s.b.Bytes())
}

func newHub(t *testing.T) *hub {
	t.Helper()
	return newHubWith(t, nil)
}

// newHubWith is newHub with the Store wrapped by wrap (nil: unwrapped).
func newHubWith(t *testing.T, wrap func(Store) Store) *hub {
	t.Helper()
	p := filepath.Join(t.TempDir(), "peer.db")
	st, err := store.Open(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	logs := &syncBuffer{}
	log := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ps := NewDBStore(st)
	if wrap != nil {
		ps = wrap(ps)
	}
	svc := New(Config{Hostname: "homelab-hub", Heartbeat: time.Hour, EnrolURL: "https://peer.example" + ApproverPath}, ps, log)
	return &hub{svc: svc, st: st, dbPath: p, logs: logs}
}

func (h *hub) log() *slog.Logger { return slog.New(slog.NewJSONHandler(h.logs, nil)) }

// dbBytes is the database file plus its write-ahead log, as on disk.
func (h *hub) dbBytes(t *testing.T) []byte {
	t.Helper()
	var all []byte
	for _, p := range []string{h.dbPath, h.dbPath + "-wal"} {
		b, err := os.ReadFile(p)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		all = append(all, b...)
	}
	return all
}

func caller(host string, kinds []Kind) Caller {
	c, err := CallerFromCaps(host+"-node", []CapEntry{{Host: host, Kinds: kinds}})
	if err != nil {
		panic(err)
	}
	return c
}

var (
	allKinds   = []Kind{KindRequest, KindResult, KindStatus}
	homelab    = caller("homelab", allKinds)
	haCaller   = caller("homeassistant", []Kind{KindResult, KindStatus})
	statusOnly = caller("laptop", []Kind{KindStatus})
)

func status(id, target string) Send {
	return Send{ID: id, Kind: KindStatus, Target: target, Phase: "progress", Body: "working on " + id}
}

func TestCallerFromCapsUnionsGrants(t *testing.T) {
	t.Parallel()
	c, err := CallerFromCaps("ha", []CapEntry{
		{Host: "homeassistant", Kinds: []Kind{KindStatus}},
		{Host: "homeassistant", Kinds: []Kind{KindResult, "secret", "bogus"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(c.Kinds, []Kind{KindResult, KindStatus}) {
		t.Errorf("kinds = %v; secret and unknown kinds are dropped", c.Kinds)
	}

	for name, entries := range map[string][]CapEntry{
		"none":            nil,
		"different hosts": {{Host: "a", Kinds: allKinds}, {Host: "b"}},
		"no host":         {{Kinds: allKinds}},
	} {
		if _, err := CallerFromCaps("n", entries); !errors.Is(err, ErrNoCapability) {
			t.Errorf("%s: err = %v, want ErrNoCapability", name, err)
		}
	}
}

func TestStatusRetryHasNoSecondEffect(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h := newHub(t)
	first, err := h.svc.Send(ctx, homelab, status("s1", "homeassistant"))
	if err != nil || first.State != OutcomeStored || first.Seq == 0 || first.Replayed {
		t.Fatalf("first send = %+v, %v", first, err)
	}
	again, err := h.svc.Send(ctx, homelab, status("s1", "homeassistant"))
	if err != nil || !again.Replayed || again.Seq != first.Seq || again.State != OutcomeStored {
		t.Fatalf("retry = %+v, %v; want the first outcome replayed", again, err)
	}
	if ms, _ := h.svc.Messages(ctx, 10); len(ms) != 1 {
		t.Fatalf("messages after retry = %d, want 1", len(ms))
	}
	if _, err := h.svc.Send(ctx, homelab, status("s1", "laptop")); !errors.Is(err, ErrConflict) {
		t.Fatalf("same id, other target: err = %v, want ErrConflict", err)
	}
}

func TestStatusValidation(t *testing.T) {
	t.Parallel()
	h := newHub(t)
	for name, in := range map[string]Send{
		"no phase":     {ID: "a", Kind: KindStatus, Target: "x"},
		"bad phase":    {ID: "a", Kind: KindStatus, Target: "x", Phase: "sleeping"},
		"no id":        {Kind: KindStatus, Target: "x", Phase: "info"},
		"no target":    {ID: "a", Kind: KindStatus, Phase: "info"},
		"long body":    {ID: "a", Kind: KindStatus, Target: "x", Phase: "info", Body: string(make([]byte, maxBody+1))},
		"carries text": {ID: "a", Kind: KindStatus, Target: "x", Phase: "info", Text: "x"},
		"legacy name":  {ID: "a", Kind: KindStatus, Target: "x", Phase: "info", Legacy: true},
		"secret kind":  {ID: "a", Kind: "secret", Target: "x"},
	} {
		var inv invalidError
		if _, err := h.svc.Send(context.Background(), homelab, in); !errors.As(err, &inv) {
			t.Errorf("%s: err = %v, want invalid", name, err)
		}
	}
}
