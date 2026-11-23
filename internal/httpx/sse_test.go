package httpx

import (
	"bufio"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// readFrame reads one SSE frame (up to the blank line) from r.
func readFrame(t *testing.T, r *bufio.Reader) string {
	t.Helper()
	var sb strings.Builder
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("read frame: %v (got %q)", err, sb.String())
		}
		if line == "\n" {
			return sb.String()
		}
		sb.WriteString(line)
	}
}

// TestStreamFlushesEachEventThroughMiddleware proves the first frame reaches
// the client while Run is still blocked: per-event flush must survive the
// logging middleware's statusRecorder wrapper.
func TestStreamFlushesEachEventThroughMiddleware(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	h := Middleware(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := Stream{Ctx: r.Context(), Run: func(ctx context.Context, emit func(string, any) error) error {
			if err := emit("connected", map[string]string{"type": "connected", "message": ""}); err != nil {
				return err
			}
			<-release
			return emit("done", map[string]string{"type": "done", "message": "pull complete"})
		}}.Serve(w)
		if err != nil {
			t.Errorf("Serve: %v", err)
		}
	}))
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("content-type = %q", ct)
	}

	br := bufio.NewReader(resp.Body)
	got := make(chan string, 1)
	go func() { got <- readFrame(t, br) }()
	select {
	case f := <-got:
		if f != "event: connected\ndata: {\"message\":\"\",\"type\":\"connected\"}\n" {
			t.Fatalf("first frame = %q", f)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("first frame not flushed while Run is blocked")
	}

	close(release)
	if f := readFrame(t, br); f != "event: done\ndata: {\"message\":\"pull complete\",\"type\":\"done\"}\n" {
		t.Fatalf("second frame = %q", f)
	}
}

func TestStreamRunErrorBecomesErrorFrame(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	err := Stream{Run: func(ctx context.Context, emit func(string, any) error) error {
		_ = emit("log", map[string]string{"type": "log", "message": "pulling"})
		return errors.New("pull failed: no such image")
	}}.Serve(rec)
	if err != nil {
		t.Fatalf("Serve = %v", err)
	}
	want := "event: log\ndata: {\"message\":\"pulling\",\"type\":\"log\"}\n\n" +
		"event: error\ndata: {\"message\":\"pull failed: no such image\",\"type\":\"error\"}\n\n"
	if rec.Body.String() != want {
		t.Fatalf("body = %q\nwant   %q", rec.Body.String(), want)
	}
}

func TestStreamSanitizesEventName(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	_ = Stream{Run: func(ctx context.Context, emit func(string, any) error) error {
		return emit("lo\ng", 1)
	}}.Serve(rec)
	if !strings.HasPrefix(rec.Body.String(), "event: log\ndata: 1\n\n") {
		t.Fatalf("body = %q", rec.Body.String())
	}
}

func TestStreamCanceledClientIsNotAnError(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	rec := httptest.NewRecorder()
	err := Stream{Ctx: ctx, Run: func(ctx context.Context, emit func(string, any) error) error {
		cancel()
		return ctx.Err()
	}}.Serve(rec)
	if err != nil {
		t.Fatalf("Serve = %v", err)
	}
	if strings.Contains(rec.Body.String(), "event: error") {
		t.Fatalf("error frame sent to a gone client: %q", rec.Body.String())
	}
}

// TestStreamHeartbeat proves an idle stream gets a comment frame within the
// interval, and that a client disconnect ends Serve cleanly.
func TestStreamHeartbeat(t *testing.T) {
	t.Parallel()
	served := make(chan error, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served <- Stream{Ctx: r.Context(), Heartbeat: 20 * time.Millisecond, Run: func(ctx context.Context, emit func(string, any) error) error {
			if err := emit("connected", 1); err != nil {
				return err
			}
			<-ctx.Done()
			return ctx.Err()
		}}.Serve(w)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	br := bufio.NewReader(resp.Body)
	if f := readFrame(t, br); f != "event: connected\ndata: 1\n" {
		t.Fatalf("first frame = %q", f)
	}
	got := make(chan string, 1)
	go func() { got <- readFrame(t, br) }()
	select {
	case f := <-got:
		if !strings.HasPrefix(f, ":") {
			t.Fatalf("heartbeat frame = %q, want a comment", f)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no heartbeat on an idle stream")
	}

	cancel()
	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("Serve after disconnect = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after the client went away")
	}
}

func TestStatusRecorderUnwrapAndFlush(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	sr := &statusRecorder{ResponseWriter: rec, status: 200}
	if sr.Unwrap() != http.ResponseWriter(rec) {
		t.Fatal("Unwrap must return the wrapped writer")
	}
	if err := http.NewResponseController(sr).Flush(); err != nil {
		t.Fatalf("ResponseController.Flush through recorder: %v", err)
	}
	if !rec.Flushed {
		t.Fatal("underlying writer not flushed")
	}
	sr.WriteHeader(418)
	if sr.status != 418 {
		t.Fatalf("status = %d", sr.status)
	}
}
