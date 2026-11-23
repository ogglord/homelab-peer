package httpx

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Stream is one server-sent-events response.
//
// Run produces events through emit; each emit writes one frame
//
//	event: <event>\ndata: <json>\n\n
//
// and flushes it, so the client sees progress as it happens. Strict handlers
// wrap a Stream in a tiny adapter that implements the generated
// Visit<Op>Response interface and calls Serve (the generated
// text/event-stream response copies a reader without flushing per event, so
// it is not used).
type Stream struct {
	// Ctx is cancelled when the client goes away; it is passed to Run.
	// A nil Ctx means context.Background().
	Ctx context.Context
	Run func(ctx context.Context, emit func(event string, data any) error) error
	// Heartbeat, when positive, writes a `: ping` comment frame at this
	// interval so an idle long-lived stream survives proxies and the client
	// can tell a dead connection from a quiet one. Zero sends none.
	Heartbeat time.Duration
}

// Serve writes the stream to w. A Run error becomes a final `event: error`
// frame carrying {"type":"error","message":...}; Serve itself only returns an
// error when the connection can no longer be written to.
func (s Stream) Serve(w http.ResponseWriter) error {
	ctx := s.Ctx
	if ctx == nil {
		ctx = context.Background()
	}
	rc := http.NewResponseController(w)

	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	if err := rc.Flush(); err != nil {
		return fmt.Errorf("sse: response is not flushable: %w", err)
	}

	// mu serialises the frames of Run and of the heartbeat.
	var mu sync.Mutex
	write := func(frame string) error {
		mu.Lock()
		defer mu.Unlock()
		if _, err := io.WriteString(w, frame); err != nil {
			return err
		}
		return rc.Flush()
	}
	emit := func(event string, data any) error {
		payload, err := json.Marshal(data)
		if err != nil {
			return fmt.Errorf("sse: marshal %q event: %w", event, err)
		}
		return write(fmt.Sprintf("event: %s\ndata: %s\n\n", sanitizeEvent(event), payload))
	}

	if s.Heartbeat > 0 {
		stop := make(chan struct{})
		done := make(chan struct{})
		go func() {
			defer close(done)
			t := time.NewTicker(s.Heartbeat)
			defer t.Stop()
			for {
				select {
				case <-stop:
					return
				case <-ctx.Done():
					return
				case <-t.C:
					// A failed write means the client is gone; Run learns
					// that from ctx or from its own next emit.
					_ = write(": ping\n\n")
				}
			}
		}()
		// Nothing may write to w once Serve has returned.
		defer func() { close(stop); <-done }()
	}

	if err := s.Run(ctx, emit); err != nil {
		if ctx.Err() != nil {
			return nil // client went away; nobody to tell
		}
		return emit("error", map[string]string{"type": "error", "message": err.Error()})
	}
	return nil
}

// sanitizeEvent keeps a caller-supplied event name on one line.
func sanitizeEvent(s string) string {
	return strings.NewReplacer("\r", "", "\n", "").Replace(s)
}
