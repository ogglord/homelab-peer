package peerclient

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// frame is one server-sent event.
type frame struct{ event, data string }

// StreamError is the hub's final `error` frame: the stream was superseded by
// a newer instance, fell behind, or failed.
type StreamError struct{ Message string }

func (e *StreamError) Error() string { return "hub ended the stream: " + e.Message }

// maxLine bounds one SSE line; a message body is at most 16 KiB.
const maxLine = 1 << 20

// readFrames parses an event stream the way the old React dashboard's SseParser did:
// lines end in CRLF, LF or CR; `:` lines are comments; a blank line ends a
// frame; multi-line data joins with LF; an unnamed frame is `message`. line
// is called for every line, comments included (the idle watchdog).
func readFrames(r io.Reader, line func(), onFrame func(frame) error) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), maxLine)
	sc.Split(splitLines)
	var event string
	var data []string
	flush := func() error {
		if len(data) == 0 && event == "" {
			return nil
		}
		f := frame{event: event, data: strings.Join(data, "\n")}
		if f.event == "" {
			f.event = "message"
		}
		event, data = "", nil
		return onFrame(f)
	}
	for sc.Scan() {
		line()
		l := sc.Text()
		if l == "" {
			if err := flush(); err != nil {
				return err
			}
			continue
		}
		if strings.HasPrefix(l, ":") {
			continue
		}
		field, value, _ := strings.Cut(l, ":")
		value = strings.TrimPrefix(value, " ")
		switch field {
		case "event":
			event = value
		case "data":
			data = append(data, value)
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	return flush()
}

// splitLines splits on CRLF, LF or a lone CR.
func splitLines(data []byte, atEOF bool) (int, []byte, error) {
	i := bytes.IndexAny(data, "\r\n")
	if i < 0 {
		if atEOF && len(data) > 0 {
			return len(data), data, nil
		}
		return 0, nil, nil
	}
	if data[i] == '\n' {
		return i + 1, data[:i], nil
	}
	// A CR at the end of the buffer may be the first half of CRLF.
	if i == len(data)-1 && !atEOF {
		return 0, nil, nil
	}
	if i+1 < len(data) && data[i+1] == '\n' {
		return i + 2, data[:i], nil
	}
	return i + 1, data[:i], nil
}

// Stream opens the caller's message stream for instance after cursor and
// calls onMessage for each message frame, in order, and onRequest (when set)
// for each request frame, until the stream ends.
// opened runs once the hub answered 200. A stream silent for longer than
// idle (the hub pings every 20 s) is treated as dead. It returns nil when
// the hub closed the stream cleanly, a *StreamError for the hub's error
// frame, a *Problem when the hub refused the stream, or the read error.
func (c *Client) Stream(ctx context.Context, instance string, after int64, idle time.Duration, opened func(), onMessage func(Message) error, onRequest func(RequestFrame) error) error {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	q := url.Values{"instance": {instance}, "after": {strconv.FormatInt(after, 10)}}
	resp, err := c.send(ctx, http.MethodGet, "/peer/stream?"+q.Encode(), nil, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return readProblem(resp)
	}
	if opened != nil {
		opened()
	}
	errIdle := fmt.Errorf("no data from the hub for %s", idle)
	watchdog := time.AfterFunc(idle, func() { cancel(errIdle) })
	defer watchdog.Stop()

	err = readFrames(resp.Body, func() { watchdog.Reset(idle) }, func(f frame) error {
		switch f.event {
		case "message":
			var m Message
			if err := json.Unmarshal([]byte(f.data), &m); err != nil {
				return fmt.Errorf("undecodable message frame: %w", err)
			}
			return onMessage(m)
		case "request":
			if onRequest == nil {
				return nil
			}
			var r RequestFrame
			if err := json.Unmarshal([]byte(f.data), &r); err != nil {
				return fmt.Errorf("undecodable request frame: %w", err)
			}
			return onRequest(r)
		case "error":
			var e struct {
				Message string `json:"message"`
			}
			_ = json.Unmarshal([]byte(f.data), &e)
			return &StreamError{Message: e.Message}
		}
		return nil
	})
	if cause := context.Cause(ctx); cause == errIdle {
		return &UnreachableError{Hub: c.base, Err: errIdle}
	}
	return err
}
