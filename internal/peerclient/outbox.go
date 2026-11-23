package peerclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// Outbox holds the run reports the hub has not taken yet, a result or a park,
// one file per request attempt in a 0700 directory, and posts them again on
// reconnect. Status goes out live or not at all.
type Outbox struct{ dir string }

// outboxEntry is one stored report: exactly one of Result and Park.
type outboxEntry struct {
	Result *ResultRequest `json:"result,omitempty"`
	Park   *ParkRequest   `json:"park,omitempty"`
}

func (e outboxEntry) post(ctx context.Context, hub HubRunAPI) error {
	if e.Park != nil {
		return hub.Park(ctx, *e.Park)
	}
	return hub.PostResult(ctx, *e.Result)
}

// OpenOutbox opens (creating) the outbox directory.
func OpenOutbox(dir string) (*Outbox, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Outbox{dir: dir}, nil
}

// put stores e, replacing an earlier copy for the same attempt.
func (o *Outbox) put(ref RunRef, e outboxEntry) (string, error) {
	data, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	tmp, err := writeTemp(o.dir, ".report-*", data)
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp)
	name := o.path(ref)
	return name, os.Rename(tmp, name)
}

// writeTemp writes data to a new temp file in dir and returns its name, for
// the caller to move into place and then remove. A failed write leaves no
// file behind.
func writeTemp(dir, pattern string, data []byte) (string, error) {
	f, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return "", err
	}
	_, err = f.Write(data)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

// Post stores r, then tries to post it once; the stored copy stays when the
// hub could not take it.
func (o *Outbox) Post(ctx context.Context, hub HubRunAPI, r ResultRequest) error {
	return o.store(ctx, hub, r.RunRef, outboxEntry{Result: &r})
}

// PostPark stores p, then tries to report it once, like Post.
func (o *Outbox) PostPark(ctx context.Context, hub HubRunAPI, p ParkRequest) error {
	return o.store(ctx, hub, p.RunRef, outboxEntry{Park: &p})
}

func (o *Outbox) store(ctx context.Context, hub HubRunAPI, ref RunRef, e outboxEntry) error {
	name, err := o.put(ref, e)
	if err != nil {
		return err
	}
	return o.send(ctx, hub, name, e)
}

// Flush posts every stored report, in file name order, and returns how many
// remain. A report the hub refuses for good (a 4xx other than 408 and 429,
// such as a request no longer running) is dropped; one it could not take
// stays.
func (o *Outbox) Flush(ctx context.Context, hub HubRunAPI) (int, error) {
	names, err := o.names()
	if err != nil {
		return 0, err
	}
	left := 0
	var firstErr error
	for _, name := range names {
		data, err := os.ReadFile(name)
		if err != nil {
			left++
			continue
		}
		var e outboxEntry
		if json.Unmarshal(data, &e) != nil || (e.Result == nil) == (e.Park == nil) {
			_ = os.Remove(name) // unreadable; it can never be posted
			continue
		}
		if err := o.send(ctx, hub, name, e); err != nil {
			left++
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return left, firstErr
}

// Pending is the request ids with a stored report. The listener reports them
// in hello as runs it still holds, so the hub does not fail them as
// listener_lost before their report lands.
func (o *Outbox) Pending() []string {
	names, _ := o.names()
	var ids []string
	for _, name := range names {
		if id := requestOf(name); id != "" && !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}
	return ids
}

// Drop removes every stored report for these request ids (ones the hub no
// longer holds as running, so it would refuse them).
func (o *Outbox) Drop(ids []string) {
	names, _ := o.names()
	for _, name := range names {
		if slices.Contains(ids, requestOf(name)) {
			_ = os.Remove(name)
		}
	}
}

func (o *Outbox) names() ([]string, error) {
	return filepath.Glob(filepath.Join(o.dir, "*.json")) // sorted
}

func (o *Outbox) send(ctx context.Context, hub HubRunAPI, name string, e outboxEntry) error {
	err := e.post(ctx, hub)
	var p *Problem
	if err == nil || (errors.As(err, &p) && p.Status >= 400 && p.Status < 500 &&
		p.Status != http.StatusRequestTimeout && p.Status != http.StatusTooManyRequests) {
		_ = os.Remove(name)
	}
	return err
}

func (o *Outbox) path(ref RunRef) string {
	// Request ids are URL-safe; the attempt makes each run's report its own.
	return filepath.Join(o.dir, filepath.Base(ref.RequestID)+"-"+strconv.Itoa(ref.Attempt)+".json")
}

// requestOf is the request id in a report's file name (<id>-<attempt>.json).
func requestOf(name string) string {
	base := strings.TrimSuffix(filepath.Base(name), ".json")
	if i := strings.LastIndexByte(base, '-'); i > 0 {
		return base[:i]
	}
	return ""
}
