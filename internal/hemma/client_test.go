package hemma

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

const testToken = "0123456789abcdef0123456789abcdef-token"

type call struct {
	method, path, query, auth string
	body                      map[string]any
}

// hub is a fake Hemma hub: it records each call and answers with reply.
func hub(t *testing.T, reply func(w http.ResponseWriter, r *http.Request)) (*Client, func() []call) {
	t.Helper()
	var mu sync.Mutex
	var calls []call
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := call{method: r.Method, path: r.URL.Path, query: r.URL.RawQuery, auth: r.Header.Get("Authorization")}
		if raw, _ := io.ReadAll(r.Body); len(raw) > 0 {
			if err := json.Unmarshal(raw, &c.body); err != nil {
				t.Errorf("body is not JSON: %s", raw)
			}
		}
		mu.Lock()
		calls = append(calls, c)
		mu.Unlock()
		reply(w, r)
	}))
	t.Cleanup(srv.Close)
	return &Client{BaseURL: srv.URL + "/", TokenFile: tokenFile(t, testToken+"\n")}, func() []call {
		mu.Lock()
		defer mu.Unlock()
		return append([]call(nil), calls...)
	}
}

func tokenFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "TOKEN")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func answer(status int, body string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}
}

func TestNotifyPayload(t *testing.T) {
	t.Parallel()
	c, calls := hub(t, answer(200, `{"id":"n1","sent":1,"failed":0}`))
	err := c.Notify(context.Background(), Notification{
		Title: "Disk", Message: "/pool is 95% full", Tag: "audit:disk",
		URL: "https://homelab.example.com/storage", InterruptionLevel: LevelTimeSensitive,
	})
	if err != nil {
		t.Fatal(err)
	}
	got := calls()
	if len(got) != 1 || got[0].method != http.MethodPost || got[0].path != "/notify/admin" || got[0].auth != "Bearer "+testToken {
		t.Fatalf("calls = %+v", got)
	}
	b, _ := json.Marshal(got[0].body)
	want := `{"data":{"group":"homelab","push":{"interruption-level":"time-sensitive"},"tag":"audit:disk","url":"https://homelab.example.com/storage"},"message":"/pool is 95% full","title":"Disk"}`
	if string(b) != want {
		t.Fatalf("payload\n%s\nwant\n%s", b, want)
	}
}

func TestNotifyOmitsEmptyTagAndURL(t *testing.T) {
	t.Parallel()
	c, calls := hub(t, answer(200, `{}`))
	if err := c.Notify(context.Background(), Notification{Title: "t", Message: "m", InterruptionLevel: LevelActive}); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(calls()[0].body)
	if want := `{"data":{"group":"homelab","push":{"interruption-level":"active"}},"message":"m","title":"t"}`; string(b) != want {
		t.Fatalf("payload %s, want %s", b, want)
	}
}

func TestNon2xxIsAnError(t *testing.T) {
	t.Parallel()
	c, _ := hub(t, answer(503, `{"error":"no APNs key configured"}`))
	err := c.Notify(context.Background(), Notification{Title: "t", Message: "m"})
	var se *StatusError
	if !errors.As(err, &se) || se.Status != 503 || se.Message != "no APNs key configured" {
		t.Fatalf("err = %v", err)
	}
}

func TestTokenFileRequired(t *testing.T) {
	t.Parallel()
	c, calls := hub(t, answer(200, `{}`))
	c.TokenFile = tokenFile(t, " \n")
	if err := c.Notify(context.Background(), Notification{Title: "t", Message: "m"}); err == nil {
		t.Fatal("empty token file: no error")
	}
	c.TokenFile = filepath.Join(t.TempDir(), "missing")
	if err := c.Notify(context.Background(), Notification{Title: "t", Message: "m"}); err == nil {
		t.Fatal("missing token file: no error")
	}
	if len(calls()) != 0 {
		t.Fatal("sent a request without a token")
	}
}

func TestPostApproval(t *testing.T) {
	t.Parallel()
	c, calls := hub(t, answer(200, `{"id":"ap_1","repeat":false,"sent":1,"failed":0}`))
	id, err := c.PostApproval(context.Background(), Prompt{
		Request: "req_1", Round: 2, Fingerprint: "fp", Kind: "step", Host: "homeassistant", Sender: "macbook",
		Text: "", Step: "ha auth create", Reason: "", ExpiresAt: 1762878600,
		Signer: Signer{KeyID: "kid", PublicKey: "pk", Name: "Admin"},
	})
	if err != nil || id != "ap_1" {
		t.Fatalf("id=%q err=%v", id, err)
	}
	got := calls()[0]
	if got.path != "/homelab/approvals" || got.auth != "Bearer "+testToken {
		t.Fatalf("call %+v", got)
	}
	// text and reason are sent even when empty; url is left out.
	for _, k := range []string{"text", "reason"} {
		if v, ok := got.body[k]; !ok || v != "" {
			t.Errorf("%s = %v (present %v), want \"\"", k, v, ok)
		}
	}
	if _, ok := got.body["url"]; ok {
		t.Error("empty url sent")
	}
}

func TestPostApprovalWithoutID(t *testing.T) {
	t.Parallel()
	c, _ := hub(t, answer(200, `{}`))
	if _, err := c.PostApproval(context.Background(), Prompt{}); err == nil {
		t.Fatal("an answer without id is not an error")
	}
}

func TestPostStateConflictIsAlreadyReported(t *testing.T) {
	t.Parallel()
	status := 409
	c, calls := hub(t, func(w http.ResponseWriter, r *http.Request) { answer(status, `{"error":"already applied"}`)(w, r) })
	if err := c.PostState(context.Background(), "ap/1", StateApplied, ""); err != nil {
		t.Fatalf("409: %v", err)
	}
	got := calls()[0]
	if got.method != http.MethodPost || got.path != "/homelab/approvals/ap/1/state" || got.body["state"] != "applied" {
		t.Fatalf("call %+v", got)
	}
	if _, ok := got.body["note"]; ok {
		t.Error("empty note sent")
	}
	status = 404
	var se *StatusError
	if err := c.PostState(context.Background(), "x", StateRefused, "bad signature"); !errors.As(err, &se) || se.Status != 404 {
		t.Fatalf("404: %v", err)
	}
	if calls()[1].body["note"] != "bad signature" {
		t.Fatalf("note not sent: %+v", calls()[1])
	}
}

func TestDecisions(t *testing.T) {
	t.Parallel()
	c, calls := hub(t, answer(200, `{"decisions":[{"seq":7,"id":"ap_1","request":"req_1","round":2,"fingerprint":"fp",
		"decision":"approve","expires_at":1762878600,"key_id":"kid","signature":"sig","device_name":"Admin","decided_at":1762876860}],"cursor":7}`))
	got, err := c.Decisions(context.Background(), 5, 25*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	want := Decision{Seq: 7, ID: "ap_1", Request: "req_1", Round: 2, Fingerprint: "fp", Decision: "approve",
		ExpiresAt: 1762878600, KeyID: "kid", Signature: "sig", DeviceName: "Admin", DecidedAt: 1762876860}
	if got.Cursor != 7 || len(got.Decisions) != 1 || got.Decisions[0] != want {
		t.Fatalf("decisions = %+v", got)
	}
	cl := calls()[0]
	if cl.method != http.MethodGet || cl.path != "/homelab/decisions" || cl.query != "after=5&wait=25" || cl.auth != "Bearer "+testToken {
		t.Fatalf("call %+v", cl)
	}
}
