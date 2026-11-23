package peer

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeIdentity answers every connection with one caller (or err) and
// records the remote addresses it was asked about.
type fakeIdentity struct {
	c   Caller
	err error

	mu    sync.Mutex
	addrs []string
}

func (f *fakeIdentity) Identify(_ context.Context, remoteAddr string) (Caller, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.addrs = append(f.addrs, remoteAddr)
	return f.c, f.err
}

// agent is one tailnet caller talking to the hub's agent handler.
type agent struct {
	t   *testing.T
	url string
	id  *fakeIdentity
}

func (h *hub) agent(t *testing.T, id *fakeIdentity) *agent {
	t.Helper()
	srv := httptest.NewServer(AgentHandler(h.svc, id, h.log()))
	t.Cleanup(srv.Close)
	return &agent{t: t, url: srv.URL, id: id}
}

func (h *hub) as(t *testing.T, c Caller) *agent { return h.agent(t, &fakeIdentity{c: c}) }

type reply struct {
	status int
	body   []byte
}

func (r reply) code() string {
	var p struct{ Code string }
	_ = json.Unmarshal(r.body, &p)
	return p.Code
}

func (a *agent) do(method, path string, body any, header ...string) reply {
	a.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case []byte:
		rd = bytes.NewReader(b)
	default:
		raw, _ := json.Marshal(b)
		rd = bytes.NewReader(raw)
	}
	req, _ := http.NewRequest(method, a.url+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		a.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return reply{resp.StatusCode, b}
}

func (a *agent) send(body map[string]any, header ...string) reply {
	return a.do(http.MethodPost, "/api/peer/send", body, header...)
}

func statusBody(id, target string) map[string]any {
	return map[string]any{"id": id, "kind": "status", "target": target, "phase": "info", "body": "hi"}
}

// AE2: a connection whose identity cannot be established is refused.
func TestUnknownCallerIsUnauthorized(t *testing.T) {
	t.Parallel()
	h := newHub(t)
	for _, err := range []error{ErrUnknownCaller, errors.New("whois: no such peer")} {
		r := h.agent(t, &fakeIdentity{err: err}).send(statusBody("s1", "homeassistant"))
		if r.status != http.StatusUnauthorized || r.code() != "unknown_caller" {
			t.Fatalf("%v: got %d %s", err, r.status, r.body)
		}
	}
	r := h.agent(t, &fakeIdentity{err: ErrNoCapability}).send(statusBody("s1", "homeassistant"))
	if r.status != http.StatusForbidden || r.code() != "no_capability" {
		t.Fatalf("no capability: got %d %s", r.status, r.body)
	}
	if ms, _ := h.svc.Messages(context.Background(), 10); len(ms) != 0 {
		t.Fatalf("rows after refused callers: %+v", ms)
	}
}

// An untagged node carrying the homelab capability is accepted and bound to
// the host its capability names.
func TestUntaggedNodeBoundToCapabilityHost(t *testing.T) {
	t.Parallel()
	h := newHub(t)
	c, err := CallerFromCaps("ogge-desktop", []CapEntry{{Host: "homelab", Kinds: allKinds}})
	if err != nil {
		t.Fatal(err)
	}
	a := h.as(t, c)
	r := a.do(http.MethodPost, "/api/peer/hello", map[string]any{"instance": "i1", "started_at": "2026-10-29T12:00:00Z"})
	if r.status != http.StatusOK || !strings.Contains(string(r.body), `"host":"homelab"`) || !strings.Contains(string(r.body), `"node":"ogge-desktop"`) {
		t.Fatalf("hello: %d %s", r.status, r.body)
	}
	if r := a.send(statusBody("s1", "homeassistant")); r.status != http.StatusOK {
		t.Fatalf("send: %d %s", r.status, r.body)
	}
	ms, _ := h.svc.Messages(context.Background(), 10)
	if len(ms) != 1 || ms[0].Sender != "homelab" {
		t.Fatalf("messages = %+v, want one from homelab", ms)
	}
}

// The sender is the connection's identity: a differing body sender is
// refused and forwarded-address headers change nothing.
func TestSenderComesFromConnection(t *testing.T) {
	t.Parallel()
	h := newHub(t)
	a := h.as(t, haCaller)
	body := statusBody("s1", "homelab")
	body["sender"] = "homelab"
	if r := a.send(body); r.status != http.StatusForbidden || r.code() != "sender_mismatch" {
		t.Fatalf("spoofed sender: %d %s", r.status, r.body)
	}
	r := a.send(statusBody("s2", "homelab"), "X-Forwarded-For", "100.64.0.99", "X-Real-Ip", "100.64.0.99")
	if r.status != http.StatusOK {
		t.Fatalf("send: %d %s", r.status, r.body)
	}
	for _, addr := range a.id.addrs {
		if strings.Contains(addr, "100.64.0.99") {
			t.Fatalf("identity asked about a forwarded address: %v", a.id.addrs)
		}
	}
	ms, _ := h.svc.Messages(context.Background(), 10)
	if len(ms) != 1 || ms[0].Sender != "homeassistant" {
		t.Fatalf("messages = %+v", ms)
	}
}

// Reading a message whose sender and target are both other hosts is 403;
// its target reads it and marks it read.
func TestReadMessageOnlyForSenderOrTarget(t *testing.T) {
	t.Parallel()
	h := newHub(t)
	if r := h.as(t, homelab).send(statusBody("s1", "laptop")); r.status != http.StatusOK {
		t.Fatalf("send: %d %s", r.status, r.body)
	}
	if r := h.as(t, haCaller).do(http.MethodGet, "/api/peer/messages/homelab/s1", nil); r.status != http.StatusForbidden || r.code() != "not_permitted" {
		t.Fatalf("other host: %d %s", r.status, r.body)
	}
	laptop := h.as(t, statusOnly)
	if r := laptop.do(http.MethodGet, "/api/peer/inbox", nil); r.status != http.StatusOK || !strings.Contains(string(r.body), `"id":"s1"`) {
		t.Fatalf("inbox: %d %s", r.status, r.body)
	}
	if r := laptop.do(http.MethodGet, "/api/peer/messages/homelab/s1", nil); r.status != http.StatusOK || !strings.Contains(string(r.body), `"read":true`) {
		t.Fatalf("target read: %d %s", r.status, r.body)
	}
	if r := laptop.do(http.MethodGet, "/api/peer/inbox", nil); r.status != http.StatusOK || string(bytes.TrimSpace(r.body)) != "[]" {
		t.Fatalf("inbox after read: %d %s", r.status, r.body)
	}
	if r := laptop.do(http.MethodGet, "/api/peer/messages/homelab/nope", nil); r.status != http.StatusNotFound || r.code() != "unknown_message" {
		t.Fatalf("missing message: %d %s", r.status, r.body)
	}
}

func TestVersionState(t *testing.T) {
	t.Parallel()
	const hub = "79826c3f0e1d2a3b4c5d6e7f8091a2b3c4d5e6f7"
	for _, tc := range []struct{ version, hub, want string }{
		{"79826c3", hub, "current"},
		{"79826c3-dirty", hub, "current"},
		{"d1b4675", hub, "behind"},
		{"", hub, "unknown"},
		{"dev", hub, "unknown"},
		{"dirty", hub, "unknown"},
		{"79826c3", "", "unknown"},
	} {
		if got := versionState(tc.version, tc.hub); got != tc.want {
			t.Errorf("versionState(%q, %q) = %q, want %q", tc.version, tc.hub, got, tc.want)
		}
	}
}

// The identity check answers who the caller is and registers nothing, so it
// neither displaces a running listener nor is refused as superseded.
func TestIdentityIsReadOnly(t *testing.T) {
	t.Parallel()
	h := newHub(t)
	a := h.as(t, haCaller)
	if r := a.do(http.MethodPost, "/api/peer/hello", map[string]any{"instance": "i1", "started_at": "2026-10-29T12:00:00Z"}); r.status != http.StatusOK {
		t.Fatalf("hello: %d %s", r.status, r.body)
	}
	r := a.do(http.MethodGet, "/api/peer/identity", nil)
	var id identityJSON
	if err := json.Unmarshal(r.body, &id); r.status != http.StatusOK || err != nil {
		t.Fatalf("identity: %d %s", r.status, r.body)
	}
	if id.Host != haCaller.Host || id.Node != haCaller.Node || len(id.Kinds) != len(haCaller.Kinds) || id.Cancel == nil || len(id.Cancel) != 0 {
		t.Fatalf("identity = %+v, want %+v", id, haCaller)
	}
	// The listener's instance still holds the host: its stream is accepted.
	s, err := h.svc.broker.subscribe(haCaller.Host, "i1")
	if err != nil {
		t.Fatalf("listener instance after identity: %v", err)
	}
	h.svc.broker.unsubscribe(s)
	if r := h.agent(t, &fakeIdentity{err: ErrNoCapability}).do(http.MethodGet, "/api/peer/identity", nil); r.status != http.StatusForbidden || r.code() != "no_capability" {
		t.Fatalf("no capability: %d %s", r.status, r.body)
	}
}

// Any identified caller reads recent requests and messages across every
// host; state filters requests only.
func TestListActivityAcrossCircle(t *testing.T) {
	t.Parallel()
	h := newHub(t)
	lab := h.as(t, homelab)
	if r := lab.send(map[string]any{"id": "r1", "kind": "request", "target": "homeassistant", "text": "make a user"}); r.status != http.StatusOK {
		t.Fatalf("request: %d %s", r.status, r.body)
	}
	if r := lab.send(statusBody("s1", "homeassistant")); r.status != http.StatusOK {
		t.Fatalf("status: %d %s", r.status, r.body)
	}

	// laptop is neither sender nor target of anything listed.
	r := h.as(t, statusOnly).do(http.MethodGet, "/api/peer/list", nil)
	if r.status != http.StatusOK {
		t.Fatalf("list: %d %s", r.status, r.body)
	}
	var got activityJSON
	if err := json.Unmarshal(r.body, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Requests) != 1 || got.Requests[0].ID != "r1" || got.Requests[0].State != "waiting" {
		t.Fatalf("requests = %+v", got.Requests)
	}
	if len(got.Messages) != 1 || got.Messages[0].ID != "s1" {
		t.Fatalf("messages = %+v", got.Messages)
	}

	r = lab.do(http.MethodGet, "/api/peer/list?state=done&limit=5", nil)
	if r.status != http.StatusOK || !strings.Contains(string(r.body), `"requests":[]`) || !strings.Contains(string(r.body), `"id":"s1"`) {
		t.Fatalf("filtered: %d %s", r.status, r.body)
	}
	if r := lab.do(http.MethodGet, "/api/peer/list?state=bogus", nil); r.status != http.StatusBadRequest {
		t.Fatalf("bad state: %d %s", r.status, r.body)
	}
	if r := h.agent(t, &fakeIdentity{err: ErrUnknownCaller}).do(http.MethodGet, "/api/peer/list", nil); r.status != http.StatusUnauthorized {
		t.Fatalf("unknown caller: %d %s", r.status, r.body)
	}
}

// The removed secret handover: a secret, or a request or status carrying
// its members, is refused with a 400 and leaves nothing behind.
func TestSecretHandoverIsRefused(t *testing.T) {
	t.Parallel()
	h := newHub(t)
	a := h.as(t, homelab)
	for name, body := range map[string]map[string]any{
		"secret":            {"id": "x1", "kind": "secret", "target": "homeassistant", "name": "mqtt/P", "value": "v"},
		"declared names":    {"id": "r1", "kind": "request", "target": "homeassistant", "text": "t", "secret_names": []string{"mqtt/P"}},
		"status with value": {"id": "s1", "kind": "status", "target": "homeassistant", "phase": "info", "value": "v"},
	} {
		if r := a.send(body); r.status != http.StatusBadRequest || r.code() != "invalid_message" || bytes.Contains(r.body, []byte(`"v"`)) {
			t.Errorf("%s: %d %s", name, r.status, r.body)
		}
	}
	if outs, _ := h.svc.Outcomes(context.Background(), 10); len(outs) != 0 {
		t.Fatalf("outcome rows: %+v", outs)
	}
}

// Wire compatibility: the JSON members of every agent answer are exactly
// those the hub had in homelab-daemon (its OpenAPI schemas), so a deployed
// peer binary of any version keeps decoding them.
func TestWireMembersMatchTheOldAPI(t *testing.T) {
	t.Parallel()
	keys := func(v any) string {
		raw, _ := json.Marshal(v)
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		var ks []string
		for k := range m {
			ks = append(ks, k)
		}
		slices.Sort(ks)
		return strings.Join(ks, ",")
	}
	now := time.Now()
	for name, tc := range map[string]struct {
		v    any
		want string
	}{
		"PeerRequest": {requestOut(Request{ID: "r"}), "allowance_seconds,allowance_usd,approval_cycles,attempt,claimed_at,created_at,delivered_at," +
			"expires_at,fingerprint,id,instance,notified_at,parent_id,park_kind,park_reason,prompt_id,reason,result_secrets,secret_names," +
			"sender,spent_usd,state,step,step_hash,summary,target,text,tool,updated_at,used_seconds"},
		"PeerRequestFrame": {frameOut(Request{ID: "r", ExpiresAt: now}), "approval_cycles,attempt,created_at,expires_at,id,parent_id,secret_names,sender,state,step_hash,target,text"},
		"PeerMessage":      {messageOut(Message{ID: "m"}), "body,created_at,delivered,id,kind,phase,read,request_id,sender,seq,target"},
		"PeerIdentity":     {identityOut(homelab, nil), "cancel,host,kinds,node,secrets"},
		"PeerSendResult":   {sendResultJSON{}, "id,kind,outcome,reason,replayed"},
		"PeerClaimResult":  {claimResultJSON{}, "remaining_seconds,remaining_usd,request,run_token"},
		"PeerResultAck":    {resultAckJSON{}, "discarded,request"},
		"PeerActivity":     {activityJSON{}, "messages,requests"},
	} {
		if got := keys(tc.v); got != tc.want {
			t.Errorf("%s members\n got %s\nwant %s", name, got, tc.want)
		}
	}
	// Lists are never null: older clients range over them.
	raw, _ := json.Marshal(requestOut(Request{ID: "r"}))
	if !bytes.Contains(raw, []byte(`"secret_names":[]`)) || !bytes.Contains(raw, []byte(`"result_secrets":[]`)) {
		t.Errorf("request lists: %s", raw)
	}
}

// The enrolment listener serves the phone's two calls and a health probe,
// nothing else: no code minting, no revoke, no agent operation.
func TestEnrolHandlerServesOnlyEnrolment(t *testing.T) {
	t.Parallel()
	h := newHub(t)
	srv := httptest.NewServer(EnrolHandler(h.svc, h.log()))
	t.Cleanup(srv.Close)
	call := func(method, path string, body any) reply {
		var rd io.Reader
		if body != nil {
			raw, _ := json.Marshal(body)
			rd = bytes.NewReader(raw)
		}
		req, _ := http.NewRequest(method, srv.URL+path, rd)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return reply{resp.StatusCode, b}
	}
	if r := call(http.MethodGet, "/healthz", nil); r.status != http.StatusOK {
		t.Fatalf("healthz: %d %s", r.status, r.body)
	}
	if r := call(http.MethodGet, ApproverPath, nil); r.status != http.StatusOK || string(bytes.TrimSpace(r.body)) != `{"approver":null}` {
		t.Fatalf("no approver: %d %s", r.status, r.body)
	}
	for _, mp := range [][2]string{
		{http.MethodPost, "/api/peer/approvers/code"},
		{http.MethodDelete, ApproverPath},
		{http.MethodPost, "/api/peer/hello"},
		{http.MethodGet, AdminStatus},
	} {
		if r := call(mp[0], mp[1], map[string]any{}); r.status != http.StatusNotFound && r.status != http.StatusMethodNotAllowed {
			t.Errorf("%s %s: %d %s", mp[0], mp[1], r.status, r.body)
		}
	}
	if r := call(http.MethodPost, ApproverPath, map[string]any{"code": "nope", "public_key": "x", "key_id": "y", "name": "phone"}); r.status != http.StatusForbidden || r.code() != "invalid_code" {
		t.Fatalf("wrong code: %d %s", r.status, r.body)
	}
	code := h.svc.MintApproverCode()
	pub, kid, _ := phoneKey(t, elliptic.P256())
	if r := call(http.MethodPost, ApproverPath, map[string]any{"code": code.Code, "public_key": pub, "key_id": kid, "name": "phone"}); r.status != http.StatusOK || r.code() != "" {
		t.Fatalf("enrol: %d %s", r.status, r.body)
	}
	if r := call(http.MethodGet, ApproverPath, nil); r.status != http.StatusOK || !strings.Contains(string(r.body), `"key_id":"`+kid+`"`) {
		t.Fatalf("approver: %d %s", r.status, r.body)
	}
}

// The admin socket's handler mints a code whose link names the enrolment
// URL, shows and revokes the phone, and reports the hub.
func TestAdminHandler(t *testing.T) {
	t.Parallel()
	h := newHub(t)
	srv := httptest.NewServer(AdminHandler(h.svc, h.log()))
	t.Cleanup(srv.Close)
	resp, err := http.Post(srv.URL+AdminApproverCode, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	var c ApproverCodeJSON
	_ = json.NewDecoder(resp.Body).Decode(&c)
	resp.Body.Close()
	if c.Code == "" || !strings.HasPrefix(c.Link, "hemma://homelab?u=https%3A%2F%2Fpeer.example%2Fapi%2Fpeer%2Fapprovers&c=") {
		t.Fatalf("code = %+v", c)
	}
	req, _ := http.NewRequest(http.MethodDelete, srv.URL+AdminApprover, nil)
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke: %v %v", resp, err)
	}
	resp, err = http.Get(srv.URL + AdminStatus)
	if err != nil {
		t.Fatal(err)
	}
	var st HubJSON
	_ = json.NewDecoder(resp.Body).Decode(&st)
	resp.Body.Close()
	if st.Node != "homelab-hub" || st.Hosts == nil || st.IPs == nil {
		t.Fatalf("status = %+v", st)
	}
}

func sendResult(t *testing.T, r reply) sendResultJSON {
	t.Helper()
	if r.status != http.StatusOK {
		t.Fatalf("reply %d %s, want 200", r.status, r.body)
	}
	var out sendResultJSON
	if err := json.Unmarshal(r.body, &out); err != nil {
		t.Fatal(err)
	}
	return out
}
