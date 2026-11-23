package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ogglord/homelab-peer/internal/peerclient"
	"github.com/ogglord/homelab-peer/internal/peerclient/hubtest"
)

var (
	homelabCaller = hubtest.Caller("homelab", "request", "result", "status")
	haCaller      = hubtest.Caller("homeassistant", "result", "status")
)

type result struct {
	code        int
	out, stderr string
}

func (r result) json(t *testing.T, s string) map[string]any {
	t.Helper()
	var v map[string]any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatalf("not JSON: %q", s)
	}
	return v
}

// cliMu serialises in-process CLI runs: urfave/cli writes its shared
// help and version flags on every run, a data race between parallel tests.
var cliMu sync.Mutex

func peerCmd(stdin string, args ...string) result {
	cliMu.Lock()
	defer cliMu.Unlock()
	var out, errb bytes.Buffer
	code := run(append([]string{"peer"}, args...), strings.NewReader(stdin), &out, &errb)
	return result{code, out.String(), errb.String()}
}

// The removed secret commands are gone from the CLI.
func TestNoSecretCommands(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"--hub", "http://127.0.0.1:1", "send", "secret", "--target", "homelab", "--name", "a/B", "--value-stdin"},
		{"--hub", "http://127.0.0.1:1", "secret", "get", "a/B"},
	} {
		if r := peerCmd("v\n", args...); r.code == 0 {
			t.Errorf("%v exited 0: %+v", args, r)
		}
	}
}

func TestSendStatusHubUnreachable(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hub := "http://" + ln.Addr().String()
	ln.Close()

	r := peerCmd("", "--json", "--hub", hub, "send", "status", "--target", "homelab", "--phase", "info", "hello")
	if r.code == 0 {
		t.Fatalf("exit 0: %+v", r)
	}
	got := r.json(t, r.stderr)
	if got["success"] != false || got["code"] != "hub_unreachable" || got["hub"] != hub || !strings.Contains(got["error"].(string), "unreachable") {
		t.Fatalf("problem %v", got)
	}
}

func TestInboxAndResult(t *testing.T) {
	t.Parallel()
	h := hubtest.New(t)
	ha, lab := h.Serve(haCaller), h.Serve(homelabCaller)
	if r := peerCmd("", "--json", "--hub", lab.URL(), "send", "status", "--target", "homeassistant",
		"--phase", "done", "--request", "req-1", "--id", "st-1", "frigate", "user", "created"); r.code != 0 {
		t.Fatalf("send: %+v", r)
	}

	inbox := func() []any {
		r := peerCmd("", "--json", "--hub", ha.URL(), "inbox")
		if r.code != 0 {
			t.Fatalf("inbox: %+v", r)
		}
		return r.json(t, r.out)["messages"].([]any)
	}
	ms := inbox()
	if len(ms) != 1 {
		t.Fatalf("inbox %v", ms)
	}
	m := ms[0].(map[string]any)
	if m["id"] != "st-1" || m["sender"] != "homelab" || m["phase"] != "done" || m["body"] != "frigate user created" || m["request_id"] != "req-1" {
		t.Fatalf("message %v", m)
	}

	r := peerCmd("", "--json", "--hub", ha.URL(), "result", "homelab", "st-1")
	if r.code != 0 {
		t.Fatalf("result: %+v", r)
	}
	if got := r.json(t, r.out)["message"].(map[string]any); got["id"] != "st-1" || got["read"] != true {
		t.Fatalf("result message %v", got)
	}
	if ms := inbox(); len(ms) != 0 {
		t.Fatalf("read message still in inbox: %v", ms)
	}
}

func TestDoctorReportsChecksAndIdentity(t *testing.T) {
	t.Parallel()
	h := hubtest.New(t)
	ha := h.Serve(haCaller)
	caddy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "dashboard mutations are refused from the Home Assistant box", http.StatusForbidden)
		}
	}))
	defer caddy.Close()

	r := peerCmd("", "--json", "--hub", ha.URL(), "doctor", "--dashboard", caddy.URL)
	if r.code != 0 {
		t.Fatalf("doctor: %+v", r)
	}
	got := r.json(t, r.out)
	var names []string
	for _, c := range got["checks"].([]any) {
		c := c.(map[string]any)
		names = append(names, c["name"].(string))
		if c["ok"] != true {
			t.Fatalf("check failed: %v", c)
		}
	}
	if want := "tailnet_reach hub_http identity capability dashboard_mutations_unreachable"; strings.Join(names, " ") != want {
		t.Fatalf("checks %v, want %s", names, want)
	}
	id := got["identity"].(map[string]any)
	if id["host"] != "homeassistant" || id["node"] != "homeassistant-node" || len(id["kinds"].([]any)) != 2 {
		t.Fatalf("identity %v", id)
	}

	// Anything but Caddy's refusal means a mutation would get through.
	open := httptest.NewServer(http.NotFoundHandler())
	defer open.Close()
	r = peerCmd("", "--json", "--hub", ha.URL(), "doctor", "--dashboard", open.URL)
	if r.code == 0 || !strings.Contains(r.out, `"name":"dashboard_mutations_unreachable","ok":false`) {
		t.Fatalf("open dashboard: %+v", r)
	}
}

// dashboardCheck runs doctor with args and returns its exit code and the
// dashboard_mutations_unreachable check.
func dashboardCheck(t *testing.T, hub string, args ...string) (int, map[string]any) {
	t.Helper()
	r := peerCmd("", append([]string{"--json", "--hub", hub, "doctor"}, args...)...)
	for _, c := range r.json(t, r.out)["checks"].([]any) {
		if c := c.(map[string]any); c["name"] == "dashboard_mutations_unreachable" {
			return r.code, c
		}
	}
	t.Fatalf("no dashboard check: %+v", r)
	return 0, nil
}

// Without --dashboard the probe is skipped and doctor still succeeds.
func TestDoctorSkipsDashboardProbeByDefault(t *testing.T) {
	t.Parallel()
	ha := hubtest.New(t).Serve(haCaller)
	code, c := dashboardCheck(t, ha.URL())
	if code != 0 || c["ok"] != true || c["skipped"] != true || !strings.HasPrefix(c["detail"].(string), "skipped") {
		t.Fatalf("exit %d, check %v", code, c)
	}
}

// A refused TCP connect proves the dashboard unreachable; a DNS or TLS
// failure is inconclusive and fails the check.
func TestDoctorDashboardProbeErrors(t *testing.T) {
	t.Parallel()
	ha := hubtest.New(t).Serve(haCaller)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := "http://" + ln.Addr().String()
	ln.Close()
	if code, c := dashboardCheck(t, ha.URL(), "--dashboard", closed); code != 0 || c["ok"] != true {
		t.Fatalf("refused connect: exit %d, check %v", code, c)
	}

	untrusted := httptest.NewTLSServer(http.NotFoundHandler())
	defer untrusted.Close()
	for origin, class := range map[string]string{
		"https://peer-doctor-probe.invalid": "dns",
		untrusted.URL:                       "tls",
	} {
		code, c := dashboardCheck(t, ha.URL(), "--dashboard", origin)
		if code == 0 || c["ok"] != false || !strings.HasPrefix(c["detail"].(string), "inconclusive: "+class) {
			t.Fatalf("%s: exit %d, check %v", origin, code, c)
		}
	}
}

// A listener that a newer instance holds the host against exits 3, which
// the unit does not restart on.
func TestListenSupersededExitsThree(t *testing.T) {
	t.Parallel()
	ha := hubtest.New(t).Serve(haCaller)
	cl, err := peerclient.New(ha.URL())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cl.Hello(context.Background(), peerclient.Hello{Instance: "newer", StartedAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if r := peerCmd("", "--hub", ha.URL(), "listen"); r.code != exitSuperseded || exitSuperseded != 3 {
		t.Fatalf("exit %d, want 3: %+v", r.code, r)
	}
}

func TestListPrintsRequestsAndMessages(t *testing.T) {
	t.Parallel()
	h := hubtest.New(t)
	ha, lab := h.Serve(haCaller), h.Serve(homelabCaller)
	h.Request(homelabCaller, "req-1", "homeassistant", "make a user")
	if r := peerCmd("", "--json", "--hub", lab.URL(), "send", "status", "--target", "homeassistant",
		"--phase", "done", "--request", "req-1", "--id", "st-1", "done"); r.code != 0 {
		t.Fatalf("send: %+v", r)
	}
	r := peerCmd("", "--json", "--hub", ha.URL(), "list", "--limit", "10")
	if r.code != 0 {
		t.Fatalf("list: %+v", r)
	}
	got := r.json(t, r.out)
	rs, ms := got["requests"].([]any), got["messages"].([]any)
	if len(rs) != 1 || rs[0].(map[string]any)["id"] != "req-1" || rs[0].(map[string]any)["state"] == nil {
		t.Fatalf("requests %v", rs)
	}
	if len(ms) != 1 || ms[0].(map[string]any)["request_id"] != "req-1" {
		t.Fatalf("messages %v", ms)
	}
	r = peerCmd("", "--json", "--hub", ha.URL(), "list", "--state", "done")
	if r.code != 0 || len(r.json(t, r.out)["requests"].([]any)) != 0 {
		t.Fatalf("filtered list: %+v", r)
	}
}
