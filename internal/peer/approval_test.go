package peer

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// count runs a count query through its own read-only handle.
func (h *hub) count(t *testing.T, q string, args ...any) int {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+h.dbPath+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// call serves one request on handler h and returns the status and body.
func call(t *testing.T, h http.Handler, method, path string, body any) (int, []byte) {
	t.Helper()
	var b bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&b).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, &b)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.Bytes()
}

func problemCode(b []byte) string {
	var p struct{ Code string }
	_ = json.Unmarshal(b, &p)
	return p.Code
}

// fakePrompter records prompts and withdrawals; fail makes delivery fail.
type fakePrompter struct {
	mu        sync.Mutex
	fail      bool
	sent      []Request
	withdrawn []Request
}

func (f *fakePrompter) SendPrompt(_ context.Context, r Request) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return "", errors.New("hub down")
	}
	f.sent = append(f.sent, r)
	return "prompt-" + r.ID, nil
}

func (f *fakePrompter) Withdraw(_ context.Context, r Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.withdrawn = append(f.withdrawn, r)
}

func (f *fakePrompter) counts() (sent, withdrawn int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.sent), len(f.withdrawn)
}

// parkStep claims id at its current attempt and parks it on a step.
func (h *hub) parkStep(t *testing.T, id, step string) Request {
	t.Helper()
	at := h.req(t, id).Attempt
	token := h.claim(t, id, at)
	r, err := h.svc.Park(context.Background(), haCaller, ParkIn{ID: id, Instance: haInst, Token: token, Attempt: at + 1, Tool: "Bash", Step: step})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// decide applies a decision on id's current round and fingerprint.
func (h *hub) decide(t *testing.T, id string, approve bool) (Request, error) {
	t.Helper()
	r := h.req(t, id)
	return h.svc.ApplyDecision(context.Background(), Decision{
		RequestID: id, Round: r.ApprovalCycles, Fingerprint: r.Fingerprint, Approve: approve, ExpiresAt: h.svc.now().Add(5 * time.Minute),
	})
}

func sha(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// Rounds are unbounded: a fifth park parks like the first, and each
// approval re-queues the request with the approved step.
func TestParkRoundsAreUnbounded(t *testing.T) {
	t.Parallel()
	h, _ := reqHub(t)
	h.hello(t, haCaller, haInst)
	h.request(t, "r1", "homeassistant")
	for round := int64(1); round <= 5; round++ {
		r := h.parkStep(t, "r1", "rm x")
		if r.State != ReqParked || r.ApprovalCycles != round || r.ParkKind != ParkStep || r.Fingerprint != stepHash {
			t.Fatalf("park %d: %+v", round, r)
		}
		a, err := h.decide(t, "r1", true)
		if err != nil || a.State != ReqApproved || a.StepHash != stepHash {
			t.Fatalf("approve %d: %+v %v", round, a, err)
		}
	}
	if ms := h.results(t, "r1"); len(ms) != 0 {
		t.Fatalf("result messages %+v", ms)
	}
}

// The fingerprint a decision must name, per park kind.
func TestParkFingerprintPerKind(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h, _ := reqHub(t)
	h.hello(t, haCaller, haInst)
	h.request(t, "r1", "homeassistant")
	if r := h.parkStep(t, "r1", "rm x"); r.Fingerprint != stepHash || r.ParkKind != ParkStep {
		t.Fatalf("step park: %+v", r)
	}
	if _, err := h.decide(t, "r1", true); err != nil {
		t.Fatal(err)
	}
	token := h.claim(t, "r1", 1)
	if _, err := h.svc.Park(ctx, haCaller, ParkIn{ID: "r1", Instance: haInst, Token: token, Attempt: 2, Kind: ParkLimit, Tool: "Bash"}); err == nil {
		t.Fatal("a limit park with a tool was accepted")
	}
	r, err := h.svc.Park(ctx, haCaller, ParkIn{ID: "r1", Instance: haInst, Token: token, Attempt: 2, Kind: ParkLimit, Reason: "budget\nreached"})
	if err != nil {
		t.Fatal(err)
	}
	if r.ParkKind != ParkLimit || r.ApprovalCycles != 2 || r.Fingerprint != sha("limit:2") ||
		r.Tool != "" || r.Step != "" || r.StepHash != "" || r.ParkReason != "budget reached" {
		t.Fatalf("limit park: %+v", r)
	}
}

// Limits: the claim answers what is left; parks and results report the
// run's cost (cumulative, kept at its maximum) and time (added up); an
// approved limit park raises the allowance.
func TestLimitAccounting(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h, clk := reqHub(t)
	h.hello(t, haCaller, haInst)
	h.request(t, "r1", "homeassistant")
	ha := h.as(t, haCaller)
	claim := func(attempt int64) claimResultJSON {
		t.Helper()
		r := ha.do(http.MethodPost, "/api/peer/claim", map[string]any{"request_id": "r1", "attempt": attempt, "instance": haInst})
		var c claimResultJSON
		if r.status != http.StatusOK || json.Unmarshal(r.body, &c) != nil {
			t.Fatalf("claim: %d %s", r.status, r.body)
		}
		return c
	}
	c := claim(0)
	if c.RemainingUSD != 10 || c.RemainingSeconds != 7200 || c.Request.ExpiresAt == nil || !c.Request.ExpiresAt.Equal(t0.Add(7200*time.Second+RunGrace)) {
		t.Fatalf("first claim: %v USD, %d s, expires %v", c.RemainingUSD, c.RemainingSeconds, c.Request.ExpiresAt)
	}
	if _, err := h.svc.Park(ctx, haCaller, ParkIn{ID: "r1", Instance: haInst, Token: c.RunToken, Attempt: 1, Tool: "Bash", Step: testStep, SpentUSD: 4.5, UsedSeconds: 600}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.decide(t, "r1", true); err != nil {
		t.Fatal(err)
	}
	clk.set(t0.Add(time.Hour))
	c = claim(1)
	if c.RemainingUSD != 5.5 || c.RemainingSeconds != 6600 || c.Request.ExpiresAt == nil || !c.Request.ExpiresAt.Equal(t0.Add(time.Hour+6600*time.Second+RunGrace)) {
		t.Fatalf("second claim: %v USD, %d s, expires %v", c.RemainingUSD, c.RemainingSeconds, c.Request.ExpiresAt)
	}
	// A lower cost report keeps the maximum; time adds up.
	r, err := h.svc.Park(ctx, haCaller, ParkIn{ID: "r1", Instance: haInst, Token: c.RunToken, Attempt: 2, Kind: ParkLimit, SpentUSD: 3, UsedSeconds: 100})
	if err != nil || r.SpentUSD != 4.5 || r.UsedSeconds != 700 {
		t.Fatalf("limit park: %+v %v", r, err)
	}
	a, err := h.decide(t, "r1", true)
	if err != nil || a.AllowanceUSD != 20 || a.AllowanceSeconds != 14400 {
		t.Fatalf("limit approval: %+v %v", a, err)
	}
	c = claim(2)
	if c.RemainingUSD != 15.5 || c.RemainingSeconds != 13700 {
		t.Fatalf("after the limit approval: %v USD, %d s", c.RemainingUSD, c.RemainingSeconds)
	}
	res, _, err := h.svc.PostResult(ctx, haCaller, ResultIn{ID: "r1", Instance: haInst, Attempt: 3, State: ReqDone, SpentUSD: 12, UsedSeconds: 50})
	if err != nil || res.SpentUSD != 12 || res.UsedSeconds != 750 {
		t.Fatalf("result: %+v %v", res, err)
	}
	if _, err := h.svc.Park(ctx, haCaller, ParkIn{ID: "r1", Instance: haInst, Token: c.RunToken, Attempt: 3, Tool: "Bash", Step: testStep, SpentUSD: -1}); err == nil {
		t.Fatal("a negative cost was accepted")
	}
}

// A decision applies only to the parked round and fingerprint it names,
// before its own expiry and the park's; anything else changes nothing.
func TestApplyDecision(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h, clk := reqHub(t)
	h.hello(t, haCaller, haInst)
	h.request(t, "r1", "homeassistant")
	parked := h.parkStep(t, "r1", "rm x")
	exp := clk.now().Add(time.Minute)
	refused := func(d Decision, want DecisionRefused) {
		t.Helper()
		_, err := h.svc.ApplyDecision(ctx, d)
		var got DecisionRefused
		if !errors.As(err, &got) || got != want {
			t.Fatalf("%+v: %v, want %v", d, err, want)
		}
	}
	refused(Decision{RequestID: "r1", Round: 2, Fingerprint: stepHash, Approve: true, ExpiresAt: exp}, RefusedStale)
	refused(Decision{RequestID: "r1", Round: 1, Fingerprint: strings.Repeat("cd", 32), Approve: true, ExpiresAt: exp}, RefusedStale)
	refused(Decision{RequestID: "r1", Round: 1, Fingerprint: stepHash, Approve: true, ExpiresAt: clk.now()}, RefusedExpired)
	refused(Decision{RequestID: "nope", Round: 1, Fingerprint: stepHash, Approve: true, ExpiresAt: exp}, RefusedUnknown)
	if r := h.req(t, "r1"); r.State != ReqParked || !r.UpdatedAt.Equal(parked.UpdatedAt) {
		t.Fatalf("a refused decision changed the request: %+v", r)
	}

	r, err := h.svc.ApplyDecision(ctx, Decision{RequestID: "r1", Round: 1, Fingerprint: stepHash, Approve: true, ExpiresAt: exp})
	if err != nil || r.State != ReqApproved || r.StepHash != stepHash || !r.ExpiresAt.Equal(clk.now().Add(QueueTTL)) {
		t.Fatalf("approve: %+v %v", r, err)
	}
	refused(Decision{RequestID: "r1", Round: 1, Fingerprint: stepHash, Approve: false, ExpiresAt: exp}, RefusedNotParked)

	h.request(t, "r2", "homeassistant")
	h.parkStep(t, "r2", "rm y")
	d, err := h.decide(t, "r2", false)
	if err != nil || d.State != ReqDenied {
		t.Fatalf("deny: %+v %v", d, err)
	}
	if ms := h.results(t, "r2"); len(ms) != 1 || ms[0].Body != "denied" {
		t.Fatalf("deny result messages %+v", ms)
	}

	// A park past its expiry the sweep has not reached yet is refused.
	h.request(t, "r3", "homeassistant")
	h.parkStep(t, "r3", testStep)
	clk.set(clk.now().Add(QueueTTL))
	refused(Decision{RequestID: "r3", Round: 1, Fingerprint: stepHash, Approve: true, ExpiresAt: clk.now().Add(time.Minute)}, RefusedExpired)
}

// A park sends its prompt and records the delivery; an undelivered one is
// sent again by the sweep, once; a parked request that expires is withdrawn.
func TestPromptOnParkSweepAndWithdraw(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h, clk := reqHub(t)
	p := &fakePrompter{fail: true}
	h.svc.SetPrompter(p)
	h.hello(t, haCaller, haInst)
	h.request(t, "r1", "homeassistant")
	h.parkStep(t, "r1", "rm x")
	if r := h.req(t, "r1"); !r.NotifiedAt.IsZero() || r.PromptID != "" {
		t.Fatalf("an undelivered prompt was recorded: %+v", r)
	}
	p.mu.Lock()
	p.fail = false
	p.mu.Unlock()
	for range 2 {
		if err := h.svc.SweepApprovals(ctx, clk.now()); err != nil {
			t.Fatal(err)
		}
	}
	if sent, _ := p.counts(); sent != 1 {
		t.Fatalf("%d prompts, want 1", sent)
	}
	if r := h.req(t, "r1"); r.NotifiedAt.IsZero() || r.PromptID != "prompt-r1" {
		t.Fatalf("delivery not recorded: %+v", r)
	}
	clk.set(clk.now().Add(QueueTTL + time.Minute))
	if _, err := h.svc.Sweep(ctx, clk.now()); err != nil {
		t.Fatal(err)
	}
	if _, withdrawn := p.counts(); withdrawn != 1 || p.withdrawn[0].ID != "r1" || p.withdrawn[0].PromptID != "prompt-r1" {
		t.Fatalf("withdrawn %+v", p.withdrawn)
	}
}

// R13, R14: a run may send a request to another host, which becomes its
// child; a child's run may not send requests, and no run may send one to
// its own host.
func TestRunRequestChaining(t *testing.T) {
	t.Parallel()
	h, _ := reqHub(t)
	haFull := caller("homeassistant", allKinds)
	lab, ha := h.as(t, homelab), h.as(t, haFull)
	h.hello(t, homelab, "lab-1")
	h.request(t, "top", "homelab")
	_, token, err := h.svc.Claim(context.Background(), homelab, "top", 0, "lab-1")
	if err != nil {
		t.Fatal(err)
	}
	if r := lab.send(map[string]any{"id": "self", "kind": "request", "target": "homelab", "text": "loop"}, "X-Peer-Run-Token", token); r.status != http.StatusForbidden || r.code() != "self_request" {
		t.Fatalf("to its own host: %d %s", r.status, r.body)
	}
	if r := lab.send(map[string]any{"id": "child", "kind": "request", "target": "homeassistant", "text": "do more"}, "X-Peer-Run-Token", token); r.status != http.StatusOK {
		t.Fatalf("child: %d %s", r.status, r.body)
	}
	if c := h.req(t, "child"); c.ParentID != "top" || c.Sender != "homelab" {
		t.Fatalf("child %+v", c)
	}
	h.hello(t, haFull, haInst)
	_, childToken, err := h.svc.Claim(context.Background(), haFull, "child", 0, haInst)
	if err != nil {
		t.Fatal(err)
	}
	if r := ha.send(map[string]any{"id": "grandchild", "kind": "request", "target": "homelab", "text": "and more"}, "X-Peer-Run-Token", childToken); r.status != http.StatusForbidden || r.code() != "child_request" {
		t.Fatalf("grandchild: %d %s", r.status, r.body)
	}
	for _, id := range []string{"self", "grandchild"} {
		if _, ok, _ := h.svc.st.Request(context.Background(), id); ok {
			t.Fatalf("refused request %s was stored", id)
		}
	}
	if r := lab.send(statusBody("s1", "homeassistant"), "X-Peer-Run-Token", "not-a-token"); r.status != http.StatusForbidden || r.code() != "invalid_run_token" {
		t.Fatalf("status with a bad token: %d %s", r.status, r.body)
	}
}

// phoneKey is an enrolment body for a fresh key on curve c.
func phoneKey(t *testing.T, c elliptic.Curve) (publicKey, keyID string, der []byte) {
	t.Helper()
	k, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err = x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(der), hex.EncodeToString(sum[:]), der
}

// R21, R22: enrolment takes the current code once, before it expires, and
// only an unpadded base64url P-256 SPKI whose SHA-256 is the key id; a new
// phone replaces the old one, and revoking leaves none.
func TestApproverEnrolment(t *testing.T) {
	t.Parallel()
	h, clk := reqHub(t)
	h.svc.cfg.EnrolURL = "https://peer.example.com/api/peer/approvers"
	var enrolled []string
	h.svc.cfg.OnEnrolled = func(name string) { enrolled = append(enrolled, name) }
	phone, admin := EnrolHandler(h.svc, h.log()), AdminHandler(h.svc, h.log())
	mint := func() ApproverCodeJSON {
		t.Helper()
		code, body := call(t, admin, http.MethodPost, AdminApproverCode, nil)
		var c ApproverCodeJSON
		if code != http.StatusOK || json.Unmarshal(body, &c) != nil {
			t.Fatalf("mint: %d %s", code, body)
		}
		return c
	}
	enrol := func(code, pub, keyID, name string) (int, []byte) {
		return call(t, phone, http.MethodPost, ApproverPath, map[string]any{"code": code, "public_key": pub, "key_id": keyID, "name": name})
	}
	approver := func() *ApproverJSON {
		t.Helper()
		code, body := call(t, phone, http.MethodGet, ApproverPath, nil)
		var s ApproverStateJSON
		if code != http.StatusOK || json.Unmarshal(body, &s) != nil {
			t.Fatalf("get: %d %s", code, body)
		}
		return s.Approver
	}

	c := mint()
	if want := "hemma://homelab?u=" + url.QueryEscape("https://peer.example.com/api/peer/approvers") + "&c=" + c.Code; c.Link != want {
		t.Fatalf("link %q, want %q", c.Link, want)
	}
	if !c.ExpiresAt.Equal(t0.Add(EnrolCodeTTL)) {
		t.Fatalf("code expires %v", c.ExpiresAt)
	}
	pub, keyID, der := phoneKey(t, elliptic.P256())
	p384, p384ID, _ := phoneKey(t, elliptic.P384())
	padded := base64.URLEncoding.EncodeToString(der)
	if !strings.HasSuffix(padded, "=") {
		t.Fatal("the padded form has no padding; pick another key size")
	}
	for name, tc := range map[string]struct {
		code, pub, keyID, problem string
	}{
		"wrong code":       {"not-the-code", pub, keyID, "invalid_code"},
		"key id mismatch":  {c.Code, pub, strings.Repeat("0", 64), "invalid_key"},
		"padded base64url": {c.Code, padded, keyID, "invalid_key"},
		"standard base64":  {c.Code, base64.StdEncoding.EncodeToString(der), keyID, "invalid_key"},
		"not P-256":        {c.Code, p384, p384ID, "invalid_key"},
	} {
		if code, body := enrol(tc.code, tc.pub, tc.keyID, "iPhone"); problemCode(body) != tc.problem {
			t.Errorf("%s: %d %s", name, code, body)
		}
	}
	if approver() != nil {
		t.Fatal("a refused enrolment stored an approver")
	}

	// The code expires after 10 minutes.
	clk.set(t0.Add(EnrolCodeTTL))
	if code, body := enrol(c.Code, pub, keyID, "iPhone"); problemCode(body) != "invalid_code" {
		t.Fatalf("expired code: %d %s", code, body)
	}

	c = mint()
	if code, body := enrol(c.Code, pub, keyID, "Operator iPhone"); code != http.StatusOK || !bytes.Contains(body, []byte(keyID)) {
		t.Fatalf("enrol: %d %s", code, body)
	}
	if a := approver(); a == nil || a.KeyID != keyID || a.Name != "Operator iPhone" {
		t.Fatalf("approver %+v", a)
	}
	if code, body := enrol(c.Code, pub, keyID, "again"); problemCode(body) != "invalid_code" {
		t.Fatalf("code reused: %d %s", code, body)
	}

	// A second phone replaces the first.
	pub2, keyID2, _ := phoneKey(t, elliptic.P256())
	if code, body := enrol(mint().Code, pub2, keyID2, "iPad"); code != http.StatusOK {
		t.Fatalf("second phone: %d %s", code, body)
	}
	if a := approver(); a == nil || a.KeyID != keyID2 {
		t.Fatalf("approver after the second phone %+v", a)
	}
	if stored, ok, err := h.svc.Approver(context.Background()); err != nil || !ok || stored.PublicKey != pub2 {
		t.Fatalf("stored approver %+v %v %v", stored, ok, err)
	}
	if strings.Join(enrolled, ",") != "Operator iPhone,iPad" {
		t.Fatalf("OnEnrolled calls %v", enrolled)
	}

	if code, body := call(t, admin, http.MethodDelete, AdminApprover, nil); code != http.StatusNoContent {
		t.Fatalf("revoke: %d %s", code, body)
	}
	if a := approver(); a != nil {
		t.Fatalf("approver after revoke %+v", a)
	}
}

// A step park's hash (and fingerprint) is the hub's SHA-256 of the step text
// it stores, whatever hash the run posted: an approval names exactly the
// text the operator saw. A step park without text, or with more than the
// stored limit, is refused rather than cut.
func TestStepParkHashIsTheStepText(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h, _ := reqHub(t)
	h.hello(t, haCaller, haInst)
	h.request(t, "r1", "homeassistant")
	token := h.claim(t, "r1", 0)
	park := func(step, hash string) (Request, error) {
		return h.svc.Park(ctx, haCaller, ParkIn{ID: "r1", Instance: haInst, Token: token, Attempt: 1, Tool: "Bash", Step: step})
	}
	for name, step := range map[string]string{"empty": "", "overlong": "Bash " + strings.Repeat("é", maxStep)} {
		if _, err := park(step, stepHash); err == nil {
			t.Fatalf("%s step accepted", name)
		}
	}
	const harmless = `Bash {"command":"echo harmless"}`
	forged := sha(`Bash {"command":"rm -rf /pool"}`)
	r, err := park(harmless, forged)
	if err != nil {
		t.Fatal(err)
	}
	if r.Step != harmless || r.StepHash != sha(harmless) || r.Fingerprint != sha(harmless) {
		t.Fatalf("park %+v: hash %s, want %s", r, r.StepHash, sha(harmless))
	}
}

// The hook parks a step without the run's cost; the listener's park report
// that follows, for the same attempt, instance and token, records the cost
// (kept at its maximum) and run time (added) on the parked request without
// a new round or prompt. The next claim's remaining allowance counts it.
func TestListenerParkReportAddsUsageToTheParkedRequest(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h, _ := reqHub(t)
	p := &fakePrompter{}
	h.svc.SetPrompter(p)
	h.hello(t, haCaller, haInst)
	h.request(t, "r1", "homeassistant")
	token := h.claim(t, "r1", 0)
	park := func(tok string, spent float64, used int64) (Request, error) {
		return h.svc.Park(ctx, haCaller, ParkIn{ID: "r1", Instance: haInst, Token: tok, Attempt: 1, Tool: "Bash", Step: testStep, SpentUSD: spent, UsedSeconds: used})
	}
	if _, err := park(token, 0, 0); err != nil { // the hook
		t.Fatal(err)
	}
	r, err := park(token, 3.25, 400) // the listener, after the run stopped
	if err != nil || r.State != ReqParked || r.ApprovalCycles != 1 || r.SpentUSD != 3.25 || r.UsedSeconds != 400 {
		t.Fatalf("listener report: %+v %v", r, err)
	}
	// A run stopped before it printed its cost reports time only: the cost
	// is never lowered.
	if r, err = park(token, 0, 5); err != nil || r.SpentUSD != 3.25 || r.UsedSeconds != 405 {
		t.Fatalf("report without a cost: %+v %v", r, err)
	}
	if _, err := park("not-the-token", 9, 9); err == nil {
		t.Fatal("another token's report was taken")
	}
	if r := h.req(t, "r1"); r.SpentUSD != 3.25 || r.UsedSeconds != 405 {
		t.Fatalf("another token's report changed the usage: %+v", r)
	}
	if sent, _ := p.counts(); sent != 1 {
		t.Fatalf("prompts sent %d, want 1", sent)
	}
	if _, err := h.decide(t, "r1", true); err != nil {
		t.Fatal(err)
	}
	c, _, err := h.svc.Claim(ctx, haCaller, "r1", 1, haInst)
	if err != nil || c.RemainingUSD() != AllowanceUSD-3.25 || c.RemainingSeconds() != AllowanceSeconds-405 {
		t.Fatalf("next claim: %+v %v", c, err)
	}
}

// signerPrompter is a fakePrompter that, like the Hemma prompter, signs
// each prompt for the phone enrolled when it is sent, and has none to send
// for when no phone is.
type signerPrompter struct {
	fakePrompter
	svc     *Service
	signers []string // per sent prompt: request, round and key id
}

func (p *signerPrompter) SendPrompt(ctx context.Context, r Request) (string, error) {
	a, ok, err := p.svc.Approver(ctx)
	if err != nil || !ok {
		return "", errors.New("no approver phone is enrolled")
	}
	p.mu.Lock()
	p.signers = append(p.signers, fmt.Sprintf("%s@%d:%s", r.ID, r.ApprovalCycles, a.KeyID))
	p.mu.Unlock()
	return p.fakePrompter.SendPrompt(ctx, r)
}

// Enrolling a phone, or revoking it, moves every parked request to a new
// round: its prompt (signed for the old phone) is withdrawn, the round's
// fingerprint is recomputed (a limit park's names the round), and the
// sweep prompts it again for the phone enrolled then. A decision for the
// old round is stale.
func TestApproverChangeRoundsParkedRequestsAgain(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h, clk := reqHub(t)
	p := &signerPrompter{svc: h.svc}
	h.svc.SetPrompter(p)
	enrol := func(name string) string {
		t.Helper()
		pub, keyID, _ := phoneKey(t, elliptic.P256())
		if _, err := h.svc.EnrolApprover(ctx, EnrolIn{Code: h.svc.MintApproverCode().Code, PublicKey: pub, KeyID: keyID, Name: name}); err != nil {
			t.Fatal(err)
		}
		return keyID
	}
	first := enrol("iPhone")
	h.hello(t, haCaller, haInst)
	h.request(t, "step", "homeassistant")
	h.parkStep(t, "step", testStep)
	h.request(t, "limit", "homeassistant")
	token := h.claim(t, "limit", 0)
	if _, err := h.svc.Park(ctx, haCaller, ParkIn{ID: "limit", Instance: haInst, Token: token, Attempt: 1, Kind: ParkLimit}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(p.signers, ","); got != "step@1:"+first+",limit@1:"+first {
		t.Fatalf("first prompts %s", got)
	}

	second := enrol("iPad")
	for id, fp := range map[string]string{"step": stepHash, "limit": sha("limit:2")} {
		r := h.req(t, id)
		if r.State != ReqParked || r.ApprovalCycles != 2 || r.Fingerprint != fp || !r.NotifiedAt.IsZero() || r.PromptID != "" {
			t.Fatalf("%s after the new phone: %+v", id, r)
		}
	}
	var withdrawn []string
	for _, w := range p.withdrawn {
		withdrawn = append(withdrawn, w.PromptID)
	}
	if got := strings.Join(withdrawn, ","); got != "prompt-step,prompt-limit" && got != "prompt-limit,prompt-step" {
		t.Fatalf("withdrawn prompts %s", got)
	}
	_, err := h.svc.ApplyDecision(ctx, Decision{RequestID: "step", Round: 1, Fingerprint: stepHash, Approve: true, ExpiresAt: clk.now().Add(time.Minute)})
	if refused := DecisionRefused(""); !errors.As(err, &refused) || refused != RefusedStale {
		t.Fatalf("old round's decision: %v", err)
	}
	if err := h.svc.SweepApprovals(ctx, clk.now()); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(p.signers[2:], ","); got != "step@2:"+second+",limit@2:"+second && got != "limit@2:"+second+",step@2:"+second {
		t.Fatalf("prompts after the new phone %s", got)
	}

	if err := h.svc.RevokeApprover(ctx); err != nil {
		t.Fatal(err)
	}
	if r := h.req(t, "step"); r.ApprovalCycles != 3 || !r.NotifiedAt.IsZero() || r.PromptID != "" {
		t.Fatalf("step after revoke: %+v", r)
	}
	if _, n := p.counts(); n != 4 {
		t.Fatalf("withdrawn %d prompts, want 4", n)
	}
	if err := h.svc.SweepApprovals(ctx, clk.now()); err != nil {
		t.Fatal(err)
	}
	if len(p.signers) != 4 {
		t.Fatalf("prompted with no phone enrolled: %v", p.signers)
	}
}
