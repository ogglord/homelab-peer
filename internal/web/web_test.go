package web

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ogglord/homelab-peer/internal/peer"
	"github.com/ogglord/homelab-peer/internal/store"
)

const origin = "https://peer.example"

// fakeAuth signs in code "good" as the operator and code "outsider" as an
// account outside the group.
type fakeAuth struct{ nonce string }

func (f *fakeAuth) AuthURL(_ context.Context, state, nonce, _ string) (string, error) {
	f.nonce = nonce
	return "https://auth.example/authorize?state=" + url.QueryEscape(state), nil
}

func (f *fakeAuth) Exchange(_ context.Context, code, nonce, _ string) (Identity, error) {
	if nonce != f.nonce {
		return Identity{}, io.ErrUnexpectedEOF
	}
	switch code {
	case "good":
		return Identity{Subject: "op", Name: "Operator"}, nil
	case "outsider":
		return Identity{}, ErrNotAllowed
	}
	return Identity{}, io.ErrUnexpectedEOF
}

type fixture struct {
	t   *testing.T
	svc *peer.Service
	st  *store.Store
	h   http.Handler
	now time.Time
}

func newFixture(t *testing.T, auth Authenticator) *fixture {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "peer.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := peer.New(peer.Config{Hostname: "homelab-hub", Heartbeat: time.Hour, EnrolURL: origin + peer.ApproverPath}, peer.NewDBStore(st), log)
	key, err := SessionKey(context.Background(), st)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, svc: svc, st: st, now: time.Now()}
	f.h, err = Handler(svc, peer.EnrolHandler(svc, log), Options{
		PublicURL: origin, Auth: auth, Key: key, Log: log, Now: func() time.Time { return f.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

type resp struct {
	status  int
	body    string
	loc     string
	cookies []*http.Cookie
}

// do serves one request. Unless a header says otherwise, a POST carries the
// browser's same-origin headers.
func (f *fixture) do(method, path string, cookies []*http.Cookie, header ...string) resp {
	f.t.Helper()
	var body io.Reader
	if method == http.MethodPost && path == peer.ApproverPath {
		body = strings.NewReader(header[len(header)-1])
		header = header[:len(header)-1]
	}
	r := httptest.NewRequest(method, origin+path, body)
	if method == http.MethodPost {
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		r.Header.Set("Origin", origin)
	}
	for i := 0; i+1 < len(header); i += 2 {
		r.Header.Set(header[i], header[i+1])
	}
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, r)
	return resp{w.Code, w.Body.String(), w.Header().Get("Location"), w.Result().Cookies()}
}

// signIn runs the sign-in and returns the session cookie.
func (f *fixture) signIn(code string) (resp, []*http.Cookie) {
	f.t.Helper()
	r := f.do(http.MethodGet, "/auth/login", nil)
	if r.status != http.StatusSeeOther || !strings.HasPrefix(r.loc, "https://auth.example/") {
		f.t.Fatalf("login: %d %q", r.status, r.loc)
	}
	u, _ := url.Parse(r.loc)
	state := u.Query().Get("state")
	cb := f.do(http.MethodGet, "/auth/callback?state="+url.QueryEscape(state)+"&code="+code, r.cookies)
	var session []*http.Cookie
	for _, c := range cb.cookies {
		if c.Name == "__Host-peer_session" && c.MaxAge > 0 {
			if !c.Secure || !c.HttpOnly || c.Path != "/" {
				f.t.Fatalf("session cookie attributes: %+v", c)
			}
			session = append(session, c)
		}
	}
	return cb, session
}

func caller(host string, kinds ...peer.Kind) peer.Caller {
	c, err := peer.CallerFromCaps(host+"-node", []peer.CapEntry{{Host: host, Kinds: kinds}})
	if err != nil {
		panic(err)
	}
	return c
}

// seed gives the hub a host, a parked request, a status message and
// their outcomes.
func (f *fixture) seed() {
	f.t.Helper()
	ctx := context.Background()
	homelab := caller("homelab", peer.KindRequest, peer.KindResult, peer.KindStatus)
	ha := caller("homeassistant", peer.KindResult, peer.KindStatus)
	if _, err := f.svc.Hello(ctx, ha, peer.HelloIn{Instance: "ha-1", StartedAt: time.Now(), Version: "abc1234"}); err != nil {
		f.t.Fatal(err)
	}
	if _, err := f.svc.Send(ctx, homelab, peer.Send{ID: "req-1", Kind: peer.KindRequest, Target: "homeassistant", Text: "list add-ons"}); err != nil {
		f.t.Fatal(err)
	}
	if _, err := f.svc.Send(ctx, homelab, peer.Send{ID: "st-1", Kind: peer.KindStatus, Target: "homeassistant", Phase: "progress", Body: "working on it"}); err != nil {
		f.t.Fatal(err)
	}
	waiting, err := f.svc.Requests(ctx, "", 10)
	if err != nil || len(waiting) != 1 {
		f.t.Fatalf("requests: %v %v", waiting, err)
	}
	at := waiting[0].Attempt
	_, token, err := f.svc.Claim(ctx, ha, "req-1", at, "ha-1")
	if err != nil {
		f.t.Fatal(err)
	}
	if _, err := f.svc.Park(ctx, ha, peer.ParkIn{ID: "req-1", Instance: "ha-1", Token: token, Attempt: at + 1, Tool: "Bash", Step: "ha addons restart <mqtt>"}); err != nil {
		f.t.Fatal(err)
	}
}

func phoneKey(t *testing.T) (pub, keyID string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(der), hex.EncodeToString(sum[:])
}

func (f *fixture) enrol(code string) string {
	f.t.Helper()
	pub, kid := phoneKey(f.t)
	body, _ := json.Marshal(map[string]string{"code": code, "public_key": pub, "key_id": kid, "name": "iPhone"})
	if r := f.do(http.MethodPost, peer.ApproverPath, nil, string(body)); r.status != http.StatusOK {
		f.t.Fatalf("enrol: %d %s", r.status, r.body)
	}
	return kid
}

// ── tests ───────────────────────────────────────────────────────────────

// The phone's enrolment and the health probe need no sign-in.
func TestEnrolmentAndHealthStayOpen(t *testing.T) {
	t.Parallel()
	f := newFixture(t, &fakeAuth{})
	if r := f.do(http.MethodGet, "/healthz", nil); r.status != http.StatusOK {
		t.Fatalf("healthz: %d %s", r.status, r.body)
	}
	if r := f.do(http.MethodGet, peer.ApproverPath, nil); r.status != http.StatusOK || !strings.Contains(r.body, `"approver":null`) {
		t.Fatalf("approver: %d %s", r.status, r.body)
	}
	kid := f.enrol(f.svc.MintApproverCode().Code)
	if r := f.do(http.MethodGet, peer.ApproverPath, nil); !strings.Contains(r.body, kid) {
		t.Fatalf("approver after enrolment: %s", r.body)
	}
}

// Without a session a GET goes to sign-in and a POST is refused; nothing
// mints a code.
func TestSignedOutIsKeptOut(t *testing.T) {
	t.Parallel()
	f := newFixture(t, &fakeAuth{})
	for _, p := range []string{"/", "/approver/remove"} {
		if r := f.do(http.MethodGet, p, nil); r.status != http.StatusSeeOther || r.loc != "/auth/login" {
			t.Errorf("GET %s: %d %q", p, r.status, r.loc)
		}
	}
	for _, p := range []string{"/approver/code", "/approver/remove"} {
		if r := f.do(http.MethodPost, p, nil); r.status != http.StatusUnauthorized || strings.Contains(r.body, "hemma://") {
			t.Errorf("POST %s: %d", p, r.status)
		}
	}
	forged := []*http.Cookie{{Name: "__Host-peer_session", Value: "eyJzdWIiOiJvcCJ9.AAAA"}}
	if r := f.do(http.MethodGet, "/", forged); r.status != http.StatusSeeOther {
		t.Errorf("forged cookie: %d", r.status)
	}
}

func TestSignInAdmitsOnlyTheGroup(t *testing.T) {
	t.Parallel()
	f := newFixture(t, &fakeAuth{})
	if r, s := f.signIn("outsider"); r.status != http.StatusForbidden || len(s) != 0 {
		t.Fatalf("outsider: %d %d cookies", r.status, len(s))
	}
	r, s := f.signIn("good")
	if r.status != http.StatusSeeOther || r.loc != "/" || len(s) != 1 {
		t.Fatalf("operator: %d %q %d cookies", r.status, r.loc, len(s))
	}
	if p := f.do(http.MethodGet, "/", s); p.status != http.StatusOK || !strings.Contains(p.body, "Operator") {
		t.Fatalf("page: %d", p.status)
	}
	// The session ends after its lifetime.
	f.now = f.now.Add(sessionTTL + time.Minute)
	if p := f.do(http.MethodGet, "/", s); p.status != http.StatusSeeOther {
		t.Fatalf("expired session: %d", p.status)
	}
}

// A callback whose state does not match the login cookie is refused.
func TestCallbackChecksState(t *testing.T) {
	t.Parallel()
	f := newFixture(t, &fakeAuth{})
	r := f.do(http.MethodGet, "/auth/login", nil)
	cb := f.do(http.MethodGet, "/auth/callback?state=other&code=good", r.cookies)
	if cb.status != http.StatusBadRequest {
		t.Fatalf("wrong state: %d", cb.status)
	}
	if cb := f.do(http.MethodGet, "/auth/callback?state=x&code=good", nil); cb.status != http.StatusBadRequest {
		t.Fatalf("no login cookie: %d", cb.status)
	}
}

// A signed-in POST from another origin (a sibling stack's page) is refused.
func TestCrossOriginPostIsRefused(t *testing.T) {
	t.Parallel()
	f := newFixture(t, &fakeAuth{})
	_, s := f.signIn("good")
	for _, h := range [][]string{
		{"Sec-Fetch-Site", "same-site"},
		{"Sec-Fetch-Site", "cross-site"},
		{"Sec-Fetch-Site", "", "Origin", "https://photos.example"},
		{"Sec-Fetch-Site", "", "Origin", ""},
	} {
		if r := f.do(http.MethodPost, "/approver/code", s, h...); r.status != http.StatusForbidden || strings.Contains(r.body, "hemma://") {
			t.Errorf("%v: %d", h, r.status)
		}
	}
	// Without Sec-Fetch-Site, the page's own Origin passes.
	if r := f.do(http.MethodPost, "/approver/code", s, "Sec-Fetch-Site", ""); r.status != http.StatusOK {
		t.Errorf("same origin: %d", r.status)
	}
}

func TestPageShowsTheHub(t *testing.T) {
	t.Parallel()
	f := newFixture(t, &fakeAuth{})
	f.seed()
	_, s := f.signIn("good")
	r := f.do(http.MethodGet, "/", s)
	if r.status != http.StatusOK {
		t.Fatalf("page: %d %s", r.status, r.body)
	}
	for _, want := range []string{
		"homelab → homeassistant · Bash", "round 1", "not sent yet", "list add-ons",
		"ha addons restart &lt;mqtt&gt;", // escaped
		"homeassistant", "abc1234",
		"working on it", "progress",
		"No phone enrolled", "Enrol a phone",
	} {
		if !strings.Contains(r.body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
}

// Minting shows the QR and the link in the response, never in a URL; the
// phone enrols with it; Remove takes a confirmation and a POST.
func TestEnrolAndRemoveThePhone(t *testing.T) {
	t.Parallel()
	f := newFixture(t, &fakeAuth{})
	_, s := f.signIn("good")
	r := f.do(http.MethodPost, "/approver/code", s)
	if r.status != http.StatusOK || !strings.Contains(r.body, `<svg class="qr"`) || r.loc != "" {
		t.Fatalf("mint: %d %q", r.status, r.loc)
	}
	// Only the QR carries the link: it is in no markup and no URL.
	if strings.Contains(r.body, "hemma://") {
		t.Fatal("the enrolment link is in the page's markup")
	}
	if !strings.Contains(r.body, "data-enrol") || !strings.Contains(r.body, `data-baseline=""`) {
		t.Fatal("the enrolment poll is missing")
	}
	// The test cannot scan the QR: a mint on the service replaces the
	// page's code, and the phone enrols with that one.
	kid := f.enrol(f.svc.MintApproverCode().Code)

	p := f.do(http.MethodGet, "/", s)
	if !strings.Contains(p.body, "iPhone") || !strings.Contains(p.body, "key "+kid[:8]) {
		t.Fatalf("enrolled phone not shown")
	}
	if c := f.do(http.MethodGet, "/approver/remove", s); c.status != http.StatusOK || !strings.Contains(c.body, "Remove iPhone?") {
		t.Fatalf("confirm: %d", c.status)
	}
	if rm := f.do(http.MethodPost, "/approver/remove", s); rm.status != http.StatusSeeOther || rm.loc != "/" {
		t.Fatalf("remove: %d %q", rm.status, rm.loc)
	}
	if _, ok, _ := f.svc.Approver(context.Background()); ok {
		t.Fatal("phone still enrolled")
	}
}

func TestNoAuthenticatorSaysSignInIsNotSetUp(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	if r := f.do(http.MethodGet, "/", nil); r.status != http.StatusServiceUnavailable || !strings.Contains(r.body, "not set up") {
		t.Fatalf("page: %d", r.status)
	}
	if r := f.do(http.MethodGet, "/healthz", nil); r.status != http.StatusOK {
		t.Fatalf("healthz: %d", r.status)
	}
}

func TestClaimsNeedTheGroup(t *testing.T) {
	t.Parallel()
	if _, err := (claims{Groups: []string{"family"}}).identity("s", "peer-admins"); err != ErrNotAllowed {
		t.Fatalf("other group: %v", err)
	}
	if _, err := (claims{}).identity("s", ""); err != ErrNotAllowed {
		t.Fatalf("no group configured: %v", err)
	}
	id, err := (claims{PreferredUsername: "ogge", Groups: []string{"peer-admins"}}).identity("s", "peer-admins")
	if err != nil || id.Name != "ogge" || id.Subject != "s" {
		t.Fatalf("member: %+v %v", id, err)
	}
}

func TestSignedValuesKeepTheirPurpose(t *testing.T) {
	t.Parallel()
	s := signer{key: make([]byte, 32)}
	v, err := s.seal("login", login{State: "x"})
	if err != nil {
		t.Fatal(err)
	}
	var ss session
	if s.open("session", v, &ss) {
		t.Fatal("a login cookie opened as a session")
	}
	var l login
	if !s.open("login", v, &l) || l.State != "x" {
		t.Fatal("login cookie did not open")
	}
	if s.open("login", v[:len(v)-2]+"AA", &l) {
		t.Fatal("tampered cookie opened")
	}
}
