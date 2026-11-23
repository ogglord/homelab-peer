// Package web is the hub's page on the enrolment listener (peer.<domain>):
// the hub's state, the hosts, what waits for approval, recent messages and
// outcomes, and the approver phone, which the signed-in operator enrols
// (a QR code of the one-time link) or removes.
//
// The phone's own enrolment calls and the health probe stay open; every
// other route needs the operator signed in through Pocket ID, and every
// POST must come from the page itself.
package web

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/ogglord/homelab-peer/internal/httpx"
	"github.com/ogglord/homelab-peer/internal/peer"
)

// recent is how many messages, outcomes and parked requests the page lists.
const recent = 50

//go:embed templates/*.html
var templateFS embed.FS

// Options configure the page.
type Options struct {
	// PublicURL is the page's origin as the browser sees it, e.g.
	// https://peer.example.com. Cookies are Secure and __Host- over https.
	PublicURL string
	// Auth signs the operator in; nil answers every page "sign-in is not
	// set up".
	Auth Authenticator
	// Key signs the cookies (SessionKey).
	Key []byte
	Log *slog.Logger
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

type server struct {
	svc    *peer.Service
	auth   Authenticator
	sign   signer
	origin string
	secure bool
	log    *slog.Logger
	now    func() time.Time
	tmpl   *template.Template
}

// Handler serves the page and its sign-in, and hands the phone's enrolment
// routes and /healthz to enrol (peer.EnrolHandler).
func Handler(svc *peer.Service, enrol http.Handler, o Options) (http.Handler, error) {
	u, err := url.Parse(o.PublicURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, fmt.Errorf("public URL %q: want http(s)://host", o.PublicURL)
	}
	if len(o.Key) < 32 {
		return nil, errors.New("the cookie key must be at least 32 bytes")
	}
	s := &server{
		svc: svc, auth: o.Auth, sign: signer{key: o.Key},
		origin: u.Scheme + "://" + u.Host, secure: u.Scheme == "https",
		log: o.Log, now: o.Now,
	}
	if s.log == nil {
		s.log = slog.Default()
	}
	if s.now == nil {
		s.now = time.Now
	}
	s.tmpl, err = template.New("").Funcs(template.FuncMap{
		"ago": s.ago, "stamp": s.stamp, "full": full, "short": short,
	}).ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, err
	}

	mux := http.NewServeMux()
	mux.Handle(peer.ApproverPath, enrol)
	mux.Handle("/healthz", enrol)

	page := http.NewServeMux()
	page.HandleFunc("GET /auth/login", s.login)
	page.HandleFunc("GET /auth/callback", s.callback)
	page.HandleFunc("POST /auth/logout", s.sameOrigin(s.logout))
	page.HandleFunc("GET /{$}", s.signedIn(s.page))
	page.HandleFunc("POST /approver/code", s.sameOrigin(s.signedIn(s.mint)))
	page.HandleFunc("GET /approver/remove", s.signedIn(s.confirmRemove))
	page.HandleFunc("POST /approver/remove", s.sameOrigin(s.signedIn(s.remove)))
	page.Handle("/", httpx.NotFoundHandler)
	mux.Handle("/", httpx.Middleware(s.log)(page))
	return mux, nil
}

// ── guards ──────────────────────────────────────────────────────────────

type identityKey struct{}

func operator(r *http.Request) Identity {
	id, _ := r.Context().Value(identityKey{}).(Identity)
	return id
}

// signedIn admits a request with a live session. Without one a GET goes
// to sign-in and anything else is refused.
func (s *server) signedIn(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.auth == nil {
			s.message(w, http.StatusServiceUnavailable, "Sign-in is not set up",
				"The hub has no OIDC client. Set the stack's OIDC variables and restart it.")
			return
		}
		var ss session
		if c, err := r.Cookie(s.cookie("session")); err == nil &&
			s.sign.open("session", c.Value, &ss) && s.now().Unix() < ss.Expires {
			next(w, r.WithContext(context.WithValue(r.Context(), identityKey{}, ss.Identity)))
			return
		}
		if r.Method == http.MethodGet {
			http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
			return
		}
		s.message(w, http.StatusUnauthorized, "Signed out", "Sign in again and repeat what you did.")
	}
}

// sameOrigin refuses a POST the page did not send. Other stacks are
// sibling subdomains, same-site to the browser, so SameSite cookies alone
// would let them post here.
func (s *server) sameOrigin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ok := r.Header.Get("Origin") == s.origin
		if site := r.Header.Get("Sec-Fetch-Site"); site != "" {
			ok = site == "same-origin"
		}
		if !ok {
			s.message(w, http.StatusForbidden, "Refused", "This request did not come from the peer page.")
			return
		}
		next(w, r)
	}
}

// ── sign-in ─────────────────────────────────────────────────────────────

func (s *server) cookie(name string) string {
	if s.secure {
		return "__Host-peer_" + name
	}
	return "peer_" + name
}

func (s *server) setCookie(w http.ResponseWriter, name, value string, ttl time.Duration) {
	c := &http.Cookie{
		Name: s.cookie(name), Value: value, Path: "/", HttpOnly: true, Secure: s.secure,
		// Lax, not Strict: the session is set at the end of a redirect
		// chain that started on the provider's site. POSTs are guarded
		// by sameOrigin.
		SameSite: http.SameSiteLaxMode,
	}
	if ttl > 0 {
		c.MaxAge = int(ttl.Seconds())
	} else {
		c.MaxAge = -1
	}
	http.SetCookie(w, c)
}

func (s *server) login(w http.ResponseWriter, r *http.Request) {
	if s.auth == nil {
		s.message(w, http.StatusServiceUnavailable, "Sign-in is not set up",
			"The hub has no OIDC client. Set the stack's OIDC variables and restart it.")
		return
	}
	l := login{State: randomToken(), Nonce: randomToken(), Verifier: oauth2.GenerateVerifier(),
		Expires: s.now().Add(loginTTL).Unix()}
	to, err := s.auth.AuthURL(r.Context(), l.State, l.Nonce, l.Verifier)
	if err != nil {
		s.log.Warn("sign-in unavailable", "error", err)
		s.message(w, http.StatusServiceUnavailable, "Sign-in is unavailable",
			"Pocket ID did not answer. Try again in a moment.")
		return
	}
	v, err := s.sign.seal("login", l)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.setCookie(w, "login", v, loginTTL)
	http.Redirect(w, r, to, http.StatusSeeOther)
}

func (s *server) callback(w http.ResponseWriter, r *http.Request) {
	if s.auth == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	q := r.URL.Query()
	var l login
	c, err := r.Cookie(s.cookie("login"))
	if err != nil || !s.sign.open("login", c.Value, &l) || s.now().Unix() >= l.Expires ||
		subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(l.State)) != 1 {
		s.message(w, http.StatusBadRequest, "Sign-in expired", `The sign-in took too long or was started elsewhere. <a href="/auth/login">Sign in again</a>.`)
		return
	}
	s.setCookie(w, "login", "", 0)
	if e := q.Get("error"); e != "" {
		s.log.Warn("sign-in refused by the provider", "error", e)
		s.message(w, http.StatusForbidden, "Sign-in refused", `Pocket ID refused the sign-in. <a href="/auth/login">Try again</a>.`)
		return
	}
	id, err := s.auth.Exchange(r.Context(), q.Get("code"), l.Nonce, l.Verifier)
	if errors.Is(err, ErrNotAllowed) {
		s.log.Warn("sign-in refused: not in the admitted group")
		s.message(w, http.StatusForbidden, "Not allowed", "This account is not in the group admitted to the peer page.")
		return
	}
	if err != nil {
		s.log.Warn("sign-in failed", "error", err)
		s.message(w, http.StatusBadGateway, "Sign-in failed", `Pocket ID's answer did not check out. <a href="/auth/login">Try again</a>.`)
		return
	}
	v, err := s.sign.seal("session", session{Identity: id, Expires: s.now().Add(sessionTTL).Unix()})
	if err != nil {
		s.fail(w, err)
		return
	}
	s.log.Info("operator signed in", "sub", id.Subject, "name", id.Name)
	s.setCookie(w, "session", v, sessionTTL)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *server) logout(w http.ResponseWriter, r *http.Request) {
	s.setCookie(w, "session", "", 0)
	s.message(w, http.StatusOK, "Signed out", `<a href="/">Sign in again</a>.`)
}

// ── the page ────────────────────────────────────────────────────────────

// codeView is a freshly minted enrolment code as the page shows it.
type codeView struct {
	Link      string
	QR        template.HTML
	ExpiresAt time.Time
	Baseline  string // the enrolled key id when it was minted
}

type pageData struct {
	Operator Identity
	Hub      peer.HubJSON
	Parked   []peer.Request
	Approver *peer.Approver
	Code     *codeView
	Messages []peer.Message
	Outcomes []peer.Outcome
	// Errors names the parts that could not be read.
	Errors []string
}

func (s *server) gather(ctx context.Context, id Identity) pageData {
	d := pageData{Operator: id}
	var err error
	note := func(what string, e error) {
		if e != nil {
			s.log.Warn("page: read failed", "what", what, "error", e)
			d.Errors = append(d.Errors, what)
		}
	}
	d.Hub, err = s.svc.Hub(ctx)
	note("the hub's state", err)
	d.Parked, err = s.svc.Requests(ctx, peer.ReqParked, recent)
	note("pending approvals", err)
	a, ok, err := s.svc.Approver(ctx)
	note("the approver phone", err)
	if ok {
		d.Approver = &a
	}
	d.Messages, err = s.svc.Messages(ctx, recent)
	note("messages", err)
	d.Outcomes, err = s.svc.Outcomes(ctx, recent)
	note("outcomes", err)
	return d
}

func (s *server) page(w http.ResponseWriter, r *http.Request) {
	s.render(w, http.StatusOK, "page", s.gather(r.Context(), operator(r)))
}

// mint shows a fresh code in the response itself: it never travels in a
// URL, and a reload of the page drops it.
func (s *server) mint(w http.ResponseWriter, r *http.Request) {
	d := s.gather(r.Context(), operator(r))
	c := s.svc.MintApproverCode()
	qr, err := qrSVG(c.Link)
	if err != nil {
		s.fail(w, err)
		return
	}
	d.Code = &codeView{Link: c.Link, QR: qr, ExpiresAt: c.ExpiresAt}
	if d.Approver != nil {
		d.Code.Baseline = d.Approver.KeyID
	}
	s.log.Info("enrolment code minted from the page", "sub", operator(r).Subject)
	s.render(w, http.StatusOK, "page", d)
}

func (s *server) confirmRemove(w http.ResponseWriter, r *http.Request) {
	a, ok, err := s.svc.Approver(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	if !ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.render(w, http.StatusOK, "remove", a)
}

func (s *server) remove(w http.ResponseWriter, r *http.Request) {
	if err := s.svc.RevokeApprover(r.Context()); err != nil {
		s.fail(w, err)
		return
	}
	s.log.Info("approver phone removed from the page", "sub", operator(r).Subject)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// ── rendering ───────────────────────────────────────────────────────────

func (s *server) message(w http.ResponseWriter, status int, title, body string) {
	// body is a fixed string from this file, never request input.
	s.render(w, status, "message", struct {
		Title string
		Body  template.HTML
	}{Title: title, Body: template.HTML(body)})
}

func (s *server) fail(w http.ResponseWriter, err error) {
	s.log.Error("page failed", "error", err)
	s.message(w, http.StatusInternalServerError, "Something went wrong", "The hub logged the error.")
}

// view is what a template gets: its data and the script nonce the Content-Security-Policy allows.
type view struct {
	Nonce string
	D     any
}

// render executes a template with a fresh script nonce.
func (s *server) render(w http.ResponseWriter, status int, name string, data any) {
	var b [16]byte
	_, _ = rand.Read(b[:])
	nonce := base64.RawStdEncoding.EncodeToString(b[:])
	var buf bytes.Buffer
	if err := s.tmpl.ExecuteTemplate(&buf, name, view{Nonce: nonce, D: data}); err != nil {
		s.log.Error("render", "template", name, "error", err)
		http.Error(w, "render failed", http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy", strings.Join([]string{
		"default-src 'none'", "style-src 'unsafe-inline'", "script-src 'nonce-" + nonce + "'",
		"connect-src 'self'", "img-src 'self' data:", "form-action 'self'",
		"frame-ancestors 'none'", "base-uri 'none'",
	}, "; "))
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}
