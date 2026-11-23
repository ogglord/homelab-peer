package web

// Sign-in. The page is the operator's: it mints enrolment codes and removes
// the phone, which no agent on a peer host may do. Caddy's route has no
// sign-in of its own, so the hub signs the operator in through Pocket ID
// (OIDC, authorization code with PKCE) and admits only members of one
// group. The session is a signed cookie; its key lives in peer.db's meta,
// so a restart keeps everyone signed in.

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Identity is the signed-in operator.
type Identity struct {
	Subject string `json:"sub"`
	Name    string `json:"name"`
}

// ErrNotAllowed: the account signed in but is not in the admitted group.
var ErrNotAllowed = errors.New("web: the account is not in the group admitted to the page")

// Authenticator signs the operator in with an identity provider.
type Authenticator interface {
	// AuthURL is where the browser goes to sign in.
	AuthURL(ctx context.Context, state, nonce, verifier string) (string, error)
	// Exchange redeems the callback's code and returns the operator, or
	// ErrNotAllowed.
	Exchange(ctx context.Context, code, nonce, verifier string) (Identity, error)
}

// OIDC is the Authenticator for an OIDC provider (Pocket ID). Discovery
// runs at the first sign-in and again after a failure, so the hub starts
// while the provider is down.
type OIDC struct {
	Issuer, ClientID, ClientSecret, RedirectURL string
	// Group is the groups-claim value an account needs.
	Group string

	mu       sync.Mutex
	provider *oidc.Provider
}

// discoveryTimeout bounds each call to the provider.
const discoveryTimeout = 10 * time.Second

func (o *OIDC) client() context.Context {
	return oidc.ClientContext(context.Background(), &http.Client{Timeout: discoveryTimeout})
}

func (o *OIDC) load() (*oidc.Provider, oauth2.Config, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.provider == nil {
		// The provider keeps this context for its key fetches: it must
		// outlive the request that triggered discovery.
		p, err := oidc.NewProvider(o.client(), o.Issuer)
		if err != nil {
			return nil, oauth2.Config{}, fmt.Errorf("discover %s: %w", o.Issuer, err)
		}
		o.provider = p
	}
	return o.provider, oauth2.Config{
		ClientID: o.ClientID, ClientSecret: o.ClientSecret, RedirectURL: o.RedirectURL,
		Endpoint: o.provider.Endpoint(),
		Scopes:   []string{oidc.ScopeOpenID, "profile", "groups"},
	}, nil
}

func (o *OIDC) AuthURL(_ context.Context, state, nonce, verifier string) (string, error) {
	_, cfg, err := o.load()
	if err != nil {
		return "", err
	}
	return cfg.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), nil
}

func (o *OIDC) Exchange(ctx context.Context, code, nonce, verifier string) (Identity, error) {
	p, cfg, err := o.load()
	if err != nil {
		return Identity{}, err
	}
	ctx, cancel := context.WithTimeout(oidc.ClientContext(ctx, &http.Client{Timeout: discoveryTimeout}), discoveryTimeout)
	defer cancel()
	tok, err := cfg.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return Identity{}, fmt.Errorf("redeem the code: %w", err)
	}
	raw, ok := tok.Extra("id_token").(string)
	if !ok {
		return Identity{}, errors.New("the token response has no id_token")
	}
	idt, err := p.VerifierContext(o.client(), &oidc.Config{ClientID: o.ClientID}).Verify(ctx, raw)
	if err != nil {
		return Identity{}, fmt.Errorf("verify the id token: %w", err)
	}
	if !hmac.Equal([]byte(idt.Nonce), []byte(nonce)) {
		return Identity{}, errors.New("the id token's nonce does not match")
	}
	var c claims
	if err := idt.Claims(&c); err != nil {
		return Identity{}, fmt.Errorf("read the id token's claims: %w", err)
	}
	return c.identity(idt.Subject, o.Group)
}

type claims struct {
	Name              string   `json:"name"`
	PreferredUsername string   `json:"preferred_username"`
	Email             string   `json:"email"`
	Groups            []string `json:"groups"`
}

// identity admits the account only when group is among its groups.
func (c claims) identity(subject, group string) (Identity, error) {
	if group == "" || !slices.Contains(c.Groups, group) {
		return Identity{}, ErrNotAllowed
	}
	name := c.Name
	for _, n := range []string{c.PreferredUsername, c.Email, subject} {
		if name == "" {
			name = n
		}
	}
	return Identity{Subject: subject, Name: name}, nil
}

// ── signed cookies ──────────────────────────────────────────────────────

// Meta is the hub's key-value store (store.Store).
type Meta interface {
	Meta(ctx context.Context, key string) (string, bool, error)
	SetMeta(ctx context.Context, key, value string) error
}

const sessionKeyMeta = "web_session_key"

// SessionKey is the cookie signing key, made at the first start.
func SessionKey(ctx context.Context, m Meta) ([]byte, error) {
	v, ok, err := m.Meta(ctx, sessionKeyMeta)
	if err != nil {
		return nil, err
	}
	if ok {
		if k, err := hex.DecodeString(v); err == nil && len(k) == 32 {
			return k, nil
		}
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, m.SetMeta(ctx, sessionKeyMeta, hex.EncodeToString(k))
}

// signer seals small JSON values into cookie values. The purpose is part
// of the MAC, so a login cookie never passes as a session.
type signer struct{ key []byte }

func (s signer) mac(purpose string, payload []byte) []byte {
	h := hmac.New(sha256.New, s.key)
	h.Write([]byte(purpose))
	h.Write([]byte{0})
	h.Write(payload)
	return h.Sum(nil)
}

func (s signer) seal(purpose string, v any) (string, error) {
	payload, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString(payload) + "." + enc.EncodeToString(s.mac(purpose, payload)), nil
}

func (s signer) open(purpose, value string, v any) bool {
	p, m, ok := strings.Cut(value, ".")
	if !ok {
		return false
	}
	enc := base64.RawURLEncoding
	payload, err1 := enc.DecodeString(p)
	sum, err2 := enc.DecodeString(m)
	if err1 != nil || err2 != nil || !hmac.Equal(sum, s.mac(purpose, payload)) {
		return false
	}
	return json.Unmarshal(payload, v) == nil
}

// session is the session cookie's content.
type session struct {
	Identity
	Expires int64 `json:"exp"`
}

// login is the login cookie's content: what the callback checks.
type login struct {
	State    string `json:"state"`
	Nonce    string `json:"nonce"`
	Verifier string `json:"verifier"`
	Expires  int64  `json:"exp"`
}

const (
	sessionTTL = 12 * time.Hour
	loginTTL   = 10 * time.Minute
)

func randomToken() string {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand does not fail on Linux
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}
