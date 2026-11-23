// Package hemma is the peer hub's side of the Hemma hub on the Home
// Assistant box (the wire contract is docs/homelab.md in the Hemma repo; its
// signing fixtures are copied into testdata/): plain notifications to the
// admin phones, approval prompts, and the long poll for the phones' signed
// decisions. Every call carries the homelab token as a bearer token. The
// prompter and the decision poller live in hemma/approvals.
package hemma

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Interruption levels of a notification (data.push["interruption-level"]).
const (
	LevelActive        = "active"
	LevelTimeSensitive = "time-sensitive"
)

// States the homelab reports for an approval.
const (
	StateApplied   = "applied"
	StateRefused   = "refused"
	StateWithdrawn = "withdrawn"
)

const (
	// maxBody bounds what is read of an answer; the hub's bodies are at
	// most 64 KiB both ways.
	maxBody = 64 << 10
	// callTimeout bounds a notification, a prompt or a state report.
	callTimeout = 10 * time.Second
	// pollSlack is how much longer than its wait a decisions poll may take.
	pollSlack = 15 * time.Second
	// group stacks the homelab's notifications on the phone.
	group = "homelab"
)

// Client talks to the Hemma hub.
type Client struct {
	// BaseURL is the hub's origin, e.g. https://192.0.2.10:8788.
	BaseURL string
	// TokenFile holds the homelab token; it is read on every call, so a
	// rotated token applies without a restart.
	TokenFile string
	// HTTP is the transport; nil means http.DefaultClient. Calls are
	// bounded by their own deadlines.
	HTTP *http.Client
}

// NewClient is the client for the hub at baseURL with the token in
// tokenFile, or nil (Hemma not configured) when either is empty. A
// non-empty certSHA256 pins the hub's self-signed certificate (see
// PinnedHTTP); empty means the system trust store.
func NewClient(baseURL, tokenFile, certSHA256 string) *Client {
	if baseURL == "" || tokenFile == "" {
		return nil
	}
	c := &Client{BaseURL: baseURL, TokenFile: tokenFile}
	if certSHA256 != "" {
		c.HTTP = PinnedHTTP(certSHA256)
	}
	return c
}

// PinnedHTTP is an HTTP client that accepts only a TLS server whose leaf
// certificate's DER encoding hashes (SHA-256) to pin, lowercase hex. The
// chain and host name are not checked: the pin replaces them, which is what
// makes the hub's self-signed certificate usable. A malformed pin matches
// nothing. Calls are bounded by their contexts, so the client sets no
// timeout of its own.
func PinnedHTTP(pin string) *http.Client {
	want, _ := hex.DecodeString(pin)
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = nil
	t.TLSClientConfig = &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // replaced by VerifyPeerCertificate below
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("hemma: hub sent no certificate")
			}
			got := sha256.Sum256(rawCerts[0])
			if len(want) != sha256.Size || subtle.ConstantTimeCompare(got[:], want) != 1 {
				return errors.New("hemma: hub certificate does not match the pin")
			}
			return nil
		},
	}
	return &http.Client{Transport: t}
}

// StatusError is a non-2xx answer.
type StatusError struct {
	Status  int
	Message string // the body's "error", when there is one
}

func (e *StatusError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("hemma answered %d: %s", e.Status, e.Message)
	}
	return fmt.Sprintf("hemma answered %d", e.Status)
}

// Notification is one plain notification to the admin phones.
type Notification struct {
	Title   string
	Message string // required by the hub
	// Tag replaces an earlier notification with the same tag; "" for none.
	Tag string
	// URL opens on tap; "" for none.
	URL string
	// InterruptionLevel is LevelActive or LevelTimeSensitive.
	InterruptionLevel string
}

// Notify posts n to the admin phones (POST /notify/admin).
func (c *Client) Notify(ctx context.Context, n Notification) error {
	type push struct {
		Level string `json:"interruption-level"`
	}
	type data struct {
		Tag   string `json:"tag,omitempty"`
		Group string `json:"group"`
		URL   string `json:"url,omitempty"`
		Push  push   `json:"push"`
	}
	body := struct {
		Title   string `json:"title"`
		Message string `json:"message"`
		Data    data   `json:"data"`
	}{n.Title, n.Message, data{Tag: n.Tag, Group: group, URL: n.URL, Push: push{n.InterruptionLevel}}}
	return c.do(ctx, callTimeout, http.MethodPost, "/notify/admin", body, nil)
}

// Signer is the enrolled phone a prompt names as the one that can sign.
type Signer struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
	Name      string `json:"name"`
}

// Prompt is an approval prompt (POST /homelab/approvals). Text and Reason
// are always sent, empty or not.
type Prompt struct {
	Request     string `json:"request"`
	Round       int64  `json:"round"`
	Fingerprint string `json:"fingerprint"`
	Kind        string `json:"kind"`
	Host        string `json:"host"`
	Sender      string `json:"sender"`
	Text        string `json:"text"`
	Step        string `json:"step"`
	Reason      string `json:"reason"`
	ExpiresAt   int64  `json:"expires_at"`
	Signer      Signer `json:"signer"`
	URL         string `json:"url,omitempty"`
}

// PostApproval sends p and returns the hub's approval id. The hub answers
// the same id for the same request, round and fingerprint.
func (c *Client) PostApproval(ctx context.Context, p Prompt) (string, error) {
	var out struct {
		ID string `json:"id"`
	}
	if err := c.do(ctx, callTimeout, http.MethodPost, "/homelab/approvals", p, &out); err != nil {
		return "", err
	}
	if out.ID == "" {
		return "", errors.New("hemma: approval answer has no id")
	}
	return out.ID, nil
}

// PostState reports an approval's outcome (applied, refused or withdrawn)
// with an optional one-line note. A 409 means the state cannot change that
// way, which after a replay means it was reported already: not an error.
func (c *Client) PostState(ctx context.Context, id, state, note string) error {
	body := struct {
		State string `json:"state"`
		Note  string `json:"note,omitempty"`
	}{state, note}
	err := c.do(ctx, callTimeout, http.MethodPost, "/homelab/approvals/"+url.PathEscape(id)+"/state", body, nil)
	var se *StatusError
	if errors.As(err, &se) && se.Status == http.StatusConflict {
		return nil
	}
	return err
}

// Decision is one signed decision as the hub hands it out.
type Decision struct {
	Seq         int64  `json:"seq"`
	ID          string `json:"id"`
	Request     string `json:"request"`
	Round       int64  `json:"round"`
	Fingerprint string `json:"fingerprint"`
	Decision    string `json:"decision"`
	ExpiresAt   int64  `json:"expires_at"`
	KeyID       string `json:"key_id"`
	Signature   string `json:"signature"`
	DeviceName  string `json:"device_name"`
	DecidedAt   int64  `json:"decided_at"`
}

// Decisions is one answer of the decisions poll.
type Decisions struct {
	Decisions []Decision `json:"decisions"`
	Cursor    int64      `json:"cursor"`
}

// Decisions long-polls for decisions after cursor after, holding up to wait
// (the hub caps it at 25 s) when there are none.
func (c *Client) Decisions(ctx context.Context, after int64, wait time.Duration) (Decisions, error) {
	secs := int64(wait / time.Second)
	q := url.Values{"after": {strconv.FormatInt(after, 10)}, "wait": {strconv.FormatInt(secs, 10)}}
	var out Decisions
	err := c.do(ctx, wait+pollSlack, http.MethodGet, "/homelab/decisions?"+q.Encode(), nil, &out)
	return out, err
}

func (c *Client) token() (string, error) {
	raw, err := os.ReadFile(c.TokenFile)
	if err != nil {
		return "", fmt.Errorf("hemma: read token: %w", err)
	}
	tok := strings.TrimSpace(string(raw))
	if tok == "" {
		return "", errors.New("hemma: token file is empty")
	}
	return tok, nil
}

// do sends one call bounded by timeout and decodes a 2xx answer into out
// (nil discards it).
func (c *Client) do(ctx context.Context, timeout time.Duration, method, path string, in, out any) error {
	tok, err := c.token()
	if err != nil {
		return err
	}
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.BaseURL, "/")+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("hemma: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return fmt.Errorf("hemma: read answer: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		se := &StatusError{Status: resp.StatusCode}
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(raw, &e) == nil {
			se.Message = e.Error
		}
		return se
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("hemma: decode answer: %w", err)
	}
	return nil
}
