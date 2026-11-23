package approvals

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"unicode/utf16"

	"github.com/ogglord/homelab-peer/internal/hemma"
	"github.com/ogglord/homelab-peer/internal/peer"
)

// Bounds of a prompt's fields (docs/homelab.md). The hub counts JavaScript
// string length, so text and step are cut in UTF-16 units.
const (
	maxText   = 4000
	maxStep   = 32000
	maxReason = 300
)

// noteExpired is the withdrawn note of a prompt whose request expired.
const noteExpired = "the request expired"

// errNoApprover leaves a round unprompted: the hub's sweep retries it, and
// until a phone enrols the request waits on the dashboard.
var errNoApprover = errors.New("no approver phone is enrolled")

// Approvers is where the enrolled phone comes from (the peer service).
type Approvers interface {
	Approver(ctx context.Context) (peer.Approver, bool, error)
}

// Prompter sends the peer hub's approval prompts to Hemma; it implements
// peer.Prompter.
type Prompter struct {
	Client    *hemma.Client
	Approvers Approvers
	// URL, when set, opens on the phone from the prompt.
	URL string
	Log *slog.Logger
}

var _ peer.Prompter = (*Prompter)(nil)

// SendPrompt posts the prompt for parked request r's current round, signed
// for by the enrolled phone, and returns Hemma's approval id.
func (p *Prompter) SendPrompt(ctx context.Context, r peer.Request) (string, error) {
	a, ok, err := p.Approvers.Approver(ctx)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", errNoApprover
	}
	pr := hemma.Prompt{
		Request: r.ID, Round: r.ApprovalCycles, Fingerprint: r.Fingerprint, Kind: string(r.ParkKind),
		Host: r.Target, Sender: r.Sender,
		Text:      cut16(r.Text, maxText),
		Step:      cut16(stepOf(r), maxStep),
		Reason:    oneLine(r.ParkReason, maxReason),
		ExpiresAt: r.ExpiresAt.Unix(),
		Signer:    hemma.Signer{KeyID: a.KeyID, PublicKey: a.PublicKey, Name: a.Name},
	}
	pr.URL = p.URL
	return p.Client.PostApproval(ctx, pr)
}

// Withdraw reports a prompted round whose request left parked without a
// decision. Best effort: a failure is logged.
func (p *Prompter) Withdraw(ctx context.Context, r peer.Request) {
	if r.PromptID == "" {
		return
	}
	if err := p.Client.PostState(ctx, r.PromptID, hemma.StateWithdrawn, noteExpired); err != nil {
		p.log().Warn("hemma: withdrawing the approval failed", "request_id", r.ID, "prompt_id", r.PromptID, "error", err)
	}
}

func (p *Prompter) log() *slog.Logger {
	if p.Log == nil {
		return slog.Default()
	}
	return p.Log
}

// stepOf is what the phone shows as the step: the blocked call, or what
// approving a limit park does (it carries no step).
func stepOf(r peer.Request) string {
	switch r.ParkKind {
	case peer.ParkLimit:
		return fmt.Sprintf("Raise the allowance by %g USD and %d h (spent %.2f USD, ran %d s)",
			peer.AllowanceUSD, peer.AllowanceSeconds/3600, r.SpentUSD, r.UsedSeconds)
	}
	if strings.TrimSpace(r.Step) != "" {
		return r.Step
	}
	return r.Tool
}

// oneLine collapses whitespace to single spaces and cuts s to max runes.
func oneLine(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	if rs := []rune(s); len(rs) > max {
		return string(rs[:max-1]) + "…"
	}
	return s
}

// cut16 cuts s to at most max UTF-16 units, ending a cut text with "…".
func cut16(s string, max int) string {
	if len(utf16.Encode([]rune(s))) <= max {
		return s
	}
	n := 0
	for i, r := range s {
		w := utf16.RuneLen(r)
		if w < 0 {
			w = 1
		}
		if n+w > max-1 { // room for the ellipsis
			return s[:i] + "…"
		}
		n += w
	}
	return s
}
