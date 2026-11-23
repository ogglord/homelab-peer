package approvals

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/ogglord/homelab-peer/internal/peer"
)

func parkedStep() peer.Request {
	return peer.Request{
		ID: "req_1", Sender: "macbook", Target: "homeassistant", Text: "Create a Mosquitto user for Frigate.",
		State: peer.ReqParked, ApprovalCycles: 2, Tool: "Bash", Step: "ha auth create --username frigate",
		ParkKind: peer.ParkStep, Fingerprint: fp, ParkReason: "creates a login\non the   broker",
		ExpiresAt: time.Unix(1762878600, 0),
	}
}

func newPrompter(t *testing.T) (*Prompter, *hemmaHub, *fakeHub, phone) {
	t.Helper()
	hh, client := newHemmaHub(t)
	ph := newPhone(t, "Admin")
	a := ph.a
	fh := &fakeHub{approver: &a}
	return &Prompter{Client: client, Approvers: fh, URL: "https://peer.example.com/"}, hh, fh, ph
}

func TestPromptBody(t *testing.T) {
	t.Parallel()
	p, hh, _, ph := newPrompter(t)
	id, err := p.SendPrompt(context.Background(), parkedStep())
	if err != nil || id != "ap_new" {
		t.Fatalf("id=%q err=%v", id, err)
	}
	if len(hh.prompts) != 1 {
		t.Fatalf("prompts = %d", len(hh.prompts))
	}
	got, _ := json.Marshal(hh.prompts[0])
	want, _ := json.Marshal(map[string]any{
		"request": "req_1", "round": 2, "fingerprint": fp, "kind": "step", "host": "homeassistant", "sender": "macbook",
		"text": "Create a Mosquitto user for Frigate.", "step": "ha auth create --username frigate",
		"reason": "creates a login on the broker", "expires_at": 1762878600,
		"signer": map[string]any{"key_id": ph.a.KeyID, "public_key": ph.a.PublicKey, "name": "Admin"},
		"url":    "https://peer.example.com/",
	})
	if string(got) != string(want) {
		t.Fatalf("prompt\n%s\nwant\n%s", got, want)
	}
}

func TestPromptBounds(t *testing.T) {
	t.Parallel()
	p, hh, _, _ := newPrompter(t)
	r := parkedStep()
	r.Text = strings.Repeat("😀", 3000) // 6000 UTF-16 units
	r.ParkReason = strings.Repeat("ord ", 200)
	p.URL = ""
	if _, err := p.SendPrompt(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	b := hh.prompts[0]
	if n := len(utf16.Encode([]rune(b["text"].(string)))); n > 4000 {
		t.Errorf("text is %d UTF-16 units", n)
	}
	if n := len([]rune(b["reason"].(string))); n > 300 || strings.Contains(b["reason"].(string), "  ") {
		t.Errorf("reason %d runes: %q", n, b["reason"])
	}
	if _, ok := b["url"]; ok {
		t.Error("url sent without one set")
	}
}

// A limit park carries no step; the prompt says what approving does.
func TestPromptStepForLimit(t *testing.T) {
	t.Parallel()
	p, hh, _, _ := newPrompter(t)
	limit := parkedStep()
	limit.ParkKind, limit.Step, limit.Tool, limit.SpentUSD = peer.ParkLimit, "", "", 10.25
	if _, err := p.SendPrompt(context.Background(), limit); err != nil {
		t.Fatal(err)
	}
	if s, _ := hh.prompts[0]["step"].(string); !strings.HasPrefix(s, "Raise the allowance by 10 USD and 2 h") || hh.prompts[0]["kind"] != "limit" {
		t.Errorf("limit prompt %+v", hh.prompts[0])
	}
}

func TestPromptWithoutApproverFails(t *testing.T) {
	t.Parallel()
	p, hh, fh, _ := newPrompter(t)
	fh.approver = nil
	if _, err := p.SendPrompt(context.Background(), parkedStep()); err == nil {
		t.Fatal("no error without an enrolled phone")
	}
	if len(hh.prompts) != 0 {
		t.Fatal("prompt sent without an enrolled phone")
	}
}

func TestWithdraw(t *testing.T) {
	t.Parallel()
	p, hh, _, _ := newPrompter(t)
	r := parkedStep()
	p.Withdraw(context.Background(), r) // never prompted: nothing to withdraw
	r.PromptID = "ap_9"
	p.Withdraw(context.Background(), r)
	if got := hh.stateCalls(); len(got) != 1 || got[0] != (stateCall{"ap_9", "withdrawn", noteExpired}) {
		t.Fatalf("states = %+v", got)
	}
}
