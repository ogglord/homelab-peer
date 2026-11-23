package peerclient_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ogglord/homelab-peer/internal/peerclient"
)

// canaryPass is the canary run on a working build: the hook denies the
// touch, the classifier blocks the rm.
var canaryPass = []string{bash("{{canary-touch}}"), blocked("{{canary-rm}}", "hard_deny: deletes a peer-canary file"), `{"result":{"outcome":"done","summary":"denied"}}`}

// The canary passes on a build whose PreToolUse hook denies and whose
// classifier blocks reach the PermissionDenied hook; it leaves the gate
// unverified on one without hook support, and proves it broken when auto
// mode runs the hard_deny call.
func TestCanary(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		steps   []string
		noHooks bool
		want    bool
		broken  bool
	}{
		{"hooks fire and the classifier blocks", canaryPass, false, true, false},
		{"no hook support", canaryPass, true, false, true},
		{"the classifier lets the hard_deny call run", []string{bash("{{canary-touch}}"), bash("{{canary-rm}}"), `{"result":{"outcome":"done","summary":"ran"}}`}, false, false, true},
		{"the run never makes the second call", []string{bash("{{canary-touch}}"), `{"result":{"outcome":"done","summary":"stopped"}}`}, false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, tc.steps...)
			if tc.noHooks {
				h.l.Env = append(h.l.Env, "FAKE_CLAUDE_NOHOOKS=1")
			}
			verified, err := peerclient.Canary(context.Background(), *h.l, "")
			if verified != tc.want || errors.Is(err, peerclient.ErrGateBroken) != tc.broken {
				t.Fatalf("verified = %v (%v), want %v broken %v", verified, err, tc.want, tc.broken)
			}
			if !tc.want && err == nil {
				t.Fatal("an unverified gate carries no reason")
			}
			if r := h.seen(t); r.Env[peerclient.EnvRequestSender] != peerclient.UntrustedSender {
				t.Errorf("canary sender %q", r.Env[peerclient.EnvRequestSender])
			}
		})
	}
}
