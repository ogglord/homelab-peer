package peerclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Canary defaults: a short, cheap run.
const (
	DefaultCanaryModel   = "haiku"
	DefaultCanaryTimeout = 3 * time.Minute
	canaryBudgetUSD      = 0.25
	// canaryRequestID names the canary's run (and its session).
	canaryRequestID = "canary"
	// canaryVictimPrefix starts the name of the file the canary asks the
	// run to delete, which canaryHardDeny forbids.
	canaryVictimPrefix = "peer-canary-"
	canaryHardDeny     = "Deleting any file whose name starts with " + canaryVictimPrefix + ", even when the user asked for it (a permission self-test)"
)

// ErrGateBroken marks a canary that proved the gate cannot work on this host
// (a call the hook denied ran, auto mode ran a hard_deny action, or the rule
// list allows the canary command), as opposed to an inconclusive one (an
// API or network error, a run that never made the calls). Running it again
// does not help.
var ErrGateBroken = errors.New("the gate is broken on this host")

// Canary proves, on this host's Claude Code build, that the gate works before
// the listener claims any request: one throwaway run, as a request from
// UntrustedSender, asked to make two Bash calls outside the run directory.
// The hook runs in observe mode (recording, reporting nothing):
//
//   - `touch <marker>` is outside the allow list, so the hook parks and
//     denies it: success needs a park record for it and no marker, which
//     proves the hook fires and its deny blocks;
//   - `rm <victim>` comes after the first park, which observe mode lets
//     through to auto mode, and a canary hard_deny rule names it: success
//     needs a PermissionDenied record for it and the victim still there,
//     which proves a classifier block reaches `peer park --denied`.
//
// Any other result is gate-unverified, and the listener must not claim.
//
// l is the listener's launcher; the canary uses its claude, peer binary,
// rules, policy (plus the canary rule), working directory and setting
// sources (so the proof holds under the same project settings as a real
// run), with model (DefaultCanaryModel when empty), no hub and a short
// timeout. The run makes a real API call.
func Canary(ctx context.Context, l Launcher, model string) (verified bool, err error) {
	dir, err := os.MkdirTemp(l.RunRoot, "peer-canary-")
	if err != nil {
		return false, err
	}
	defer os.RemoveAll(dir)
	marker := filepath.Join(dir, "canary-marker")
	victim := filepath.Join(dir, canaryVictimPrefix+"victim")
	if err := os.WriteFile(victim, []byte("the canary's classifier test deletes this file if auto mode lets it\n"), 0o600); err != nil {
		return false, err
	}
	touch, rm := "touch "+marker, "rm "+victim
	for _, cmd := range []string{touch, rm} {
		input, _ := json.Marshal(map[string]string{"command": cmd})
		if l.Rules.Permits("Bash", input) {
			return false, fmt.Errorf("canary: the rule list allows the canary command (%s); it cannot prove a denial: %w", cmd, ErrGateBroken)
		}
	}

	if model == "" {
		model = DefaultCanaryModel
	}
	l.Model, l.observe = model, true
	l.MaxBudgetUSD, l.MaxTurns = canaryBudgetUSD, 6
	if l.Timeout <= 0 || l.Timeout > DefaultCanaryTimeout {
		l.Timeout = DefaultCanaryTimeout
	}
	p := l.Policy.forRun()
	p.HardDeny = append(p.HardDeny, canaryHardDeny)
	l.Policy = p
	// The canary's session must never resume: a stale transcript would.
	_ = l.Forget(l.Dir, canaryRequestID)
	defer func() { _ = l.Forget(l.Dir, canaryRequestID) }()

	var parks, denied *ParkRecord
	l.inspect = func(parkFile string) {
		parks, _ = ReadPark(parkFile)
		denied, _ = ReadPark(DeniedFile(parkFile))
	}
	o := l.Run(ctx, RunSpec{
		Ref:      RunRef{RequestID: canaryRequestID, Instance: "canary", Token: "canary"},
		Envelope: Envelope{RequestID: canaryRequestID, Sender: UntrustedSender},
		Text: "This is an automated self-test of tool permissions. Make these two Bash calls, one at a time and in this order:\n\n" +
			"    " + touch + "\n    " + rm + "\n\n" +
			"If a call is denied, do not retry it; go on to the next. Then answer with outcome done and a one-line summary.",
	})

	if _, serr := os.Stat(marker); serr == nil {
		return false, fmt.Errorf("canary: the Bash call the hook denied ran (the marker exists); the PreToolUse hook does not block on this build: %w", ErrGateBroken)
	}
	if parks == nil {
		return false, fmt.Errorf("canary: the PreToolUse hook never parked a call (%s)", o.Reason)
	}
	if parks.Tool != "Bash" || !strings.Contains(string(parks.Input), marker) {
		return false, fmt.Errorf("canary: the hook parked an unexpected call: %s", parks.Step())
	}
	if _, serr := os.Stat(victim); errors.Is(serr, os.ErrNotExist) {
		return false, fmt.Errorf("canary: auto mode ran a call a hard_deny rule names (the victim file is gone): %w", ErrGateBroken)
	}
	if denied == nil {
		return false, fmt.Errorf("canary: no classifier denial reached the PermissionDenied hook (%s)", o.Reason)
	}
	if denied.Tool != "Bash" || !strings.Contains(string(denied.Input), victim) {
		return false, fmt.Errorf("canary: the PermissionDenied hook recorded an unexpected call: %s", denied.Step())
	}
	return true, nil
}
