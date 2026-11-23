package peerclient

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"slices"
)

// defaultPolicyFile is the policy `peer policy init` and `peer service
// install` write for a host: Claude Code's defaults, what an unattended run
// may do to the host it runs on, and what it may not do even when the
// request asks.
//
//go:embed default-policy.json
var defaultPolicyFile []byte

// DefaultPolicyFile is the default policy file's bytes, ready to write.
func DefaultPolicyFile() []byte { return slices.Clone(defaultPolicyFile) }

// Policy is the host's auto-mode policy: the prose rules Claude Code's
// classifier judges every call outside the allow list by, passed as the
// autoMode block of --settings. "$defaults" in a list keeps Claude Code's
// built-in rules there. A hard_deny rule holds even when the request text
// (the run's user turn) asked for the action; a soft_deny one would not,
// which is why there is none.
type Policy struct {
	Environment []string `json:"environment"`
	Allow       []string `json:"allow"`
	HardDeny    []string `json:"hard_deny"`
}

// approverHardDeny is always among a run's hard_deny rules (forRun).
const approverHardDeny = "Minting peer enrolment codes or enrolling approver keys"

// DefaultPolicy is the policy of a listener given no policy file: Claude
// Code's defaults plus the approver rule. A host installed with `peer
// service install` gets DefaultPolicyFile instead.
func DefaultPolicy() Policy {
	return Policy{
		Environment: []string{"$defaults"},
		Allow:       []string{"$defaults"},
		HardDeny:    []string{"$defaults", approverHardDeny},
	}
}

// LoadPolicy reads a policy file: one JSON object with environment, allow
// and hard_deny, each a list of prose rules.
func LoadPolicy(path string) (Policy, error) {
	var p Policy
	data, err := os.ReadFile(path)
	if err != nil {
		return p, fmt.Errorf("reading the policy: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return p, fmt.Errorf("%s: %w", path, err)
	}
	return p, nil
}

// forRun is the policy a run gets: the approver rule is always among its
// hard_deny rules, and a policy that sets nothing is DefaultPolicy.
func (p Policy) forRun() Policy {
	if len(p.Environment) == 0 && len(p.Allow) == 0 && len(p.HardDeny) == 0 {
		return DefaultPolicy()
	}
	out := Policy{Environment: slices.Clone(p.Environment), Allow: slices.Clone(p.Allow), HardDeny: slices.Clone(p.HardDeny)}
	if !slices.Contains(out.HardDeny, approverHardDeny) {
		out.HardDeny = append(out.HardDeny, approverHardDeny)
	}
	return out
}

// autoMode is the --settings autoMode block.
func (p Policy) autoMode() map[string][]string {
	nonNil := func(s []string) []string {
		if s == nil {
			return []string{}
		}
		return s
	}
	return map[string][]string{"environment": nonNil(p.Environment), "allow": nonNil(p.Allow), "hard_deny": nonNil(p.HardDeny)}
}
