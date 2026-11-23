package tsnode

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/ogglord/homelab-peer/internal/peer"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
)

func TestCallerFromWhoIs(t *testing.T) {
	t.Parallel()
	caps := func(raw ...string) tailcfg.PeerCapMap {
		vals := make([]tailcfg.RawMessage, 0, len(raw))
		for _, r := range raw {
			vals = append(vals, tailcfg.RawMessage(r))
		}
		return tailcfg.PeerCapMap{peer.CapName: vals}
	}
	grant := `{"host":"laptop","kinds":["status","secret"],"secrets":["laptop/*"]}`
	for _, tc := range []struct {
		name     string
		who      *apitype.WhoIsResponse
		wantErr  error
		wantNode string
	}{
		{name: "nil response", who: nil, wantErr: peer.ErrUnknownCaller},
		{name: "nil node", who: &apitype.WhoIsResponse{CapMap: caps(grant)}, wantErr: peer.ErrUnknownCaller},
		{name: "malformed cap", who: &apitype.WhoIsResponse{
			Node:   &tailcfg.Node{ComputedName: "laptop"},
			CapMap: caps(`{"host":`),
		}, wantErr: peer.ErrNoCapability},
		{name: "grants name different hosts", who: &apitype.WhoIsResponse{
			Node:   &tailcfg.Node{ComputedName: "laptop"},
			CapMap: caps(grant, `{"host":"desktop","kinds":["status"]}`),
		}, wantErr: peer.ErrNoCapability},
		{name: "valid grant", who: &apitype.WhoIsResponse{
			Node:   &tailcfg.Node{ComputedName: "laptop", Name: "laptop.tail1234.ts.net."},
			CapMap: caps(grant),
		}, wantNode: "laptop"},
		{name: "empty computed name falls back to name", who: &apitype.WhoIsResponse{
			Node:   &tailcfg.Node{Name: "laptop.tail1234.ts.net."},
			CapMap: caps(grant),
		}, wantNode: "laptop.tail1234.ts.net."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := callerFromWhoIs(tc.who)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if c.Node != tc.wantNode || c.Host != "laptop" ||
				!slices.Equal(c.Kinds, []peer.Kind{peer.KindStatus}) {
				t.Fatalf("caller = %+v", c)
			}
		})
	}
}

func TestReadClientSecretTreatsAbsentAndPlaceholderAsDisabled(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	write := func(name, v string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for name, p := range map[string]string{
		"empty path":       "",
		"absent file":      filepath.Join(dir, "missing"),
		"empty value":      write("empty", " \n"),
		"placeholder":      write("placeholder", "PLACEHOLDER\n"),
		"placeholder mark": write("placeholder-mark", "PLACEHOLDER_SET_ME\n"),
	} {
		if s, ok, err := ReadClientSecret(p); ok || err != nil || s != "" {
			t.Errorf("%s: (%q, %v, %v), want disabled without error", name, s, ok, err)
		}
	}
	if s, ok, err := ReadClientSecret(write("real", "tskey-client-abc\n")); !ok || err != nil || s != "tskey-client-abc" {
		t.Errorf("real secret: (%q, %v, %v)", s, ok, err)
	}
}
