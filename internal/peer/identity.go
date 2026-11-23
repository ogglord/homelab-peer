package peer

import (
	"context"
	"fmt"
	"slices"
)

// CapName is the tailnet ACL grant capability the hub reads.
const CapName = "ogglord.com/cap/peer"

// CapEntry is one value of the peer capability, from one ACL grant. A
// grant's "secrets" member (secret handover, removed) is ignored.
type CapEntry struct {
	Host  string `json:"host"`
	Kinds []Kind `json:"kinds"`
}

// Caller is a tailnet node as the hub sees it: the host it speaks for and
// what it may send. It comes from the connection, never from a request.
type Caller struct {
	Node  string
	Host  string
	Kinds []Kind // sorted, unique, known kinds only
}

// May reports whether c may send messages of kind k.
func (c Caller) May(k Kind) bool { return slices.Contains(c.Kinds, k) }

// Identity identifies the caller behind a connection's remote address. It
// returns ErrUnknownCaller when the address is not a tailnet node it can
// resolve, and ErrNoCapability when the node carries no usable peer
// capability.
type Identity interface {
	Identify(ctx context.Context, remoteAddr string) (Caller, error)
}

// CallerFromCaps unions the capability entries of one node. Every entry must
// name the same host; no entries, or entries naming different or no hosts,
// is ErrNoCapability. Unknown kinds are dropped.
func CallerFromCaps(node string, entries []CapEntry) (Caller, error) {
	if len(entries) == 0 {
		return Caller{}, ErrNoCapability
	}
	c := Caller{Node: node}
	for _, e := range entries {
		switch {
		case e.Host == "" || len(e.Host) > maxHost:
			return Caller{}, fmt.Errorf("%w: an entry names no valid host", ErrNoCapability)
		case c.Host != "" && c.Host != e.Host:
			return Caller{}, fmt.Errorf("%w: entries name different hosts", ErrNoCapability)
		}
		c.Host = e.Host
		for _, k := range e.Kinds {
			if validKind(k) {
				c.Kinds = append(c.Kinds, k)
			}
		}
	}
	slices.Sort(c.Kinds)
	c.Kinds = slices.Compact(c.Kinds)
	return c, nil
}

type callerKey struct{}

func withCaller(ctx context.Context, c Caller) context.Context {
	return context.WithValue(ctx, callerKey{}, c)
}

func callerFrom(ctx context.Context) (Caller, bool) {
	c, ok := ctx.Value(callerKey{}).(Caller)
	return c, ok
}
