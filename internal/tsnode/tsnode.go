// Package tsnode is the hub's own tailnet node: it brings a tsnet node up
// with the hub's OAuth client, serves the agent operations on it, and
// identifies each caller by WhoIs and its peer capability. It is apart from
// internal/peer so nothing else links tailscale.com.
package tsnode

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ogglord/homelab-peer/internal/peer"
	"tailscale.com/client/local"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
)

// NodeConfig is the hub's tailnet node.
type NodeConfig struct {
	Hostname string
	Tag      string
	StateDir string
	Port     int // plain-HTTP port of the agent operations, on the node only
	WGPort   int // WireGuard UDP port
}

// upWait bounds the first wait for the node to reach running before its
// state is reported; the node keeps trying afterwards.
const upWait = 60 * time.Second

// ReadClientSecret reads the OAuth client secret. ok is false, with no
// error, when the path is empty, the file is absent, or it holds an empty or
// placeholder value: the hub then stays disabled.
func ReadClientSecret(path string) (secret string, ok bool, err error) {
	if path == "" {
		return "", false, nil
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	s := strings.TrimSpace(string(raw))
	if s == "" || strings.Contains(s, "PLACEHOLDER") {
		return "", false, nil
	}
	return s, true, nil
}

// Node is the hub's own tailnet node serving AgentHandler.
type Node struct {
	cfg    NodeConfig
	secret string
	svc    *peer.Service
	log    *slog.Logger
	lc     atomic.Pointer[local.Client]
}

// NewNode prepares the node; Run brings it up.
func NewNode(cfg NodeConfig, clientSecret string, svc *peer.Service, log *slog.Logger) *Node {
	return &Node{cfg: cfg, secret: clientSecret, svc: svc, log: log}
}

// Run brings the node up and serves the agent operations on it until ctx
// ends. Problems are logged and shown in the hub state; Run returns when
// the node cannot serve, and the hub process exits for systemd to restart
// it.
func (n *Node) Run(ctx context.Context) {
	srv := &tsnet.Server{
		Dir:      n.cfg.StateDir,
		Hostname: n.cfg.Hostname,
		// A durable, pre-approved node: the OAuth resolver defaults to
		// ephemeral nodes.
		ClientSecret:  n.secret + "?ephemeral=false&preauthorized=true",
		AdvertiseTags: []string{n.cfg.Tag},
		Port:          uint16(n.cfg.WGPort),
		UserLogf:      func(format string, a ...any) { n.log.Info(fmt.Sprintf(format, a...)) },
	}
	defer srv.Close()

	n.svc.SetState(peer.StateStarting, "", nil)
	lc, err := srv.LocalClient()
	if err != nil {
		n.fail("start tailnet node", err)
		return
	}
	n.lc.Store(lc)

	upCtx, cancel := context.WithTimeout(ctx, upWait)
	st, err := srv.Up(upCtx)
	cancel()
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		n.reportNotUp(ctx, lc, err)
		if st, err = srv.Up(ctx); err != nil {
			if ctx.Err() == nil {
				n.fail("bring tailnet node up", err)
			}
			return
		}
	}

	ln, err := srv.Listen("tcp", fmt.Sprintf(":%d", n.cfg.Port))
	if err != nil {
		n.fail("listen on tailnet node", err)
		return
	}
	ips := make([]string, 0, len(st.TailscaleIPs))
	for _, ip := range st.TailscaleIPs {
		ips = append(ips, ip.String())
	}
	n.svc.SetState(peer.StateRunning, "", ips)
	n.log.Info("peer hub listening", "node", n.cfg.Hostname, "ips", ips, "port", n.cfg.Port)

	hs := &http.Server{
		Handler:           peer.AgentHandler(n.svc, tsnetIdentity{n}, n.log),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      0, // the push stream is long-lived
		IdleTimeout:       120 * time.Second,
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = hs.Shutdown(sctx)
	}()
	if err := hs.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		n.fail("serve peer hub", err)
	}
}

// reportNotUp records why the node is not running after the bounded wait.
func (n *Node) reportNotUp(ctx context.Context, lc *local.Client, upErr error) {
	state, detail := peer.StateStarting, "tailnet node not running yet"
	sctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if st, err := lc.StatusWithoutPeers(sctx); err == nil {
		switch st.BackendState {
		case "NeedsLogin", "NeedsMachineAuth":
			state, detail = peer.StateUnauthorized, "tailnet node is not authorised ("+st.BackendState+")"
		}
	}
	n.log.Warn("peer hub node not running", "state", state, "error", upErr)
	n.svc.SetState(state, detail, nil)
}

func (n *Node) fail(what string, err error) {
	n.log.Error("peer hub stopped", "step", what, "error", err)
	n.svc.SetState(peer.StateError, what+" failed", nil)
}

// tsnetIdentity identifies a caller with WhoIs on the node's local client.
type tsnetIdentity struct{ n *Node }

func (t tsnetIdentity) Identify(ctx context.Context, remoteAddr string) (peer.Caller, error) {
	lc := t.n.lc.Load()
	if lc == nil {
		return peer.Caller{}, peer.ErrUnknownCaller
	}
	who, err := lc.WhoIs(ctx, remoteAddr)
	if err != nil {
		return peer.Caller{}, fmt.Errorf("%w: %w", peer.ErrUnknownCaller, err)
	}
	return callerFromWhoIs(who)
}

// callerFromWhoIs maps a WhoIs answer to the caller it names.
func callerFromWhoIs(who *apitype.WhoIsResponse) (peer.Caller, error) {
	if who == nil || who.Node == nil {
		return peer.Caller{}, peer.ErrUnknownCaller
	}
	entries, err := tailcfg.UnmarshalCapJSON[peer.CapEntry](who.CapMap, peer.CapName)
	if err != nil {
		return peer.Caller{}, fmt.Errorf("%w: %w", peer.ErrNoCapability, err)
	}
	name := who.Node.ComputedName
	if name == "" {
		name = who.Node.Name
	}
	return peer.CallerFromCaps(name, entries)
}
