// Command peer-hub is the homelab peer hub, run as the `peer` stack. `serve`
// joins the tailnet as its own node (homelab-hub, tag:homelab-hub) and
// serves the agent operations on it (:7790), serves the operator's page
// and the approver phone's enrolment on the stack's address behind Caddy
// (peer.<domain>; the page signs in through Pocket ID), and serves the
// operator's commands on a unix socket only root and the hub's user can
// open. The other subcommands are those operator commands, run as root
// inside the stack:
//
//	systemd-run -M peer --pipe -q -- /run/current-system/sw/bin/peer-hub approver code
//	systemd-run -M peer --pipe -q -- /run/current-system/sw/bin/peer-hub approver revoke
//	systemd-run -M peer --pipe -q -- /run/current-system/sw/bin/peer-hub status
//
// So no agent on a peer host can enrol a phone: minting the code takes
// root in the stack, or the operator signed in on the page.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/urfave/cli/v2"
	"golang.org/x/sync/errgroup"

	"github.com/ogglord/homelab-peer/internal/hemma"
	"github.com/ogglord/homelab-peer/internal/hemma/approvals"
	"github.com/ogglord/homelab-peer/internal/peer"
	"github.com/ogglord/homelab-peer/internal/store"
	"github.com/ogglord/homelab-peer/internal/tsnode"
	"github.com/ogglord/homelab-peer/internal/web"
)

// version is the commit this binary was built from (-X main.version=...).
var version = "dev"

const defaultAdminSocket = "/run/peer-hub/admin.sock"

func main() {
	app := &cli.App{
		Name:    "peer-hub",
		Usage:   "The homelab peer hub, and its operator commands",
		Version: version,
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "admin-socket", Value: defaultAdminSocket, EnvVars: []string{"PEER_HUB_ADMIN_SOCKET"}, Usage: "the operator's unix socket"},
		},
		Commands: []*cli.Command{
			{
				Name:  "serve",
				Usage: "Run the hub",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "state-dir", Value: "/var/lib/peer-hub", EnvVars: []string{"STATE_DIRECTORY"}, Usage: "database (peer.db) and tailnet node state (tsnet/)"},
					&cli.StringFlag{Name: "client-secret-file", Required: true, Usage: "Tailscale OAuth client secret (auth-key write on the tag)"},
					&cli.StringFlag{Name: "hostname", Value: "homelab-hub", Usage: "tailnet node name"},
					&cli.StringFlag{Name: "tag", Value: "tag:homelab-hub", Usage: "tailnet tag the node advertises"},
					&cli.IntFlag{Name: "port", Value: 7790, Usage: "agent operations port on the tailnet node"},
					&cli.IntFlag{Name: "wg-port", Value: 41642, Usage: "the node's WireGuard UDP port"},
					&cli.StringFlag{Name: "enrol-listen", Value: ":8080", Usage: "address of the page and enrolment listener Caddy proxies to"},
					&cli.StringFlag{Name: "public-url", Usage: "origin of that listener as browsers and the phone reach it, e.g. https://peer.example.com"},
					&cli.StringFlag{Name: "domain-file", Usage: "the host's domain (HOMELAB_DOMAIN); without --public-url the origin is https://peer.<domain>"},
					&cli.StringFlag{Name: "enrol-url", Usage: "enrolment URL the phone posts to (in the enrolment link); empty: the public URL's " + peer.ApproverPath},
					&cli.StringFlag{Name: "oidc-issuer-file", Usage: "the page's OIDC issuer (Pocket ID), e.g. https://auth.example.com"},
					&cli.StringFlag{Name: "oidc-client-id-file", Usage: "the page's OIDC client id"},
					&cli.StringFlag{Name: "oidc-client-secret-file", Usage: "the page's OIDC client secret"},
					&cli.StringFlag{Name: "oidc-admin-group-file", Usage: "the group (groups claim) an account needs to sign in to the page"},
					&cli.StringFlag{Name: "hemma-url", Usage: "Hemma hub origin, e.g. https://192.0.2.10:8788; empty: no prompts or notices"},
					&cli.StringFlag{Name: "hemma-address-file", Usage: "Hemma's IPv4 address (HEMMA_ADDRESS); without --hemma-url the origin is https://<address>:8788"},
					&cli.StringFlag{Name: "hemma-token-file", Usage: "Hemma bearer token"},
					&cli.StringFlag{Name: "hemma-cert-sha256", Usage: "SHA-256 (hex) of Hemma's self-signed certificate"},
					&cli.StringFlag{Name: "hemma-cert-sha256-file", Usage: "file holding --hemma-cert-sha256 (HEMMA_CERT_SHA256)"},
				},
				Action: serve,
			},
			{
				Name:  "approver",
				Usage: "The approver phone",
				Subcommands: []*cli.Command{
					{Name: "code", Usage: "Mint the one-time enrolment code (10 minutes) and its hemma:// link", Action: adminCall(http.MethodPost, peer.AdminApproverCode)},
					{Name: "show", Usage: "Show the enrolled phone", Action: adminCall(http.MethodGet, peer.AdminApprover)},
					{Name: "revoke", Usage: "Revoke the enrolled phone; decisions are refused until one enrols again", Action: adminCall(http.MethodDelete, peer.AdminApprover)},
				},
			},
			{Name: "status", Usage: "The hub's tailnet node and the hosts it knows", Action: adminCall(http.MethodGet, peer.AdminStatus)},
		},
	}
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, "peer-hub:", err)
		os.Exit(1)
	}
}

func serve(c *cli.Context) error {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	slog.SetDefault(log)
	ctx, stop := signal.NotifyContext(c.Context, os.Interrupt, syscall.SIGTERM)
	defer stop()

	stateDir := c.String("state-dir")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	st, err := store.Open(ctx, filepath.Join(stateDir, "peer.db"))
	if err != nil {
		return err
	}
	defer st.Close()

	plog := log.With("component", "peer")
	publicURL, hemmaURL, certSHA, err := origins(c)
	if err != nil {
		return err
	}
	hc := hemma.NewClient(hemmaURL, c.String("hemma-token-file"), certSHA)
	enrolURL := c.String("enrol-url")
	if enrolURL == "" {
		enrolURL = publicURL + peer.ApproverPath
	}
	cfg := peer.Config{Hostname: c.String("hostname"), EnrolURL: enrolURL, Version: version}
	if hc != nil {
		// Runs under the enrolment lock: the notice goes out on its own.
		cfg.OnEnrolled = func(name string) {
			go func() {
				nctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				if err := hc.Notify(nctx, hemma.Notification{
					Message: "Ny telefon kopplad: " + name, InterruptionLevel: hemma.LevelTimeSensitive,
				}); err != nil {
					plog.Warn("approver enrolment notice not delivered", "error", err)
				}
			}()
		}
	}
	svc := peer.New(cfg, peer.NewDBStore(st), plog)
	var decisions *approvals.Poller
	if hc != nil {
		// Parks prompt the enrolled phone through Hemma; its signed
		// decisions come back by long poll.
		svc.SetPrompter(&approvals.Prompter{Client: hc, Approvers: svc, Log: plog})
		decisions = &approvals.Poller{Client: hc, Hub: svc, Meta: st, Log: plog}
	} else {
		log.Warn("no Hemma configured: parked requests are never prompted or decided")
	}

	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		svc.Run(gctx, func(ctx context.Context, now time.Time) error {
			ps, err := st.Prune(ctx, now)
			if err == nil && ps != (store.PruneStats{}) {
				plog.Info("pruned", "requests", ps.Requests, "messages", ps.Messages, "outcomes", ps.Outcomes)
			}
			return err
		})
		return nil
	})
	if decisions != nil {
		g.Go(func() error { decisions.Run(gctx); return nil })
	}
	page, err := pageHandler(ctx, c, svc, st, publicURL, log.With("component", "web"))
	if err != nil {
		return err
	}
	g.Go(func() error { return serveHTTP(gctx, "tcp", c.String("enrol-listen"), page) })
	g.Go(func() error {
		return serveAdmin(gctx, c.String("admin-socket"), peer.AdminHandler(svc, log.With("component", "admin")))
	})

	secret, ok, err := tsnode.ReadClientSecret(c.String("client-secret-file"))
	switch {
	case err != nil:
		log.Error("peer hub node disabled: cannot read the client secret", "error", err)
		svc.SetState(peer.StateError, "cannot read the client secret file", nil)
	case !ok:
		log.Warn("peer hub node disabled: client secret absent or placeholder")
		svc.SetState(peer.StateDisabled, "client secret absent or placeholder", nil)
	default:
		node := tsnode.NewNode(tsnode.NodeConfig{
			Hostname: c.String("hostname"), Tag: c.String("tag"), StateDir: filepath.Join(stateDir, "tsnet"),
			Port: c.Int("port"), WGPort: c.Int("wg-port"),
		}, secret, svc, plog)
		g.Go(func() error {
			node.Run(gctx)
			if gctx.Err() == nil {
				return errors.New("the tailnet node stopped")
			}
			return nil
		})
	}
	log.Info("peer hub started", "version", version, "state_dir", stateDir)
	return g.Wait()
}

// origins are the page's public origin and Hemma's, and Hemma's pinned
// certificate, from their flags or else from the files the stack's
// variables arrive in.
func origins(c *cli.Context) (public, hemmaURL, certSHA string, err error) {
	public = strings.TrimSuffix(c.String("public-url"), "/")
	if public == "" {
		d, err := readValue(c.String("domain-file"))
		if err != nil {
			return "", "", "", fmt.Errorf("--domain-file: %w", err)
		}
		if d == "" {
			return "", "", "", errors.New("pass --public-url, or --domain-file naming a non-empty file")
		}
		public = "https://peer." + d
	}
	hemmaURL = c.String("hemma-url")
	if hemmaURL == "" && c.String("hemma-address-file") != "" {
		a, err := readValue(c.String("hemma-address-file"))
		if err != nil {
			return "", "", "", err
		}
		addr, err := netip.ParseAddr(a)
		if err != nil || !addr.Is4() {
			return "", "", "", fmt.Errorf("--hemma-address-file: want one IPv4 address, got %q", a)
		}
		hemmaURL = "https://" + addr.String() + ":8788"
	}
	certSHA = c.String("hemma-cert-sha256")
	if certSHA == "" && c.String("hemma-cert-sha256-file") != "" {
		if certSHA, err = readValue(c.String("hemma-cert-sha256-file")); err != nil {
			return "", "", "", err
		}
	}
	return public, hemmaURL, certSHA, nil
}

// readValue is a value file's content without surrounding space; an
// empty path is an empty value.
func readValue(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// pageHandler is the listener behind Caddy: the operator's page, and the
// phone's enrolment and the health probe under it. Without the four OIDC
// values the page says sign-in is not set up; enrolment works either way.
func pageHandler(ctx context.Context, c *cli.Context, svc *peer.Service, st *store.Store, publicURL string, log *slog.Logger) (http.Handler, error) {
	key, err := web.SessionKey(ctx, st)
	if err != nil {
		return nil, fmt.Errorf("the page's cookie key: %w", err)
	}
	vals := map[string]string{}
	for _, f := range []string{"oidc-issuer-file", "oidc-client-id-file", "oidc-client-secret-file", "oidc-admin-group-file"} {
		v, err := readValue(c.String(f))
		if err != nil {
			return nil, fmt.Errorf("--%s: %w", f, err)
		}
		vals[f] = v
	}
	var auth web.Authenticator
	if vals["oidc-issuer-file"] != "" && vals["oidc-client-id-file"] != "" &&
		vals["oidc-client-secret-file"] != "" && vals["oidc-admin-group-file"] != "" {
		auth = &web.OIDC{
			Issuer: vals["oidc-issuer-file"], ClientID: vals["oidc-client-id-file"],
			ClientSecret: vals["oidc-client-secret-file"], Group: vals["oidc-admin-group-file"],
			RedirectURL: publicURL + "/auth/callback",
		}
	} else {
		log.Warn("the page has no OIDC client: it answers that sign-in is not set up")
	}
	return web.Handler(svc, peer.EnrolHandler(svc, log), web.Options{PublicURL: publicURL, Auth: auth, Key: key, Log: log})
}

// serveHTTP serves h on addr until ctx ends.
func serveHTTP(ctx context.Context, network, addr string, h http.Handler) error {
	ln, err := net.Listen(network, addr)
	if err != nil {
		return err
	}
	return serveOn(ctx, ln, h)
}

func serveOn(ctx context.Context, ln net.Listener, h http.Handler) error {
	hs := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = hs.Shutdown(sctx)
	}()
	if err := hs.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// serveAdmin serves the operator's socket, mode 0600: only the hub's user
// and root can connect.
func serveAdmin(ctx context.Context, path string, h http.Handler) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return err
	}
	return serveOn(ctx, ln, h)
}

// adminCall is one operator command: a call on the admin socket, its
// answer printed as indented JSON.
func adminCall(method, path string) cli.ActionFunc {
	return func(c *cli.Context) error {
		sock := c.String("admin-socket")
		hc := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", sock)
			},
		}}
		req, err := http.NewRequestWithContext(c.Context, method, "http://peer-hub"+path, nil)
		if err != nil {
			return err
		}
		resp, err := hc.Do(req)
		if err != nil {
			return fmt.Errorf("the hub is not reachable on %s (run as root inside the stack): %w", sock, err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if resp.StatusCode >= 300 {
			return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(body)))
		}
		if resp.StatusCode == http.StatusNoContent {
			fmt.Println("done")
			return nil
		}
		var v any
		if json.Unmarshal(body, &v) != nil {
			_, err = os.Stdout.Write(body)
			return err
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false) // the enrolment link keeps its &
		enc.SetIndent("", "  ")
		return enc.Encode(v)
	}
}
