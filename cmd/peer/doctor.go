package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/ogglord/homelab-peer/internal/peerclient"
	"github.com/urfave/cli/v2"
)

type check struct {
	Name    string `json:"name"`
	OK      bool   `json:"ok"`
	Skipped bool   `json:"skipped,omitempty"`
	Detail  string `json:"detail"`
}

// caddyRefusal is the body Caddy answers a dashboard mutation from the Home
// Assistant box with (nixos/hosts/homelab/configuration.nix).
const caddyRefusal = "refused from the Home Assistant box"

const probeTimeout = 5 * time.Second

// doctor runs each check on its own. The identity check is read-only, so it
// never touches the running listener's registration.
func (e env) doctor(c *cli.Context) error {
	cl, err := hubClient(c)
	if err != nil {
		return err
	}
	ctx := c.Context
	var checks []check
	add := func(name string, ok bool, format string, a ...any) {
		checks = append(checks, check{Name: name, OK: ok, Detail: fmt.Sprintf(format, a...)})
	}

	if conn, err := (&net.Dialer{Timeout: probeTimeout}).DialContext(ctx, "tcp", cl.HostPort()); err != nil {
		add("tailnet_reach", false, "TCP %s: %v", cl.HostPort(), err)
	} else {
		conn.Close()
		add("tailnet_reach", true, "TCP %s connected", cl.HostPort())
	}

	_, err = cl.Inbox(ctx)
	var p *peerclient.Problem
	switch {
	case err == nil:
		add("hub_http", true, "%s answered", cl.Base())
	case errors.As(err, &p):
		add("hub_http", true, "%s answered %d %s", cl.Base(), p.Status, p.Code)
	default:
		add("hub_http", false, "%v", err)
	}

	var identity *peerclient.Identity
	id, err := cl.Identity(ctx)
	switch {
	case err == nil:
		identity = &id
		add("identity", true, "node %s speaks for host %s", id.Node, id.Host)
		add("capability", len(id.Kinds) > 0, "kinds [%s]", strings.Join(id.Kinds, ", "))
	case peerclient.IsProblem(err, peerclient.CodeNoCapability):
		add("identity", true, "identified, but no peer capability")
		add("capability", false, "%v", err)
	default:
		add("identity", false, "%v", err)
		add("capability", false, "not checked: identity unknown")
	}

	if dash := strings.TrimRight(c.String("dashboard"), "/"); dash != "" {
		unreachable, detail := probeDashboard(ctx, dash)
		add("dashboard_mutations_unreachable", unreachable, "%s", detail)
	} else {
		checks = append(checks, check{Name: "dashboard_mutations_unreachable", OK: true, Skipped: true,
			Detail: "skipped: no --dashboard given (pass it on the Home Assistant box)"})
	}

	ok := true
	for _, ch := range checks {
		ok = ok && ch.OK
	}
	if jsonFlag(c) {
		writeJSON(e.out, map[string]any{"success": ok, "checks": checks, "identity": identity})
	} else {
		for _, ch := range checks {
			mark := "ok  "
			switch {
			case ch.Skipped:
				mark = "skip"
			case !ch.OK:
				mark = "FAIL"
			}
			fmt.Fprintf(e.out, "%s %-32s %s\n", mark, ch.Name, ch.Detail)
		}
	}
	if !ok {
		return errReported
	}
	return nil
}

// probeDashboard POSTs to a path that does not exist under the dashboard's
// /api. Only Caddy's refusal, or a TCP connection that cannot be made
// (refused or timed out), means a mutation cannot get through from here. A
// DNS or TLS failure is inconclusive, since a wrong origin fails that way
// too; any answer but the refusal means one would reach the daemon.
func probeDashboard(ctx context.Context, dash string) (unreachable bool, detail string) {
	// The dial, TLS and header timeouts live on the transport, so a dial
	// that times out reports as a dial error rather than a cancelled request.
	ctx, cancel := context.WithTimeout(ctx, 3*probeTimeout)
	defer cancel()
	dialer := &net.Dialer{Timeout: probeTimeout}
	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := dialer.DialContext(ctx, network, addr)
			var dnsErr *net.DNSError
			if err != nil && !errors.As(err, &dnsErr) {
				return nil, dialError{err}
			}
			return conn, err
		},
		TLSHandshakeTimeout:   probeTimeout,
		ResponseHeaderTimeout: probeTimeout,
	}}
	defer client.CloseIdleConnections()

	url := dash + "/api/__peer-doctor-probe"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return false, err.Error()
	}
	resp, err := client.Do(req)
	if err != nil {
		var de dialError
		if errors.As(err, &de) {
			return true, fmt.Sprintf("POST %s: no TCP connection (%v)", url, de.err)
		}
		return false, fmt.Sprintf("inconclusive: %s (POST %s: %v)", errorClass(err), url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode == http.StatusForbidden && strings.Contains(string(body), caddyRefusal) {
		return true, fmt.Sprintf("POST %s: refused by Caddy (403)", url)
	}
	return false, fmt.Sprintf("POST %s: answered %d, so a dashboard mutation would get through", url, resp.StatusCode)
}

// dialError marks a failed TCP connect, as opposed to a failed lookup.
type dialError struct{ err error }

func (d dialError) Error() string { return d.err.Error() }
func (d dialError) Unwrap() error { return d.err }

// errorClass names why a probe that is not a dial failure got no answer.
func errorClass(err error) string {
	var dnsErr *net.DNSError
	var certErr *tls.CertificateVerificationError
	var alert tls.AlertError
	var record tls.RecordHeaderError
	switch {
	case errors.As(err, &dnsErr):
		return "dns"
	case errors.As(err, &certErr), errors.As(err, &alert), errors.As(err, &record):
		return "tls"
	default:
		return "error"
	}
}
