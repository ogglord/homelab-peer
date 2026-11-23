// Command peer is the agent-side client of the homelab peer hub: send a
// request or a status to another host, wait for a request's outcome, read
// this host's inbox, and run the listener that receives status and results
// and, with --claude, runs the requests pushed to this host. A run calls
// back into it: `peer park` is the run's PreToolUse hook. The same static
// binary runs on homelab and the MacBook (installed with `nix profile
// install`, its listener a user service from `peer service install`,
// install.go) and in the Home Assistant SSH add-on, where it is copied into
// the add-on's persistent data directory with a peer.json beside it
// ({"hub": "http://<hub tailnet IPv4>:7790", ...}) and started from an init
// command that returns once a detached supervisor runs the listener
// (service.go):
//
//	/data/peer service
//
// There, doctor also checks that dashboard mutations cannot get through
// (elsewhere it skips that probe):
//
//	/data/peer --hub http://<hub tailnet IPv4>:7790 doctor --dashboard https://homelab.example.com
//
// listen exits 3 when a newer listener for this host took over (the user
// service and `peer service` do not restart on it), 0 when
// --restart-on-upgrade saw a newer peer installed (both restart it), 1 on
// any other failure.
//
// The hub is dialled by its tailnet address (--hub, else PEER_HUB_URL, else
// the hub in peer.json beside the binary, else ~/.config/peer/hub, which
// `service install` writes), never
// MagicDNS. Which host this client speaks for is decided by the hub from the
// tailnet connection, never configured here. Put --json before the command.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/ogglord/homelab-peer/internal/peerclient"
	"github.com/urfave/cli/v2"
)

// version is the commit this binary was built from, set by the flake's
// package (-X main.version=<short rev>); "dev" in local builds.
var version = "dev"

func main() {
	os.Exit(run(os.Args, os.Stdin, os.Stdout, os.Stderr))
}

// errReported is a failure whose output was already written.
var errReported = errors.New("reported")

// exitSuperseded is listen's exit status when a newer listener took over;
// the user service does not restart on it.
const exitSuperseded = 3

// exitStatus is a command's exit status whose output was already written.
type exitStatus int

func (e exitStatus) Error() string { return fmt.Sprintf("exit status %d", int(e)) }

func exitCode(err error) int {
	var st exitStatus
	switch {
	case err == nil:
		return 0
	case errors.As(err, &st):
		return int(st)
	case errors.Is(err, peerclient.ErrSuperseded):
		return exitSuperseded
	default:
		return 1
	}
}

type env struct {
	in       io.Reader
	out, err io.Writer
	args     []string // the command line, for `service` to re-exec itself
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	e := env{in: stdin, out: stdout, err: stderr, args: args}
	app := &cli.App{
		Name:           "peer",
		Usage:          "Send requests and status through the homelab peer hub, and listen for messages",
		Version:        version,
		Reader:         stdin,
		Writer:         stdout,
		ErrWriter:      stderr,
		ExitErrHandler: func(*cli.Context, error) {},
		// Rules hold commas (Bash(echo a,b)); every repeat is one value.
		DisableSliceFlagSeparator: true,
		Flags: []cli.Flag{
			&cli.BoolFlag{Name: "json", Usage: "output as JSON"},
			&cli.StringFlag{Name: "hub", EnvVars: []string{peerclient.EnvHubURL}, Usage: "hub origin by tailnet IPv4, e.g. http://100.64.0.1:7790 (else peer.json beside this binary, else ~/.config/peer/hub)"},
		},
		Before: func(c *cli.Context) error {
			if c.String("hub") == "" {
				if h := savedHub(); h != "" {
					return c.Set("hub", h)
				}
			}
			return nil
		},
		Commands: []*cli.Command{
			{
				Name:  "send",
				Usage: "Send a message to another host",
				Subcommands: []*cli.Command{
					{
						Name:      "request",
						Usage:     "Send a request for another host's agent to run; the text from the arguments, or stdin with -",
						ArgsUsage: "<text...|->",
						Flags: []cli.Flag{
							&cli.StringFlag{Name: "target", Required: true, Usage: "host whose agent runs the request"},
							&cli.StringFlag{Name: "id", Usage: "request id (a retry with the same id has no second effect)"},
							&cli.BoolFlag{Name: "wait", Usage: "wait for the outcome, as `peer wait`"},
							&cli.DurationFlag{Name: "timeout", Value: defaultWaitTimeout, Usage: "with --wait, how long to wait"},
						},
						Action: e.sendRequest,
					},
					{
						Name:      "status",
						Usage:     "Send a status update",
						ArgsUsage: "<text>",
						Flags: []cli.Flag{
							&cli.StringFlag{Name: "target", Required: true, Usage: "host the status is for"},
							&cli.StringFlag{Name: "phase", Required: true, Usage: strings.Join(peerclient.Phases, "|")},
							&cli.StringFlag{Name: "request", Usage: "request id this status belongs to"},
							&cli.StringFlag{Name: "id", Usage: "message id (a retry with the same id has no second effect)"},
						},
						Action: e.sendStatus,
					},
				},
			},
			{
				Name:        "wait",
				Usage:       "Wait for a request to end and show its outcome",
				ArgsUsage:   "<id>",
				Description: "Exits 0 when the request is done, 1 when it failed, was denied or expired, or is still open at the timeout.",
				Flags: []cli.Flag{
					&cli.DurationFlag{Name: "timeout", Value: defaultWaitTimeout, Usage: "how long to wait"},
				},
				Action: e.wait,
			},
			{
				Name:   "park",
				Usage:  "The PreToolUse hook of a peer run, or with --denied its PermissionDenied hook (reads the hook input on stdin)",
				Hidden: true,
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "denied", Usage: "the PermissionDenied hook: record the classifier's block as a park"},
				},
				Action: e.park,
			},
			{
				Name:  "list",
				Usage: "List recent requests and messages across every host (read-only)",
				Flags: []cli.Flag{
					&cli.IntFlag{Name: "limit", Usage: "most items of each kind (1-500; default: the hub's, 50)"},
					&cli.StringFlag{Name: "state", Usage: "only requests in this state, e.g. parked or running"},
				},
				Action: e.list,
			},
			{Name: "inbox", Usage: "List unread status and results for this host", Action: e.inbox},
			{
				Name:      "result",
				Usage:     "Show one message by sender and id, marking it read",
				ArgsUsage: "<sender> <id>",
				Action:    e.result,
			},
			{
				Name:  "listen",
				Usage: "Receive status and results, one JSON line per message on stdout; with --claude, run requests",
				Description: "Exits 3 when a newer listener for this host took over, 1 on any other failure.\n\n" +
					"With --restart-on-upgrade, once that path resolves to another binary than this one and no run is " +
					"claimed or running, it stops claiming and exits 0 for its supervisor to restart it, after " +
					"`systemctl --user daemon-reload` when it runs as a systemd unit.\n\n" +
					"With --claude, each request pushed to this host is run, one at a time, as a headless Claude Code run in auto mode " +
					"once a startup canary has proved the tool gate; without it requests are not claimed. A run's budget and " +
					"deadline are its request's remaining allowance on the hub.",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "claude", Usage: "claude binary; enables request runs"},
					&cli.StringFlag{Name: "run-dir", Usage: "working directory of runs without --checkout (default: the current directory)"},
					&cli.StringFlag{Name: "checkout", Usage: "git checkout each request runs in a worktree of (<state-dir>/" + peerclient.RunsDirName + "/<request>), kept until the request ends"},
					&cli.StringFlag{Name: "state-dir", EnvVars: []string{"STATE_DIRECTORY"}, Usage: "result outbox and worktree location (default: $XDG_STATE_HOME/homelab-peer)"},
					&cli.StringSliceFlag{Name: "allow", Usage: "tool rule a run may use without classification or approval (repeatable; none: the default list; the reply verbs are always allowed)"},
					&cli.StringSliceFlag{Name: "deny", Usage: "tool rule a run may never use (repeatable; none: the default list; the hard-deny floor is always added)"},
					&cli.StringFlag{Name: "policy-file", Usage: `auto-mode policy, JSON {"environment":[...],"allow":[...],"hard_deny":[...]} (default: Claude Code's defaults plus the approver rule)`},
					&cli.StringFlag{Name: "model", Usage: "model for runs (default: claude's)"},
					&cli.StringFlag{Name: "restart-on-upgrade", Usage: "installed peer binary to watch, e.g. /run/current-system/sw/bin/peer; exit 0 to be restarted once it is a newer one and no run is in progress"},
					&cli.StringFlag{Name: "peer", Hidden: true, Usage: "peer binary the run hook calls (default: this executable)"},
				},
				Action: e.listen,
			},
			serviceCommand(e),
			updateCommand(e),
			{
				Name:  "doctor",
				Usage: "Check the path to the hub, this host's identity and, with --dashboard, that dashboard mutations are unreachable",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "dashboard", Usage: "dashboard origin to probe, e.g. https://homelab.example.com (on the Home Assistant box); unset skips the probe"},
				},
				Action: e.doctor,
			},
		},
	}
	err := app.Run(args)
	var st exitStatus
	if err != nil && !errors.Is(err, errReported) && !errors.As(err, &st) {
		renderError(stderr, slices.Contains(args[1:], "--json"), err)
	}
	return exitCode(err)
}

func jsonFlag(c *cli.Context) bool {
	for _, ctx := range c.Lineage() {
		if ctx.Bool("json") {
			return true
		}
	}
	return false
}

// hubClient builds the hub client; inside a peer run it carries the run's
// token (PEER_RUN_TOKEN) so sends bind to the run's request.
func hubClient(c *cli.Context) (*peerclient.Client, error) {
	cl, err := peerclient.New(c.String("hub"))
	if err != nil {
		return nil, err
	}
	cl.RunToken = os.Getenv(peerclient.EnvRunToken)
	return cl, nil
}

// renderError prints a failure: with --json one object on stderr carrying
// success, error and, for a hub problem, status, code and detail.
func renderError(w io.Writer, asJSON bool, err error) {
	if !asJSON {
		fmt.Fprintf(w, "Error: %v\n", err)
		return
	}
	out := map[string]any{"success": false, "error": err.Error()}
	var p *peerclient.Problem
	var u *peerclient.UnreachableError
	switch {
	case errors.As(err, &p):
		out["status"], out["code"] = p.Status, p.Code
		if p.Detail != "" {
			out["detail"] = p.Detail
		}
	case errors.As(err, &u):
		out["code"], out["hub"] = "hub_unreachable", u.Hub
	}
	_ = json.NewEncoder(w).Encode(out)
}

func writeJSON(w io.Writer, v any) { _ = json.NewEncoder(w).Encode(v) }

// ── send ────────────────────────────────────────────────────────────────

func (e env) sendStatus(c *cli.Context) error {
	text := strings.Join(c.Args().Slice(), " ")
	if text == "" {
		return errors.New("status text is required")
	}
	if !slices.Contains(peerclient.Phases, c.String("phase")) {
		return fmt.Errorf("--phase must be one of %s", strings.Join(peerclient.Phases, ", "))
	}
	return e.send(c, peerclient.Send{
		Kind: peerclient.KindStatus, Target: c.String("target"), Phase: c.String("phase"),
		Body: text, RequestID: c.String("request"), ID: c.String("id"),
	})
}

// send makes one synchronous attempt. The id is fixed before it, so the
// caller can retry with --id and get the first outcome back.
func (e env) send(c *cli.Context, s peerclient.Send) error {
	if s.ID == "" {
		s.ID = peerclient.NewID()
	}
	cl, err := hubClient(c)
	if err != nil {
		return err
	}
	res, err := cl.Send(c.Context, s)
	if err != nil {
		return fmt.Errorf("sending %s %s: %w", s.Kind, s.ID, err)
	}
	return e.sendOutput(c, res)
}

// sendOutput shows a send's outcome; a refused or failed one exits 1.
func (e env) sendOutput(c *cli.Context, res peerclient.SendResult) error {
	ok := res.Accepted()
	if jsonFlag(c) {
		writeJSON(e.out, struct {
			Success bool `json:"success"`
			peerclient.SendResult
		}{ok, res})
	} else {
		line := fmt.Sprintf("%s %s %s", res.Kind, res.ID, res.Outcome)
		if res.Reason != nil {
			line += ": " + *res.Reason
		}
		if res.Seq != nil {
			line += fmt.Sprintf(" (seq %d)", *res.Seq)
		}
		if res.Replayed {
			line += " (replayed)"
		}
		fmt.Fprintln(e.out, line)
	}
	if !ok {
		return errReported
	}
	return nil
}

func (e env) sendRequest(c *cli.Context) error {
	text, err := e.requestText(c)
	if err != nil {
		return err
	}
	id := c.String("id")
	if id == "" {
		id = peerclient.NewID()
	}
	cl, err := hubClient(c)
	if err != nil {
		return err
	}
	res, err := cl.SendRequest(c.Context, id, c.String("target"), text)
	if err != nil {
		return fmt.Errorf("sending request %s: %w", id, err)
	}
	if !res.Accepted() || !c.Bool("wait") {
		return e.sendOutput(c, res)
	}
	if !jsonFlag(c) {
		fmt.Fprintf(e.out, "request %s stored; waiting\n", id)
	}
	return e.waitFor(c, cl, id, c.Duration("timeout"))
}

// requestText is the request's text: the arguments, or stdin for a lone -.
func (e env) requestText(c *cli.Context) (string, error) {
	args := c.Args().Slice()
	if len(args) == 1 && args[0] == "-" {
		raw, err := io.ReadAll(io.LimitReader(e.in, maxRequestText+1))
		if err != nil {
			return "", err
		}
		if len(raw) > maxRequestText {
			return "", fmt.Errorf("request text is longer than %d bytes", maxRequestText)
		}
		args = []string{strings.TrimRight(string(raw), "\n")}
	}
	text := strings.Join(args, " ")
	if strings.TrimSpace(text) == "" {
		return "", errors.New("request text is required (or - to read it from stdin)")
	}
	return text, nil
}

// maxRequestText is the hub's limit (16384 characters), checked in bytes
// here and in characters by the hub.
const maxRequestText = 64 << 10

// defaultWaitTimeout bounds `wait` and `send request --wait`.
const defaultWaitTimeout = 10 * time.Minute

func (e env) wait(c *cli.Context) error {
	if c.NArg() != 1 {
		return errors.New("usage: peer wait <id>")
	}
	cl, err := hubClient(c)
	if err != nil {
		return err
	}
	return e.waitFor(c, cl, c.Args().First(), c.Duration("timeout"))
}

// waitFor repeats the hub's bounded wait until the request ends or timeout
// passes, then shows it. Only done exits 0.
func (e env) waitFor(c *cli.Context, cl *peerclient.Client, id string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var r peerclient.Request
	for {
		left := time.Until(deadline)
		var err error
		if r, err = cl.Wait(c.Context, id, left); err != nil {
			return fmt.Errorf("waiting for request %s: %w", id, err)
		}
		if r.Terminal() || left < time.Second {
			break
		}
	}
	ok := r.State == peerclient.StateDone
	if jsonFlag(c) {
		writeJSON(e.out, map[string]any{"success": ok, "terminal": r.Terminal(), "request": r})
	} else {
		line := fmt.Sprintf("request %s %s", r.ID, r.State)
		if r.Reason != nil {
			line += ": " + *r.Reason
		}
		if !r.Terminal() {
			line += fmt.Sprintf(" (still open after %s)", timeout)
		}
		if r.State == peerclient.StateParked && r.Step != nil {
			line += "\nblocked on: " + *r.Step
		}
		if r.Summary != nil && *r.Summary != "" {
			line += "\n" + *r.Summary
		}
		fmt.Fprintln(e.out, line)
	}
	if !ok {
		return errReported
	}
	return nil
}

// ── run side ────────────────────────────────────────────────────────────

// park is the run's PreToolUse hook, or with --denied its PermissionDenied
// hook. Every PreToolUse failure denies the call; the hub report is best
// effort (the park file decides the outcome). The PermissionDenied hook
// writes nothing to stdout, so Claude Code does not retry the call.
func (e env) park(c *cli.Context) error {
	var hub peerclient.HubRunAPI
	if cl, err := hubClient(c); err == nil {
		hub = cl.RunAPI()
	}
	if c.Bool("denied") {
		if err := peerclient.ParkDenied(c.Context, e.in, os.Getenv, hub); err != nil {
			fmt.Fprintln(e.err, err)
		}
		return nil
	}
	if code := peerclient.Park(c.Context, e.in, os.Getenv, hub).Emit(e.out, e.err); code != 0 {
		return exitStatus(code)
	}
	return nil
}

// ── inbox / result ──────────────────────────────────────────────────────

func (e env) inbox(c *cli.Context) error {
	cl, err := hubClient(c)
	if err != nil {
		return err
	}
	ms, err := cl.Inbox(c.Context)
	if err != nil {
		return err
	}
	if ms == nil {
		ms = []peerclient.Message{}
	}
	if jsonFlag(c) {
		writeJSON(e.out, map[string]any{"success": true, "messages": ms})
		return nil
	}
	if len(ms) == 0 {
		fmt.Fprintln(e.out, "No unread messages.")
	}
	for _, m := range ms {
		fmt.Fprintln(e.out, summary(m))
	}
	return nil
}

func (e env) list(c *cli.Context) error {
	cl, err := hubClient(c)
	if err != nil {
		return err
	}
	a, err := cl.List(c.Context, c.Int("limit"), c.String("state"))
	if err != nil {
		return err
	}
	if jsonFlag(c) {
		writeJSON(e.out, map[string]any{"success": true, "requests": a.Requests, "messages": a.Messages})
		return nil
	}
	fmt.Fprintf(e.out, "Requests (%d):\n", len(a.Requests))
	for _, raw := range a.Requests {
		var r struct {
			ID, Sender, Target, State string
			CreatedAt                 time.Time `json:"created_at"`
			Summary                   *string
		}
		_ = json.Unmarshal(raw, &r)
		line := fmt.Sprintf("  %s %s %s -> %s [%s]", r.CreatedAt.Local().Format(time.DateTime), r.ID, r.Sender, r.Target, r.State)
		if r.Summary != nil && *r.Summary != "" {
			line += " " + *r.Summary
		}
		fmt.Fprintln(e.out, line)
	}
	fmt.Fprintf(e.out, "Messages (%d):\n", len(a.Messages))
	for _, raw := range a.Messages {
		var m peerclient.Message
		_ = json.Unmarshal(raw, &m)
		fmt.Fprintln(e.out, "  "+summary(m))
	}
	return nil
}

func (e env) result(c *cli.Context) error {
	if c.NArg() != 2 {
		return errors.New("usage: peer result <sender> <id>")
	}
	cl, err := hubClient(c)
	if err != nil {
		return err
	}
	m, err := cl.Read(c.Context, c.Args().Get(0), c.Args().Get(1))
	if err != nil {
		return err
	}
	if jsonFlag(c) {
		writeJSON(e.out, map[string]any{"success": true, "message": m})
		return nil
	}
	fmt.Fprintln(e.out, summary(m))
	return nil
}

func summary(m peerclient.Message) string {
	s := fmt.Sprintf("#%d %s %s from %s (id %s", m.Seq, m.CreatedAt.Local().Format(time.DateTime), m.Kind, m.Sender, m.ID)
	if m.RequestID != nil {
		s += ", request " + *m.RequestID
	}
	s += ")"
	if m.Phase != nil {
		s += " [" + *m.Phase + "]"
	}
	if m.Body != nil {
		s += " " + *m.Body
	}
	return s
}

// ── listen ──────────────────────────────────────────────────────────────

func (e env) listen(c *cli.Context) error {
	cl, err := hubClient(c)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(c.Context, os.Interrupt, syscall.SIGTERM)
	defer stop()
	log := slog.New(slog.NewTextHandler(e.err, nil))
	enc := json.NewEncoder(e.out)
	l := &peerclient.Listener{
		Client: cl, Instance: peerclient.NewInstance(), StartedAt: time.Now(), Log: log,
		Deliver: func(m peerclient.Message) error { return enc.Encode(m) },
		OnHello: func(id peerclient.Identity) {
			log.Info("hello", "host", id.Host, "node", id.Node, "kinds", strings.Join(id.Kinds, ","))
		},
		UpgradeWatch: c.String("restart-on-upgrade"),
		Version:      version,
	}
	if c.String("claude") != "" {
		if l.Runs, err = runsConfig(c, log); err != nil {
			return err
		}
	}
	log.Info("listening", "hub", cl.Base(), "instance", l.Instance, "runs", l.Runs != nil)
	err = l.Run(ctx)
	if errors.Is(err, peerclient.ErrUpgraded) {
		reloadUserManager(log)
		return nil
	}
	return err
}

// reloadUserManager runs `systemctl --user daemon-reload` before an upgrade
// restart when this listener is a systemd unit (INVOCATION_ID set), so the
// restart runs the changed unit's ExecStart. Best effort: a failure is
// logged.
func reloadUserManager(log *slog.Logger) {
	if os.Getenv("INVOCATION_ID") == "" {
		return
	}
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, systemctl, "--user", "daemon-reload").CombinedOutput(); err != nil {
		log.Warn("systemctl --user daemon-reload failed; the restart may run the old unit", "error", err, "output", strings.TrimSpace(string(out)))
	}
}

// runsConfig is the listener's run configuration. A run's budget and
// deadline come from each claim (the request's remaining allowance): the
// hub fails a running request as timed out only after its remaining time
// plus a grace, so the listener's deadline, its remaining time, ends the run
// first.
func runsConfig(c *cli.Context, log *slog.Logger) (*peerclient.Runs, error) {
	var policy peerclient.Policy
	if p := c.String("policy-file"); p != "" {
		var err error
		if policy, err = peerclient.LoadPolicy(p); err != nil {
			return nil, err
		}
	}
	state := c.String("state-dir")
	if state == "" {
		dir, err := stateHome()
		if err != nil {
			return nil, err
		}
		state = filepath.Join(dir, "homelab-peer")
	}
	outbox, err := peerclient.OpenOutbox(filepath.Join(state, "outbox"))
	if err != nil {
		return nil, fmt.Errorf("opening the result outbox: %w", err)
	}
	rules := peerclient.DefaultRules()
	if allow := c.StringSlice("allow"); len(allow) > 0 {
		rules.Allow = allow
	}
	if deny := c.StringSlice("deny"); len(deny) > 0 {
		rules.Deny = deny
	}
	return &peerclient.Runs{
		Launcher: peerclient.Launcher{
			Claude: c.String("claude"), Peer: c.String("peer"), Dir: c.String("run-dir"), Rules: rules, Policy: policy,
			Model: c.String("model"), Log: log,
		},
		Checkout: c.String("checkout"),
		RunsDir:  filepath.Join(state, peerclient.RunsDirName),
		Outbox:   outbox,
	}, nil
}

func stateHome() (string, error) {
	if d := os.Getenv("XDG_STATE_HOME"); filepath.IsAbs(d) {
		return d, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("no state directory: pass --state-dir (%w)", err)
	}
	return filepath.Join(home, ".local", "state"), nil
}
