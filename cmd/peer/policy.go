package main

// The host's run policy: the auto-mode rules a listener's runs are judged
// by. `peer policy init` writes the default to ~/.config/peer/policy.json,
// where `peer service install` also writes it when the host has none, so a
// listener never runs on Claude Code's built-in rules alone by accident.

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/urfave/cli/v2"

	"github.com/ogglord/homelab-peer/internal/peerclient"
)

// policyFileName is the host's policy under the user's config directory.
const policyFileName = "peer/policy.json"

func defaultPolicyPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(userConfigDir(home), policyFileName), nil
}

func policyCommand(e env) *cli.Command {
	file := &cli.StringFlag{Name: "file", Usage: "policy file (default: ~/.config/peer/policy.json)"}
	return &cli.Command{
		Name:  "policy",
		Usage: "The auto-mode policy this host's runs are judged by",
		Description: "A policy is JSON {\"environment\": [...], \"allow\": [...], \"hard_deny\": [...]}, each a list of prose " +
			"rules, with \"$defaults\" for Claude Code's built-in ones. A hard_deny rule holds even when the request asks. " +
			"The listener reads it at start (listen --policy-file): restart it after an edit.",
		Subcommands: []*cli.Command{
			{
				Name:   "default",
				Usage:  "Print the default policy",
				Action: func(*cli.Context) error { _, err := e.out.Write(peerclient.DefaultPolicyFile()); return err },
			},
			{
				Name:  "init",
				Usage: "Write the default policy to the policy file; an existing file is kept unless --force",
				Flags: []cli.Flag{file, &cli.BoolFlag{Name: "force", Usage: "replace an existing file"}},
				Action: func(c *cli.Context) error {
					path, err := policyPath(c)
					if err != nil {
						return err
					}
					wrote, err := writeDefaultPolicy(path, c.Bool("force"))
					if err != nil {
						return err
					}
					if !wrote {
						return fmt.Errorf("%s exists; pass --force to replace it with the default", path)
					}
					fmt.Fprintf(e.out, "wrote %s\n", path)
					return nil
				},
			},
			{
				Name:  "show",
				Usage: "Print the policy file, after checking that it parses",
				Flags: []cli.Flag{file},
				Action: func(c *cli.Context) error {
					path, err := policyPath(c)
					if err != nil {
						return err
					}
					if _, err := peerclient.LoadPolicy(path); errors.Is(err, fs.ErrNotExist) {
						return fmt.Errorf("no policy at %s: `peer policy init` writes the default", path)
					} else if err != nil {
						return err
					}
					b, err := os.ReadFile(path)
					if err != nil {
						return err
					}
					fmt.Fprintf(e.out, "# %s\n", path)
					_, err = e.out.Write(b)
					return err
				},
			},
		},
	}
}

func policyPath(c *cli.Context) (string, error) {
	if p := c.String("file"); p != "" {
		return filepath.Abs(p)
	}
	return defaultPolicyPath()
}

// writeDefaultPolicy writes the default policy to path, keeping an
// existing file unless force. It reports whether it wrote.
func writeDefaultPolicy(path string, force bool) (bool, error) {
	if _, err := os.Stat(path); err == nil && !force {
		return false, nil
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return false, err
	}
	return true, os.WriteFile(path, peerclient.DefaultPolicyFile(), 0o644)
}
