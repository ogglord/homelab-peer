package peerclient

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// RunsDirName is the directory under the listener's state directory that
// holds one entry per request in progress: the request's worktree of the
// checkout, or an empty marker directory without one.
const RunsDirName = "runs"

// PrepareRunWorktree makes dir a worktree of checkout for one request:
// created detached at checkout's current HEAD on the request's first run, so
// it never holds a branch, and reused as it is on every resume, so the
// resumed session finds its own changes. RemoveRunWorktree removes it when
// the request ends.
//
// Workspace trust: none is written. `claude -p` skips the trust dialog (its
// --help: "The workspace trust dialog is skipped when Claude is run in
// non-interactive mode"), unlike the Remote Control servers in claude-rc.nix,
// which are interactive sessions and need `claude` run once in the repo.
func PrepareRunWorktree(ctx context.Context, checkout, dir string) error {
	checkout, err := filepath.Abs(checkout)
	if err != nil {
		return err
	}
	dir, err = filepath.Abs(dir)
	if err != nil {
		return err
	}
	if _, serr := os.Stat(dir); errors.Is(serr, os.ErrNotExist) {
		rev, err := git(ctx, checkout, "rev-parse", "--verify", "HEAD^{commit}")
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
			return err
		}
		// A worktree whose directory was deleted is still registered.
		if _, err := git(ctx, checkout, "worktree", "prune"); err != nil {
			return err
		}
		_, err = git(ctx, checkout, "worktree", "add", "--detach", dir, rev)
		return err
	} else if serr != nil {
		return serr
	}
	want, err := git(ctx, checkout, "rev-parse", "--path-format=absolute", "--git-common-dir")
	if err != nil {
		return err
	}
	got, err := git(ctx, dir, "rev-parse", "--path-format=absolute", "--git-common-dir")
	if err != nil || got != want {
		return fmt.Errorf("%s exists but is not a worktree of %s", dir, checkout)
	}
	if top, err := git(ctx, dir, "rev-parse", "--show-toplevel"); err != nil || top != dir {
		return fmt.Errorf("%s is inside a worktree, not one", dir)
	}
	return nil
}

// RemoveRunWorktree removes a request's worktree dir of checkout, changes
// and all; a directory git does not know as one is deleted.
func RemoveRunWorktree(ctx context.Context, checkout, dir string) error {
	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		_, err := git(ctx, checkout, "worktree", "prune")
		return err
	}
	_, rerr := git(ctx, checkout, "worktree", "remove", "--force", dir)
	if rerr != nil {
		if err := os.RemoveAll(dir); err != nil {
			return errors.Join(rerr, err)
		}
	}
	_, err := git(ctx, checkout, "worktree", "prune")
	return err
}

func git(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
	}
	return strings.TrimSpace(out.String()), nil
}
