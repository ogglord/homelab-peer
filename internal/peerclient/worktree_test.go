package peerclient_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ogglord/homelab-peer/internal/peerclient"
)

func gitT(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := exec.Command("git", append([]string{"-C", dir, "-c", "user.email=t@example.com", "-c", "user.name=t"}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// newCheckout is a git checkout with one commit.
func newCheckout(t *testing.T) string {
	t.Helper()
	checkout := t.TempDir()
	gitT(t, checkout, "init", "-q")
	if err := os.WriteFile(filepath.Join(checkout, "README"), []byte("one\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitT(t, checkout, "add", ".")
	gitT(t, checkout, "commit", "-qm", "init")
	return checkout
}

// R10: a request's worktree is made at the checkout's HEAD, kept as its run
// left it for the resume, and removed with its changes at the end.
func TestRunWorktreeKeptThenRemoved(t *testing.T) {
	t.Parallel()
	checkout := newCheckout(t)
	dir := filepath.Join(t.TempDir(), peerclient.RunsDirName, "req-1")
	ctx := context.Background()
	if err := peerclient.PrepareRunWorktree(ctx, checkout, dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "README"), []byte("changed by the run\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := peerclient.PrepareRunWorktree(ctx, checkout, dir); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "README")); string(got) != "changed by the run\n" {
		t.Fatalf("the resume's worktree lost the run's change: README = %q", got)
	}
	if err := peerclient.RemoveRunWorktree(ctx, checkout, dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("worktree still there: %v", err)
	}
	if n := strings.Count(gitT(t, checkout, "worktree", "list", "--porcelain"), "worktree "); n != 1 {
		t.Fatalf("%d worktrees registered, want only the checkout", n)
	}
}
