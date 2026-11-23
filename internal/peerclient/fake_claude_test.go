package peerclient_test

import (
	"context"
	"fmt"
	"os"

	"github.com/ogglord/homelab-peer/internal/peerclient"
	"github.com/ogglord/homelab-peer/internal/peerclient/fakeclaude"
)

// The fake claude is fakeclaude.Main (testdata/fake-claude re-enters the test
// binary to run it); this is what it records.
type fakeRecord = fakeclaude.Record

// fakePeer is the peer binary's two run-side commands.
func fakePeer(args []string) int {
	switch {
	case len(args) == 1 && args[0] == "park":
		return peerclient.Park(context.Background(), os.Stdin, os.Getenv, nil).Emit(os.Stdout, os.Stderr)
	case len(args) == 2 && args[0] == "park" && args[1] == "--denied":
		if err := peerclient.ParkDenied(context.Background(), os.Stdin, os.Getenv, nil); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		return 0
	}
	fmt.Fprintln(os.Stderr, "fake peer: unsupported", args)
	return 1
}
