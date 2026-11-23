package peerclient

import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// sessionNamespace is the UUIDv5 namespace of run sessions. Fixed: changing
// it orphans every parked request's transcript.
var sessionNamespace = [16]byte{0x5e, 0x1f, 0x3c, 0x2a, 0x9b, 0x47, 0x4d, 0x0e, 0xa1, 0x6c, 0x83, 0xf2, 0x17, 0xd4, 0x58, 0xb9}

// SessionUUID is the Claude session of a request's runs: a UUIDv5 of the
// request id, so every resume of the request finds the same session.
func SessionUUID(requestID string) string {
	h := sha1.New()
	h.Write(sessionNamespace[:])
	h.Write([]byte(requestID))
	b := h.Sum(nil)[:16]
	b[6] = b[6]&0x0f | 0x50
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// TranscriptPath is where Claude Code keeps session id's transcript for a
// run in cwd: <config>/projects/<slug>/<id>.jsonl, the slug being the
// absolute (symlink-resolved) cwd with every character other than an ASCII
// letter or digit replaced by '-'. config is the run's Claude config
// directory (claudeConfigDir).
func TranscriptPath(config, cwd, id string) string {
	return filepath.Join(config, "projects", projectSlug(cwd), id+".jsonl")
}

func projectSlug(cwd string) string {
	if abs, err := filepath.Abs(cwd); err == nil {
		cwd = abs
	}
	if real, err := filepath.EvalSymlinks(cwd); err == nil {
		cwd = real
	}
	return strings.Map(func(r rune) rune {
		if r < 0x80 && (r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return r
		}
		return '-'
	}, cwd)
}

// claudeConfigDir is the Claude config directory of a run with environment
// environ (the last setting wins): CLAUDE_CONFIG_DIR, else $HOME/.claude.
func claudeConfigDir(environ []string) string {
	var config, home string
	for _, kv := range environ {
		if v, ok := strings.CutPrefix(kv, "CLAUDE_CONFIG_DIR="); ok {
			config = v
		} else if v, ok := strings.CutPrefix(kv, "HOME="); ok {
			home = v
		}
	}
	if config != "" {
		return config
	}
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	return filepath.Join(home, ".claude")
}

// forgetSession deletes what Claude Code kept of session id for a run in
// cwd: the transcript, its sidecar directory and the file edit history.
// Transcripts hold every value the run was handed.
func forgetSession(config, cwd, id string) error {
	t := TranscriptPath(config, cwd, id)
	return errors.Join(
		removeMissingOK(t),
		os.RemoveAll(strings.TrimSuffix(t, ".jsonl")),
		os.RemoveAll(filepath.Join(config, "file-history", id)),
	)
}

func removeMissingOK(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// runDirName is a request's directory name under the runs directory: the
// id itself when it is a plain name, else '%' and its hex. A name starting
// with '.' is never a request's (the canary's worktree is .canary).
func runDirName(id string) string {
	plain := id != ""
	for i, r := range id {
		ok := r < 0x80 && (r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || (i > 0 && strings.ContainsRune("._-", r)))
		plain = plain && ok
	}
	if plain {
		return id
	}
	return "%" + hex.EncodeToString([]byte(id))
}

// runIDOf is the request id of a runs directory entry, "" for one that is
// not a request's.
func runIDOf(name string) string {
	if h, ok := strings.CutPrefix(name, "%"); ok {
		b, err := hex.DecodeString(h)
		if err != nil {
			return ""
		}
		return string(b)
	}
	if strings.HasPrefix(name, ".") {
		return ""
	}
	return name
}
