package review

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"syscall"

	"github.com/getjump/airbag/internal/session"
)

// Agents keep some state in a JSON file in $HOME that they rewrite every
// run: ~/.claude.json holds counters, a machine id and migration markers
// next to things that steer later runs (MCP servers, tool permissions,
// per-project trust). The whole file goes through the branch, so none of
// it reaches the real file until review — but that would raise a
// persistence alarm on every single session over counters the user does
// not care about.
//
// jsonConfigs resolves that without any agent-specific logic in the code
// path: for each named file, changes confined to WriteBack keys are
// copied to the real file at session end and then drop out of review,
// while any other key stays in the branch, and Persist keys (which start
// commands or change trust) are flagged. The agent name appears only
// here, as data, like the persist tables.
//
// WriteBack is an ALLOWLIST, built from what Claude Code was observed to
// write on its own in a non-interactive run plus account metadata from a
// login. An unknown key is not on it, so it stays in the branch for
// review: that costs a review entry, never a silent write.
type jsonConfig struct {
	path      string   // relative to $HOME
	writeBack []string // benign top-level keys copied back to the real file
	persist   []string // top-level keys that run code or change trust
}

var jsonConfigs = []jsonConfig{
	{
		path: ".claude.json",
		// Observed written by `claude -p` 2.1.x on its own, plus
		// numStartups (a startup counter of the same family) and
		// oauthAccount (account metadata recorded by a login inside the
		// session). Interactive sessions may write more; those keys stay
		// in the branch until added here (see the PR notes).
		writeBack: []string{
			"firstStartTime", "firstStartVersion", "machineID", "userID",
			"migrationVersion", "opusProMigrationComplete", "sonnet1m45MigrationComplete",
			"seenNotifications", "hasResetAutoModeOptInForDefaultOffer",
			"pluginUsage", "numStartups", "oauthAccount",
		},
		// Keys that name commands to run or change what is trusted. A
		// change to any of these is flagged "persist" in review.
		persist: []string{
			"mcpServers", "enabledMcpjsonServers", "disabledMcpjsonServers", "mcpContextUris",
			"permissions", "allowedTools", "hooks", "env", "projects", "apiKeyHelper",
		},
	},
}

func configFor(rel string) *jsonConfig {
	for i := range jsonConfigs {
		if jsonConfigs[i].path == rel {
			return &jsonConfigs[i]
		}
	}
	return nil
}

// WriteBackConfigs copies the agent's benign changes to allowlisted keys
// of each jsonConfig back to the real file, atomically, at session end.
// It runs only when $HOME was branched (otherwise there is no branch copy
// to read, and nothing reached the real file to begin with). Any other
// change is left in the branch for review; a malformed file on either
// side is left untouched. It returns one human-readable line per file it
// wrote, for the caller to print. It never changes a key the agent did
// not, and re-reads the real file so a concurrent host edit to a
// different key is kept.
func WriteBackConfigs(s *session.Session) []string {
	if !s.OverHome {
		return nil // no branch of $HOME: the real file was never shadowed
	}
	var msgs []string
	for i := range jsonConfigs {
		cf := &jsonConfigs[i]
		branchPath := filepath.Join(s.HomeUpper(), cf.path)
		branchRaw, err := readRegular(branchPath)
		if err != nil {
			continue // not changed, or not a regular file the agent could point elsewhere
		}
		branch, err := topLevel(branchRaw)
		if err != nil {
			continue // malformed in the branch: leave it there for review
		}
		realPath := filepath.Join(s.Home, cf.path)
		realRaw, rerr := readRegular(realPath)
		real := map[string]json.RawMessage{}
		switch {
		case rerr == nil:
			if real, err = topLevel(realRaw); err != nil {
				continue // malformed real file: never corrupt it
			}
		case !errors.Is(rerr, fs.ErrNotExist):
			continue // a symlink or other non-regular file: leave it alone
		}
		var wrote []string
		for _, k := range cf.writeBack {
			bv, ok := branch[k]
			if !ok {
				continue
			}
			if rv, ok := real[k]; !ok || canon(rv) != canon(bv) {
				real[k] = bv
				wrote = append(wrote, k)
			}
		}
		if len(wrote) > 0 {
			if err := writeJSONAtomic(realPath, real); err != nil {
				msgs = append(msgs, fmt.Sprintf("could not write %s back: %v", cf.path, err))
				continue
			}
			sort.Strings(wrote)
			msgs = append(msgs, fmt.Sprintf("~/%s: wrote back %d benign key(s): %s", cf.path, len(wrote), strings.Join(wrote, ", ")))
		}
		// If the branch copy now matches the real file, only benign keys
		// differed, so drop it: review shows nothing for this file.
		if after, err := readRegular(realPath); err == nil {
			if afterTop, err := topLevel(after); err == nil && sameTopLevel(branch, afterTop) {
				_ = os.Remove(branchPath)
			}
		}
	}
	return msgs
}

// configKeyChange describes a change to a jsonConfig file for review: the
// top-level keys that differ (names only, never values), and whether any
// of them is a persist key. ok is false when the change is not a config
// file. Used so review shows "keys: mcpServers" rather than a diff that
// could print tokens.
func configKeyChange(c Change) (keys []string, persist bool, ok bool) {
	if c.Layer != "home" || c.IsDir() {
		return nil, false, false
	}
	cf := configFor(filepath.ToSlash(c.Rel))
	if cf == nil {
		return nil, false, false
	}
	branch, berr := topLevelFile(c.Upper)
	if berr != nil {
		return nil, false, true // malformed: a change, but no readable keys
	}
	real, _ := topLevelFile(c.Path)
	keys = changedKeys(real, branch)
	for _, k := range keys {
		if slices.Contains(cf.persist, k) {
			persist = true
		}
	}
	return keys, persist, true
}

func topLevel(b []byte) (map[string]json.RawMessage, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func topLevelFile(path string) (map[string]json.RawMessage, error) {
	b, err := readRegular(path)
	if err != nil {
		return nil, err
	}
	return topLevel(b)
}

// errNotRegular: the path is a symlink, a whiteout or another
// non-regular file.
var errNotRegular = errors.New("not a regular file")

// readRegular reads a file only if it is a regular file, without
// following a symlink. The branch is written by the agent, so a symlink
// there could point host-side airbag at any file the agent chose; it
// opens with O_NOFOLLOW and checks the opened file, so a swap between
// the check and the read does not help either.
func readRegular(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, errNotRegular
		}
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errNotRegular
	}
	return io.ReadAll(io.LimitReader(f, 16<<20))
}

// changedKeys is the sorted set of top-level keys whose value differs
// between two configs (present in one side only counts as changed).
func changedKeys(a, b map[string]json.RawMessage) []string {
	seen := map[string]bool{}
	var out []string
	for k := range a {
		seen[k] = true
	}
	for k := range b {
		seen[k] = true
	}
	for k := range seen {
		if canon(a[k]) != canon(b[k]) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func sameTopLevel(a, b map[string]json.RawMessage) bool {
	return len(changedKeys(a, b)) == 0
}

// canon returns a value's canonical form (object keys sorted), so two
// configs compare by meaning, not by formatting. A nil or unparsable
// value canonicalizes to "", so a missing key differs from any present
// one.
func canon(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return string(b)
	}
	out, err := json.Marshal(v)
	if err != nil {
		return string(b)
	}
	return string(out)
}

// writeJSONAtomic writes obj to path through a temp file in the same
// directory and a rename, keeping the file's mode. Unchanged keys keep
// their exact values (they ride along as json.RawMessage); only the key
// order is normalized.
func writeJSONAtomic(path string, obj map[string]json.RawMessage) error {
	out, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		return err
	}
	out = append(out, '\n')
	mode := os.FileMode(0o600)
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".airbag-cfg-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(out); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// agentMemory reports whether a home path is inside a Claude Code project
// memory directory (~/.claude/projects/<slug>/memory/…), which later
// sessions load as instructions.
func agentMemory(rel string) bool {
	parts := strings.Split(strings.TrimSuffix(filepath.ToSlash(rel), "/"), "/")
	return len(parts) >= 4 && parts[0] == ".claude" && parts[1] == "projects" && parts[3] == "memory"
}
