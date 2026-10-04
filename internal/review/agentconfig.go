package review

import (
	"crypto/sha256"
	"encoding/hex"
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

	"golang.org/x/sys/unix"

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
// path. Each entry names a file and lists key PATHS in two classes:
//
//   - writeBack: benign keys the CLI rewrites on its own every run. A
//     change confined to them is copied to the real file at session end
//     and then drops out of review.
//   - persist: keys that start commands or change trust. A change to one
//     stays in the branch and is flagged "persist".
//
// Any other changed key is unknown: it stays in the branch and review
// lists it by name. A path is dot-separated top-level keys, and one
// segment may be "*", which matches any key at that level, so
// "projects.*.lastCost" covers every project's entry. A key whose
// sub-keys are listed (projects) is compared sub-key by sub-key; a key
// with no listed sub-keys is compared whole. The agent name appears only
// here, as data, like the persist tables.
//
// writeBack is an ALLOWLIST, built from what Claude Code 2.1.x was
// observed to write on its own, in a non-interactive run and in
// interactive runs driven through a pseudo-terminal: an unknown key is
// not on it, so it costs a review entry, never a silent write.
type jsonConfig struct {
	path      string   // relative to $HOME
	writeBack []string // benign key paths copied back to the real file
	persist   []string // key paths that run code or change trust
}

var jsonConfigs = []jsonConfig{
	{
		path: ".claude.json",
		writeBack: []string{
			// Written by a non-interactive `claude -p` run on its own.
			"firstStartTime", "firstStartVersion", "machineID", "userID",
			"migrationVersion", "opusProMigrationComplete", "sonnet1m45MigrationComplete",
			"seenNotifications", "hasResetAutoModeOptInForDefaultOffer", "pluginUsage",
			// Written by interactive sessions: startup, onboarding and tip
			// counters, and markers of what was already shown.
			"numStartups", "hasCompletedOnboarding", "lastOnboardingVersion",
			"tipsHistory", "tipLifetimeShownCounts", "tipsHistoryByCommand",
			"lastReleaseNotesSeen", "lastClawdEntranceVersion",
			// Account metadata recorded by a login inside the session.
			"oauthAccount",
			// Per-project counters an interactive session rewrites on exit.
			"projects.*.lastSessionId", "projects.*.lastStartTime", "projects.*.lastVersionBase",
			"projects.*.lastGracefulShutdown", "projects.*.lastCost", "projects.*.lastDuration",
			"projects.*.lastAPIDuration", "projects.*.lastAPIDurationWithoutRetries",
			"projects.*.lastToolDuration", "projects.*.lastFpsAverage", "projects.*.lastFpsLow1Pct",
			"projects.*.lastLinesAdded", "projects.*.lastLinesRemoved",
			"projects.*.lastTotalInputTokens", "projects.*.lastTotalOutputTokens",
			"projects.*.lastTotalCacheCreationInputTokens", "projects.*.lastTotalCacheReadInputTokens",
			"projects.*.lastTotalWebSearchRequests", "projects.*.lastModelUsage",
			"projects.*.lastSessionMetrics",
		},
		persist: []string{
			"mcpServers", "enabledMcpjsonServers", "disabledMcpjsonServers", "mcpContextUris",
			"permissions", "allowedTools", "hooks", "env", "apiKeyHelper",
			// Answers to "use this API key from the environment?".
			"customApiKeyResponses",
			// Per project: tool permissions, MCP servers, folder trust, and
			// approval of CLAUDE.md imports from outside the project.
			"projects.*.allowedTools", "projects.*.mcpServers", "projects.*.mcpContextUris",
			"projects.*.enabledMcpjsonServers", "projects.*.disabledMcpjsonServers",
			"projects.*.hasTrustDialogAccepted", "projects.*.hasClaudeMdExternalIncludesApproved",
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

type keyClass int

const (
	classUnknown keyClass = iota
	classWriteBack
	classPersist
)

// keyChange is one changed key path, at the depth the table describes.
type keyChange struct {
	path  []string // concrete keys from the top level down
	class keyClass
}

// String renders a path for review: keys that are plain identifiers
// joined with dots, any other key in brackets, since project keys are
// paths (projects[/home/me/api].allowedTools). Names only, never values.
func (k keyChange) String() string {
	if len(k.path) == 0 {
		return "(whole file)"
	}
	var b strings.Builder
	for i, seg := range k.path {
		switch {
		case i == 0:
			b.WriteString(seg)
		case plainKey(seg):
			b.WriteString("." + seg)
		default:
			b.WriteString("[" + seg + "]")
		}
	}
	return b.String()
}

func plainKey(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(r == '_' || r == '-' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
			return false
		}
	}
	return true
}

func patternMatch(pat []string, path []string) bool {
	if len(pat) != len(path) {
		return false
	}
	for i := range pat {
		if pat[i] != "*" && pat[i] != path[i] {
			return false
		}
	}
	return true
}

// class returns the class of an exact path, and whether the table lists
// any path below it (so it is compared key by key).
func (cf *jsonConfig) class(path []string) (c keyClass, listed, below bool) {
	for _, set := range []struct {
		pats []string
		c    keyClass
	}{{cf.writeBack, classWriteBack}, {cf.persist, classPersist}} {
		for _, p := range set.pats {
			pat := strings.Split(p, ".")
			if patternMatch(pat, path) {
				c, listed = set.c, true
			}
			if len(pat) > len(path) && patternMatch(pat[:len(path)], path) {
				below = true
			}
		}
	}
	return c, listed, below
}

// diff lists the changed key paths between a (the real file) and b (the
// branch), at the depth the table describes: a listed path is one change,
// a path with listed sub-paths is compared key by key, anything else is
// one unknown change.
func (cf *jsonConfig) diff(prefix []string, a, b json.RawMessage) []keyChange {
	if canon(a) == canon(b) {
		return nil
	}
	c, listed, below := cf.class(prefix)
	if listed {
		return []keyChange{{prefix, c}}
	}
	if len(prefix) == 0 || below {
		am, aok := object(a)
		bm, bok := object(b)
		if aok && bok {
			var out []keyChange
			for _, k := range unionKeys(am, bm) {
				out = append(out, cf.diff(append(slices.Clip(prefix), k), am[k], bm[k])...)
			}
			return out
		}
	}
	return []keyChange{{prefix, classUnknown}}
}

// WriteBackConfigs copies the agent's changes to writeBack paths of each
// jsonConfig to the real file, atomically, at session end. It runs only
// when $HOME was branched (otherwise there is no branch copy to read, and
// nothing reached the real file to begin with). Any other change is left
// in the branch for review; a malformed or non-regular file on either
// side is left untouched. It returns one human-readable line per file it
// wrote, for the caller to print. It never changes a key the agent did
// not, never writes a deletion back (a removed key stays in the branch
// for review), and re-reads the real file so a concurrent host edit to a
// different key is kept. What it wrote is recorded in s.WroteBack, so
// apply's conflict check knows the write was airbag's; when the host had
// also edited the file during the session, nothing is recorded and apply
// reports the conflict as before.
func WriteBackConfigs(s *session.Session) []string {
	if !s.OverHome {
		return nil // no branch of $HOME: the real file was never shadowed
	}
	since := s.Created
	if !s.Baseline.IsZero() {
		since = s.Baseline
	}
	var msgs []string
	saved := false
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
		default:
			realRaw = []byte("{}")
		}
		// The host edited the real file during the session unless its
		// change time is older, or it is exactly what airbag wrote back
		// in an earlier run of this session.
		hostEdited := false
		if rerr == nil {
			if fi, err := os.Lstat(realPath); err == nil && fi.ModTime().After(since) && s.WroteBack[realPath].SHA256 != digest(realRaw) {
				hostEdited = true
			}
		}
		var wrote []string
		for _, ch := range cf.diff(nil, realRaw, branchRaw) {
			if ch.class != classWriteBack {
				continue
			}
			v, ok := getPath(branch, ch.path)
			if !ok {
				continue // a removed key is a change for review, not a write
			}
			if err := setPath(real, ch.path, v); err == nil {
				wrote = append(wrote, ch.String())
			}
		}
		if len(wrote) > 0 {
			if err := writeJSONAtomic(realPath, real); err != nil {
				msgs = append(msgs, fmt.Sprintf("could not write %s back: %v", cf.path, err))
				continue
			}
			msgs = append(msgs, fmt.Sprintf("~/%s: wrote back %d benign key(s): %s", cf.path, len(wrote), strings.Join(wrote, ", ")))
			if s.WroteBack == nil {
				s.WroteBack = map[string]session.WriteStamp{}
			}
			if st, ok := stamp(realPath); ok && !hostEdited {
				s.WroteBack[realPath] = st
			} else {
				delete(s.WroteBack, realPath)
			}
			saved = true
		}
		// If the branch copy now matches the real file, only benign keys
		// differed, so drop it: review shows nothing for this file.
		if after, err := readRegular(realPath); err == nil && len(cf.diff(nil, after, branchRaw)) == 0 {
			_ = os.Remove(branchPath)
		}
	}
	if saved {
		if err := s.Save(); err != nil {
			msgs = append(msgs, fmt.Sprintf("could not record the write-back: %v", err))
		}
	}
	return msgs
}

// digest is the hex SHA-256 of b, as recorded in session.WroteBack.
func digest(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// stamp reads a regular file's content digest and change time.
func stamp(path string) (session.WriteStamp, bool) {
	b, err := readRegular(path)
	if err != nil {
		return session.WriteStamp{}, false
	}
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return session.WriteStamp{}, false
	}
	return session.WriteStamp{SHA256: digest(b), Ctime: st.Ctim.Nano()}, true
}

// OwnWrite reports whether the file at path is exactly as
// WriteBackConfigs left it in this session: the same content and the
// same change time, so no host edit since, a chmod included. Its newer
// change time is then airbag's and not a host edit.
func OwnWrite(s *session.Session, path string) bool {
	want, ok := s.WroteBack[path]
	if !ok {
		return false
	}
	got, ok := stamp(path)
	return ok && got == want
}

// configChanges lists a config file's changed key paths for review (names
// only, never values). ok is false when the change is not a config file;
// readable is false when either side is not a readable regular JSON file.
func configChanges(c Change) (changes []keyChange, readable, ok bool) {
	if c.Layer != "home" || c.IsDir() {
		return nil, false, false
	}
	cf := configFor(filepath.ToSlash(c.Rel))
	if cf == nil {
		return nil, false, false
	}
	branchRaw, err := readRegular(c.Upper)
	if err != nil {
		return nil, false, true
	}
	if _, err := topLevel(branchRaw); err != nil {
		return nil, false, true
	}
	realRaw, err := readRegular(c.Path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		realRaw = []byte("{}")
	case err != nil:
		return nil, false, true
	}
	return cf.diff(nil, realRaw, branchRaw), true, true
}

// configKeyChange is configChanges as names, and whether any is persist.
func configKeyChange(c Change) (keys []string, persist bool, ok bool) {
	changes, _, ok := configChanges(c)
	for _, ch := range changes {
		keys = append(keys, ch.String())
		if ch.class == classPersist {
			persist = true
		}
	}
	return keys, persist, ok
}

// configFlags are review's flags for a config file change, one per
// class, each naming its keys: "persist" and "persist key(s): …" for keys
// that run code or change trust, "unknown key(s): …" for keys the table
// does not list (shown plainly, not as persistence), and "benign key(s):
// …" for listed benign keys that were not written back (removed by the
// agent, or the real file could not be written). nil when c is not a
// config file.
func configFlags(c Change) []string {
	changes, readable, ok := configChanges(c)
	if !ok {
		return nil
	}
	if !readable {
		return []string{"not a readable regular JSON file"}
	}
	byClass := map[keyClass][]string{}
	for _, ch := range changes {
		byClass[ch.class] = append(byClass[ch.class], ch.String())
	}
	var out []string
	if k := byClass[classPersist]; len(k) > 0 {
		out = append(out, "persist", "persist key(s): "+strings.Join(k, ", "))
	}
	if k := byClass[classUnknown]; len(k) > 0 {
		out = append(out, "unknown key(s): "+strings.Join(k, ", "))
	}
	if k := byClass[classWriteBack]; len(k) > 0 {
		out = append(out, "benign key(s): "+strings.Join(k, ", "))
	}
	return out
}

// topLevel parses a config file, which must be a JSON object: null or
// any other value is malformed, so it stays in the branch for review.
func topLevel(b []byte) (map[string]json.RawMessage, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	if m == nil {
		return nil, errNotObject
	}
	return m, nil
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
	defer func() { _ = f.Close() }() // read only
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errNotRegular
	}
	return io.ReadAll(io.LimitReader(f, 16<<20))
}

// object parses an object value; an absent value counts as an empty
// object, so a key added or removed on one side is compared by sub-key.
// A present null is not an object: replacing an object with null is one
// change of the whole subtree, never a deletion of each key in it.
func object(b json.RawMessage) (map[string]json.RawMessage, bool) {
	if len(b) == 0 {
		return map[string]json.RawMessage{}, true
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil || m == nil {
		return nil, false
	}
	return m, true
}

func unionKeys(a, b map[string]json.RawMessage) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range []map[string]json.RawMessage{a, b} {
		for k := range m {
			if !seen[k] {
				seen[k] = true
				out = append(out, k)
			}
		}
	}
	sort.Strings(out)
	return out
}

var errNotObject = errors.New("not an object")

func getPath(m map[string]json.RawMessage, path []string) (json.RawMessage, bool) {
	v, ok := m[path[0]]
	if !ok || len(path) == 1 {
		return v, ok
	}
	child, isObj := object(v)
	if !isObj {
		return nil, false
	}
	return getPath(child, path[1:])
}

// setPath sets a value at path, creating objects on the way; it refuses
// to replace a non-object on the way.
func setPath(m map[string]json.RawMessage, path []string, v json.RawMessage) error {
	if len(path) == 1 {
		m[path[0]] = v
		return nil
	}
	child, ok := object(m[path[0]])
	if !ok {
		return errNotObject
	}
	if err := setPath(child, path[1:], v); err != nil {
		return err
	}
	b, err := marshalJSON(child, "")
	if err != nil {
		return err
	}
	m[path[0]] = b
	return nil
}

// marshalJSON encodes without HTML escaping, so values carried through
// as json.RawMessage keep their characters; indent "" is compact.
func marshalJSON(v any, indent string) ([]byte, error) {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if indent != "" {
		enc.SetIndent("", indent)
	}
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return []byte(strings.TrimSuffix(b.String(), "\n")), nil
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
	out, err := marshalJSON(obj, "  ")
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
	defer func() { _ = os.Remove(tmp.Name()) }() // gone after the rename; on error, a scratch file
	if _, err := tmp.Write(out); err != nil {
		_ = tmp.Close() // the write already failed
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close() // the write already failed
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
